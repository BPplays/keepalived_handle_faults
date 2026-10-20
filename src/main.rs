
use clap::Parser;
use std::{path::Path, str::FromStr};
use std::path::PathBuf;
use tracing;
use tracing::{debug, error, info, warn};
use uom::si::information::{byte, megabyte, gigabyte};
use humantime;
use rustix::process::setpriority_process;

use std::collections::HashSet;

use ltrace::{RollingWriter, Rotation};
use tracing_appender::non_blocking;
use tracing_appender::non_blocking::{WorkerGuard};
use tracing_subscriber::{
	layer::SubscriberExt,
	util::SubscriberInitExt,
	EnvFilter,
};
use tracing_subscriber::filter::LevelFilter;

use futures_util::TryStreamExt;
use rtnetlink::packet_route::{
	address::AddressAttribute,
	link::{LinkAttribute, Prop},
};
use std::{
	collections::HashMap,
	error::Error,
	net::IpAddr,
};
use ipnet::IpNet;

use std::io::IsTerminal;
use tracing_subscriber::fmt::{
	format::Writer,
	time::{FormatTime, SystemTime},
};

use zbus_systemd::{
	systemd1::ManagerProxy,
	zbus::Connection,
};
use std::{
	time::{Duration, Instant},
};
use tokio::time::sleep;

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
	fs::{self, File, OpenOptions},
	io,
	time::{UNIX_EPOCH},
};

#[derive(Debug, Default, Serialize, Deserialize)]
struct RestartHistory {
	events: Vec<u64>,
}

#[derive(Debug)]
struct RestartTracker {
	path: PathBuf,
	window: Duration,
	limit: usize,
}

impl RestartTracker {
	fn new(
		path: impl Into<PathBuf>,
		window: Duration,
		limit: usize,
	) -> Result<Self, Box<dyn Error + Send + Sync>> {
		if window.is_zero() {
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				"restart window must be greater than zero",
			).into());
		}

		if limit == 0 {
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				"restart limit must be greater than zero",
			).into());
		}

		Ok(Self {
			path: path.into(),
			window,
			limit,
		})
	}

	fn now() -> Result<u64, Box<dyn Error + Send + Sync>> {
		Ok(std::time::SystemTime::now()
			.duration_since(UNIX_EPOCH)?
			.as_secs())
	}

	fn prune_history(&self, history: &mut RestartHistory) -> Result<(), Box<dyn Error + Send + Sync>> {
		let now = Self::now()?;
		let cutoff = now.saturating_sub(
			self.window.as_secs().saturating_mul(3)
		);

		history.events.retain(|&ts| ts >= cutoff && ts <= now);
		history.events.sort_unstable();

		// Hard cap: keep only the newest 10x the configured limit.
		let max_events = self.limit.saturating_mul(10);

		if history.events.len() > max_events {
			let excess = history.events.len() - max_events;
			history.events.drain(..excess);
		}

		Ok(())
	}

	/// Acquire a stable sidecar lock, reload, update and save.
	fn with_history<T>(
		&self,
		operation: impl FnOnce(&mut RestartHistory) -> Result<T, Box<dyn Error + Send + Sync>>,
	) -> Result<T, Box<dyn Error + Send + Sync>> {
		if let Some(parent) = self.path.parent() {
			if !parent.as_os_str().is_empty() {
				fs::create_dir_all(parent)?;
			}
		}

		// Lock a separate, persistent file rather than the data file:
		// the data file is atomically replaced during saving.
		let lock_path = self.path.with_extension("lock");

		let lock_file = OpenOptions::new()
			.create(true)
			.read(true)
			.write(true)
			.open(lock_path)?;

		FileExt::lock_exclusive(&lock_file)?;

		// Always reload after acquiring the lock.
		let result = (|| -> Result<T, Box<dyn Error + Send + Sync>> {
			let mut history = if self.path.exists() {
				let bytes = fs::read(&self.path)?;
				ciborium::de::from_reader(bytes.as_slice())?
			} else {
				RestartHistory::default()
			};

			self.prune_history(&mut history)?;

			let value = operation(&mut history)?;

			// Serialize as CBOR.
			let mut bytes = Vec::new();
			ciborium::ser::into_writer(&history, &mut bytes)?;

			// Write a temporary file and atomically replace the history.
			let tmp = self.path.with_extension("tmp");
			fs::write(&tmp, bytes)?;
			fs::rename(&tmp, &self.path)?;

			Ok(value)
		})();

		let unlock_result = FileExt::unlock(&lock_file);

		match (result, unlock_result) {
			(Err(err), _) => Err(err),
			(Ok(_), Err(err)) => Err(err.into()),
			(Ok(value), Ok(())) => Ok(value),
		}
	}

	/// Number of restarts in the rolling window.
	fn count(&self) -> Result<usize, Box<dyn Error + Send + Sync>> {
		self.with_history(|history| {
			let now = Self::now()?;
			let cutoff = now.saturating_sub(self.window.as_secs());

			Ok(history.events.iter()
				.filter(|&&ts| ts >= cutoff && ts <= now)
				.count())
		})
	}

	/// Average restart rate in restarts per second.
	fn average_rate(&self) -> Result<f64, Box<dyn Error + Send + Sync>> {
		self.with_history(|history| {
			let now = Self::now()?;
			let cutoff = now.saturating_sub(self.window.as_secs());

			let count = history.events.iter()
				.filter(|&&ts| ts >= cutoff && ts <= now)
				.count();

			Ok(count as f64 / self.window.as_secs_f64())
		})
	}

	fn limit_reached(&self) -> Result<bool, Box<dyn Error + Send + Sync>> {
		Ok(self.count()? > self.limit)
	}

	/// Record an event only when this method is called.
	fn record_restart(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
		self.with_history(|history| {
			history.events.push(Self::now()?);
			Ok(())
		})
	}

	fn try_record_restart(&self) -> Result<bool, Box<dyn Error + Send + Sync>> {
		self.with_history(|history| {
			let now = Self::now()?;
			let cutoff = now.saturating_sub(self.window.as_secs());

			let count = history.events.iter()
				.filter(|&&ts| ts >= cutoff && ts <= now)
				.count();

			if count > self.limit {
				return Ok(false);
			}

			history.events.push(now);
			Ok(true)
		})
	}

}



#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceIp {
	/// The interface's primary name, even when matched by an altname.
	pub interface: String,
	pub ipnet: IpNet,
}

impl From<InterfaceIp> for IpNet {
	fn from(value: InterfaceIp) -> Self {
		value.ipnet
	}
}
impl From<&InterfaceIp> for IpNet {
	fn from(value: &InterfaceIp) -> Self {
		value.ipnet
	}
}

struct ConditionalTimer {
	enabled: bool,
}

impl FormatTime for ConditionalTimer {
	fn format_time(&self, w: &mut Writer<'_>) -> std::fmt::Result {
		if self.enabled {
			SystemTime.format_time(w)
		} else {
			Ok(())
		}
	}
}


#[derive(Debug, Clone)]
enum KeepalivedType {
	Group,
	Instance,
	Unknown(String),
}
impl FromStr for KeepalivedType {
	type Err = String;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Ok(match s.to_ascii_lowercase().as_str() {
			"group" => Self::Group,
			"instance" => Self::Instance,
			_ => Self::Unknown(s.to_string()),
		})
	}
}

#[derive(Debug, Clone)]
enum KeepalivedState {
	Master,
	Backup,
	Fault,
	Stop,
	Unknown(String),
}

impl FromStr for KeepalivedState {
	type Err = String;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Ok(match s.to_ascii_lowercase().as_str() {
			"master" => Self::Master,
			"backup" => Self::Backup,
			"fault" => Self::Fault,
			"stop" => Self::Stop,
			_ => Self::Unknown(s.to_string()),
		})
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum StdoutTimestamps {
	/// Automatically detect based on whether stdout is a terminal
	Auto,
	/// Always include timestamps
	Always,
	/// Never include timestamps
	Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum NetworkCompareMode {
	Strict,
	IPbased,
}

#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
	/// Path to the master IP address list
	#[arg(short = 'f', long = "ips-file")]
	ips_file: Option<PathBuf>,

	/// Path to the master IP address list
	#[arg(short = 'r', long = "restart-tracking-file")]
	restart_tracking_file: Option<PathBuf>,

	/// Service to restart when a fault is detected
	#[arg(short = 's', long = "service")]
	service: String,

	#[arg(short = 'i', long = "interface")]
	interface: Option<String>,

	#[arg(short = 'l', long = "log-file")]
	log_file: Option<String>,

	/// Minimum log level
	#[arg(
		long = "log-level",
		// default_value = "info",
		default_value = "debug",
		value_parser = clap::value_parser!(LevelFilter)
	)]
	log_level: LevelFilter,

	/// Control timestamps in stdout logs
	#[arg(
		long = "stdout-timestamps",
		value_enum,
		default_value_t = StdoutTimestamps::Auto
	)]
	stdout_timestamps: StdoutTimestamps,

	#[arg(
		long = "network-compare-mode",
		value_enum,
		default_value_t = NetworkCompareMode::IPbased
	)]
	network_compare_mode: NetworkCompareMode,

	/// process niceness
	#[arg(long = "nice", allow_hyphen_values = true)]
	niceness: Option<i32>,

	#[arg(value_name = "TYPE")]
	keepalived_type: KeepalivedType,

	/// Keepalived instance or group name
	#[arg(value_name = "NAME")]
	instance_name: String,

	#[arg(value_name = "STATE")]
	keepalived_state: KeepalivedState,

	/// Current priority
	#[arg(value_name = "PRIORITY")]
	priority: Option<u8>,

	/// Previous priority
	#[arg(value_name = "PREVIOUS_PRIORITY")]
	previous_priority: Option<u8>,
}

pub fn soft_parse_ip_network(
	input: &str,
) -> Result<IpNet, Box<dyn Error + Send + Sync>> {
	let input = input.trim();

	if input.contains('/') {
		Ok(input.parse::<IpNet>()?)
	} else {
		let address = input.parse::<IpAddr>()?;
		Ok(IpNet::from(address))
	}
}

pub async fn get_interface_ips(
	interface_name: Option<&str>,
) -> Result<Vec<InterfaceIp>, Box<dyn Error + Send + Sync>> {
	let (connection, handle, _) = rtnetlink::new_connection()?;
	tokio::spawn(connection);

	// Map selected interface indexes to their primary names.
	let mut selected: HashMap<u32, String> = HashMap::new();
	let mut links = handle.link().get().execute();

	while let Some(link) = links.try_next().await? {
		let mut name: Option<String> = None;
		let mut altnames: Vec<String> = Vec::new();

		for attr in &link.attributes {
			match attr {
				LinkAttribute::IfName(value) => {
					name = Some(value.clone());
				}
				LinkAttribute::PropList(properties) => {
					for property in properties {
						if let Prop::AltIfName(value) = property {
							altnames.push(value.clone());
						}
					}
				}
				_ => {}
			}
		}

		let Some(name) = name else {
			continue;
		};

		let matches = interface_name.map_or(true, |wanted| {
			name == wanted
				|| altnames.iter().any(|alt| alt == wanted)
		});

		if matches {
			selected.insert(link.header.index, name);
		}
	}

	// Collect addresses for the selected interfaces.
	let mut result = Vec::new();
	let mut addresses = handle.address().get().execute();

	while let Some(addr) = addresses.try_next().await? {
		let Some(interface) = selected.get(&addr.header.index) else {
			continue;
		};

		let mut ip: Option<IpAddr> = None;

		for attr in &addr.attributes {
			match attr {
				// Prefer the local address, particularly for point-to-point
				// interfaces where Address and Local may differ.
				AddressAttribute::Local(value) => {
					ip = Some(*value);
				}
				AddressAttribute::Address(value) if ip.is_none() => {
					ip = Some(*value);
				}
				_ => {}
			}
		}

		if let Some(address) = ip {
			let network = IpNet::new(address, addr.header.prefix_len)?;
			result.push(InterfaceIp {
				interface: interface.clone(),
				ipnet: network,
			});
		}
	}

	Ok(result)
}

pub fn parse_ip_file(
	path: impl AsRef<Path>,
) -> Result<Vec<IpNet>, Box<dyn Error + Send + Sync>> {
	use std::io::{self, ErrorKind};

	let path = path.as_ref();
	let contents = std::fs::read_to_string(path)?;
	let mut result = Vec::new();

	for (index, raw_line) in contents.lines().enumerate() {
		let line_number = index + 1;

		// Ignore comments and blank lines.
		let line = raw_line.split('#').next().unwrap_or("").trim();

		if line.is_empty() {
			continue;
		}

		let (ip_text, prefix_text) = match line.split_once('/') {
			Some((ip, prefix)) => (ip.trim(), Some(prefix.trim())),
			None => (line, None),
		};

		let address = ip_text.parse::<IpAddr>().map_err(|e| {
			io::Error::new(
				ErrorKind::InvalidData,
				format!(
					"{}:{}: invalid IP address '{}': {}",
					path.display(),
					line_number,
					ip_text,
					e
				),
			)
		})?;

		let prefix_len = match prefix_text {
			Some(prefix_text) => {
				let prefix_len = prefix_text.parse::<u8>().map_err(|e| {
					io::Error::new(
						ErrorKind::InvalidData,
						format!(
							"{}:{}: invalid CIDR prefix '{}': {}",
							path.display(),
							line_number,
							prefix_text,
							e
						),
					)
				})?;

				let max_prefix = if address.is_ipv6() { 128 } else { 32 };

				if prefix_len > max_prefix {
					return Err(io::Error::new(
						ErrorKind::InvalidData,
						format!(
							"{}:{}: prefix /{} is invalid for {}",
							path.display(),
							line_number,
							prefix_len,
							address
						),
					)
					.into());
				}

				Some(prefix_len)
			}
			None => None,
		};

		let network = match prefix_len {
			Some(prefix_len) => IpNet::new(address, prefix_len)?,
			None => IpNet::from(address),
		};

		result.push(network);
	}

	Ok(result)
}

fn init_logging(
	path: Option<impl AsRef<Path>>,
	level: LevelFilter,
	stdout_timestamps: StdoutTimestamps,
) -> Result<
	Option<WorkerGuard>,
	Box<dyn std::error::Error + Send + Sync>,
> {
	let filter = EnvFilter::try_from_default_env()
		.unwrap_or_else(|_| EnvFilter::new(level.to_string()));

	let enable_stdout_timestamps = match stdout_timestamps {
		StdoutTimestamps::Auto => std::io::stdout().is_terminal(),
		StdoutTimestamps::Always => true,
		StdoutTimestamps::Never => false,
	};

	let stdout_layer = tracing_subscriber::fmt::layer()
		.with_writer(std::io::stdout)
		.with_timer(ConditionalTimer {
			enabled: enable_stdout_timestamps,
		});

	if let Some(path) = path {
		let limit = uom::si::f64::Information::new::<megabyte>(5.0);

		let writer = RollingWriter::builder(path)
			.rotation(Rotation::Never)
			.max_file_size(limit.get::<byte>() as u64)
			.max_files(3)
			.build()?;

		let (file_writer, guard) = non_blocking(writer);

		tracing_subscriber::registry()
			.with(filter)
			.with(stdout_layer)
			.with(
				tracing_subscriber::fmt::layer()
					.with_writer(file_writer)
					.with_ansi(false),
			)
			.try_init()?;

		Ok(Some(guard))
	} else {
		tracing_subscriber::registry()
			.with(filter)
			.with(stdout_layer)
			.try_init()?;

		Ok(None)
	}
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
	let args = Args::parse();

	match args.niceness {
		Some(niceness) => {
			let _ = setpriority_process(None, niceness);
		}
		None => {}
	}


	let mut restart = false;

	let _guard = init_logging(
		args.log_file.as_deref(),
		args.log_level,
		args.stdout_timestamps,
	).unwrap();



	debug!("{args:#?}");

	match args.keepalived_type {
		KeepalivedType::Unknown(ktype) => {
			debug!("keepalived instance type unknown \"{ktype}\"")
		}
		_ => {}

	}


	match args.keepalived_state {
		KeepalivedState::Master => {
			info!("Instance became MASTER");
			let timeout = Duration::from_millis(5000);
			let interval = Duration::from_millis(250);
			let start = Instant::now();

			while start.elapsed() < timeout {
				let expected_ips: Option<Vec<IpNet>> = args
					.ips_file
					.as_deref()
					.and_then(|path| match parse_ip_file(path) {
						Ok(ips) => Some(ips),
						Err(err) => {
							error!("Failed to parse IP file: {err}");
							None
						}
					});

				debug!("expected IPs from file: {expected_ips:#?}");

				let interface_ips = get_interface_ips(args.interface.as_deref()).await;
				debug!("system ips: {:#?}", interface_ips);
				match (interface_ips, expected_ips.as_ref()) {
					(Ok(interface_ips), Some(expected_ips)) => {
						let interface_ips_set: HashSet<IpNet> = interface_ips
							.iter()
							.map(|ip| {
								match args.network_compare_mode {
									NetworkCompareMode::Strict => {
										ip.ipnet
									}

									NetworkCompareMode::IPbased => {
										IpNet::from(ip.ipnet.addr())
									}
								}
							})
							.collect();

						let if_contains_all_ips = expected_ips
							.iter()
							.map(|ip| {
								match args.network_compare_mode {
									NetworkCompareMode::Strict => {
										*ip
									}

									NetworkCompareMode::IPbased => {
										IpNet::from(ip.addr())
									}
								}
							})
							.all(|expected| interface_ips_set.contains(&expected));

						debug!("interfaces contains expected IPs: {if_contains_all_ips}");
						if !if_contains_all_ips {
							restart = true;
						} else {
							restart = false;
							break;
						}
					}
					(Ok(_), None) => {
						info!("expected ips is none");
					}
					(Err(err), _) => {
						warn!("error getting ips {err}");
					}
				}

				sleep(interval).await;
			}
			if restart {
				error!(
					"failed to find expected IPs on the system after {}",
					humantime::format_duration(timeout),
				)
			}

		}
		KeepalivedState::Fault => {
			warn!("Instance entered FAULT");
			restart = true
		}
		KeepalivedState::Unknown(state) => {
			warn!("Unknown state: {state}");
		}
		_ => {
			info!("No action needed for this state");
		}
	}



	if restart {
		let default_restarts_path = PathBuf::from_str(
			"/run/keepalived_handle_fault/restarts",
		).unwrap();

		let tracker = RestartTracker::new(
			args.restart_tracking_file.unwrap_or(
				default_restarts_path
					.join(args.service.clone())
					.join("restarts.cbor"),
			),
			Duration::from_secs(500),
			5,
		)?;

		debug!("Restarts in window: {}", tracker.count()?);
		debug!(
			"Average rate: {:.4} restarts/sec",
			tracker.average_rate()?
		);

		if tracker.try_record_restart()? {
			let connection = Connection::system().await?;
			let manager = ManagerProxy::new(&connection).await?;

			let job = manager
				.restart_unit(
					args.service.clone(),
					"replace".to_owned(),
				)
			.await?;

			info!(
				"Queued restart of {} (job: {:?})",
				args.service,
				job,
			);
		} else {
			info!("Restart limit reached; suppressing restart");
		}

	}

	Ok(())
}
