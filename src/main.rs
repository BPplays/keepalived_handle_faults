
use anyhow::Context;
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
pub struct RestartHistory {
	events: Vec<u64>,
}

#[derive(Debug)]
pub struct RestartTracker {
	path: PathBuf,
	window: Duration,
	limit: usize,
}

impl RestartTracker {
	pub fn new(
		path: impl Into<PathBuf>,
		window: Duration,
		limit: usize,
	) -> Result<Self, RestartTrackerError> {
		if window.is_zero() {
			return Err(RestartTrackerError::ZeroWindow);
		}

		if limit == 0 {
			return Err(RestartTrackerError::ZeroLimit);
		}

		Ok(Self {
			path: path.into(),
			window,
			limit,
		})
	}

	pub fn now() -> Result<u64, RestartTrackerError> {
		Ok(std::time::SystemTime::now()
			.duration_since(UNIX_EPOCH)?
			.as_secs())
	}

	pub fn prune_history(
		&self,
		history: &mut RestartHistory,
	) -> Result<(), RestartTrackerError> {
		let now = Self::now()?;
		let cutoff = now.saturating_sub(
			self.window.as_secs().saturating_mul(3),
		);

		history.events.retain(|&ts| ts >= cutoff && ts <= now);
		history.events.sort_unstable();

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
		operation: impl FnOnce(&mut RestartHistory) -> Result<T, RestartTrackerError>,
	) -> Result<T, RestartTrackerError> {
		if let Some(parent) = self.path.parent() {
			if !parent.as_os_str().is_empty() {
				fs::create_dir_all(parent).map_err(|source| {
					RestartTrackerError::Io {
						operation: "create restart history directory",
						kind: RestartTrackerIoErrType::Write,
						path: parent.to_path_buf(),
						source,
					}
				})?;
			}
		}

		let lock_path = self.path.with_extension("lock");

		let lock_file = OpenOptions::new()
			.create(true)
			.read(true)
			.write(true)
			.open(&lock_path)
			.map_err(|source| RestartTrackerError::Io {
				operation: "open restart history lock",
				kind: RestartTrackerIoErrType::Lock,
				path: lock_path.clone(),
				source,
			})?;

		FileExt::lock_exclusive(&lock_file).map_err(|source| {
			RestartTrackerError::Io {
				operation: "lock restart history",
				kind: RestartTrackerIoErrType::Lock,
				path: lock_path.clone(),
				source,
			}
		})?;

		let result = (|| -> Result<T, RestartTrackerError> {
			let mut history = if self.path.exists() {
				let bytes = fs::read(&self.path).map_err(|source| {
					RestartTrackerError::Io {
						operation: "read restart history",
						kind: RestartTrackerIoErrType::Read,
						path: self.path.clone(),
						source,
					}
				})?;

				ciborium::de::from_reader(bytes.as_slice()).map_err(|source| {
					RestartTrackerError::DecodeHistory {
						path: self.path.clone(),
						source,
					}
				})?
			} else {
				RestartHistory::default()
			};

			self.prune_history(&mut history)?;

			let value = operation(&mut history)?;

			let mut bytes = Vec::new();

			ciborium::ser::into_writer(&history, &mut bytes)
				.map_err(|source|
					RestartTrackerError::EncodeHistory {
						path: self.path.clone(),
						source,
					}
				)?;

			let tmp = self.path.with_extension("tmp");

			fs::write(&tmp, bytes).map_err(|source| {
				RestartTrackerError::Io {
					operation: "write temporary restart history",
					kind: RestartTrackerIoErrType::Write,
					path: tmp.clone(),
					source,
				}
			})?;

			fs::rename(&tmp, &self.path).map_err(|source| {
				RestartTrackerError::Io {
					operation: "replace restart history",
					kind: RestartTrackerIoErrType::Write,
					path: self.path.clone(),
					source,
				}
			})?;

			Ok(value)
		})();

		let unlock_result = FileExt::unlock(&lock_file).map_err(|source| {
			RestartTrackerError::Io {
				operation: "unlock restart history",
				kind: RestartTrackerIoErrType::Unlock,
				path: lock_path,
				source,
			}
		});

		match (result, unlock_result) {
			(Err(err), _) => Err(err),
			(Ok(_), Err(err)) => Err(err),
			(Ok(value), Ok(())) => Ok(value),
		}
	}

	/// Number of restarts in the rolling window.
	pub fn count(&self) -> Result<usize, RestartTrackerError> {
		self.with_history(|history| {
			let now = Self::now()?;
			let cutoff = now.saturating_sub(self.window.as_secs());

			Ok(history.events.iter()
				.filter(|&&ts| ts >= cutoff && ts <= now)
				.count())
		})
	}

	/// Average restart rate in restarts per second.
	pub fn average_rate(&self) -> Result<f64, RestartTrackerError> {
		self.with_history(|history| {
			let now = Self::now()?;
			let cutoff = now.saturating_sub(self.window.as_secs());

			let count = history.events.iter()
				.filter(|&&ts| ts >= cutoff && ts <= now)
				.count();

			Ok(count as f64 / self.window.as_secs_f64())
		})
	}

	pub fn limit_reached(&self) -> Result<bool, RestartTrackerError> {
		Ok(self.count()? > self.limit)
	}

	/// Record an event only when this method is called.
	pub fn record_restart(&self) -> Result<(), RestartTrackerError> {
		self.with_history(|history| {
			history.events.push(Self::now()?);
			Ok(())
		})
	}

	pub fn try_record_restart(&self) -> Result<bool, RestartTrackerError> {
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


#[derive(Debug, thiserror::Error)]
pub enum RestartTrackerIoErrType {
    #[error("read")]
    Read,
    #[error("write")]
    Write,
    #[error("lock")]
    Lock,
    #[error("unlock")]
    Unlock,
}

#[derive(Debug, thiserror::Error)]
pub enum RestartTrackerError {
	#[error("restart window must be greater than zero")]
	ZeroWindow,

	#[error("restart limit must be greater than zero")]
	ZeroLimit,

	#[error("{operation} `{path}` failed ({kind}): {source}")]
	Io {
		operation: &'static str,
		kind: RestartTrackerIoErrType,
		path: PathBuf,
		#[source]
		source: io::Error,
	},

	#[error("failed to decode restart history `{path}`: {source}")]
	DecodeHistory {
		path: PathBuf,
		#[source]
		source: ciborium::de::Error<io::Error>,
	},

    #[error("failed to encode restart history `{path}`: {source}")]
    EncodeHistory {
        path: PathBuf,
        #[source]
        source: ciborium::ser::Error<io::Error>,
    },

	#[error(transparent)]
	SystemTime(#[from] std::time::SystemTimeError),
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
) -> Result<Vec<InterfaceIp>, InterfaceIpsError> {
	let (connection, handle, _) =
		rtnetlink::new_connection().map_err(InterfaceIpsError::Connection)?;
	tokio::spawn(connection);

	// Map selected interface indexes to their primary names.
	let mut selected: HashMap<u32, String> = HashMap::new();
	let mut links = handle.link().get().execute();

	while let Some(link) = links
		.try_next()
		.await
		.map_err(InterfaceIpsError::LinkQuery)?
	{
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

	while let Some(addr) = addresses
		.try_next()
		.await
		.map_err(InterfaceIpsError::AddressQuery)?
	{
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

#[derive(Debug, thiserror::Error)]
pub enum InterfaceIpsError {
	#[error("failed to create rtnetlink connection: {0}")]
	Connection(#[source] io::Error),

	#[error("failed to enumerate network links: {0}")]
	LinkQuery(#[source] rtnetlink::Error),

	#[error("failed to enumerate interface addresses: {0}")]
	AddressQuery(#[source] rtnetlink::Error),

	#[error("invalid IP prefix returned by netlink: {0}")]
	Prefix(#[from] ipnet::PrefixLenError),
}

pub fn parse_ip_file(
	path: impl AsRef<Path>,
) -> Result<Vec<IpNet>, IpFileError> {
	let path = path.as_ref();

	let contents = fs::read_to_string(path).map_err(|source| {
		IpFileError::Read {
			path: path.to_path_buf(),
			source,
		}
	})?;

	let mut result = Vec::new();

	for (index, raw_line) in contents.lines().enumerate() {
		let line_number = index + 1;

		let line = raw_line.split('#').next().unwrap_or("").trim();

		if line.is_empty() {
			continue;
		}

		let (ip_text, prefix_text) = match line.split_once('/') {
			Some((ip, prefix)) => (ip.trim(), Some(prefix.trim())),
			None => (line, None),
		};

		let address = ip_text.parse::<IpAddr>().map_err(|source| {
			IpFileError::InvalidAddress {
				path: path.to_path_buf(),
				line: line_number,
				input: ip_text.to_owned(),
				source,
			}
		})?;

		let prefix_len = match prefix_text {
			Some(prefix_text) => {
				let prefix = prefix_text.parse::<u8>().map_err(|source| {
					IpFileError::InvalidPrefix {
						path: path.to_path_buf(),
						line: line_number,
						input: prefix_text.to_owned(),
						source,
					}
				})?;

				let max_prefix = if address.is_ipv6() { 128 } else { 32 };

				if prefix > max_prefix {
					return Err(IpFileError::PrefixOutOfRange {
						path: path.to_path_buf(),
						line: line_number,
						prefix,
						address,
					});
				}

				Some(prefix)
			}
			None => None,
		};

		let network = match prefix_len {
			Some(prefix) => {
				IpNet::new(address, prefix).map_err(|source| {
					IpFileError::InvalidNetwork {
						path: path.to_path_buf(),
						line: line_number,
						source,
					}
				})?
			}
			None => IpNet::from(address),
		};

		result.push(network);
	}

	Ok(result)
}

#[derive(Debug, thiserror::Error)]
pub enum IpFileError {
	#[error("failed to read IP address file `{path}`: {source}")]
	Read {
		path: PathBuf,
		#[source]
		source: io::Error,
	},

	#[error("{path}:{line}: invalid IP address `{input}`: {source}")]
	InvalidAddress {
		path: PathBuf,
		line: usize,
		input: String,
		#[source]
		source: std::net::AddrParseError,
	},

	#[error("{path}:{line}: invalid CIDR prefix `{input}`: {source}")]
	InvalidPrefix {
		path: PathBuf,
		line: usize,
		input: String,
		#[source]
		source: std::num::ParseIntError,
	},

	#[error("{path}:{line}: prefix /{prefix} is invalid for {address}")]
	PrefixOutOfRange {
		path: PathBuf,
		line: usize,
		prefix: u8,
		address: IpAddr,
	},

	#[error("{path}:{line}: invalid network prefix: {source}")]
	InvalidNetwork {
		path: PathBuf,
		line: usize,
		#[source]
		source: ipnet::PrefixLenError,
	},
}

fn init_logging(
	path: Option<impl AsRef<Path> + std::fmt::Display>,
	level: LevelFilter,
	stdout_timestamps: StdoutTimestamps,
) -> anyhow::Result<Option<WorkerGuard>> {
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

		let writer = RollingWriter::builder(&path)
			.rotation(Rotation::Never)
			.max_file_size(limit.get::<byte>() as u64)
			.max_files(3)
			.build()?;

		let (file_writer, guard) = non_blocking(writer);

		tracing_subscriber::registry()
			.with(filter.clone())
			.with(stdout_layer)
			.with(
				tracing_subscriber::fmt::layer()
					.with_writer(file_writer)
					.with_ansi(false),
			)
			.try_init()
			.with_context(|| {
				format!(
					"failed to init\npath: {}\nfilter: {}\n",
					&path,
					&filter,
				)
			})?;

		Ok(Some(guard))
	} else {
		tracing_subscriber::registry()
			.with(filter)
			.with(stdout_layer)
			.try_init()?;

		Ok(None)
	}
}

#[derive(Debug, thiserror::Error)]
enum AppError {
	#[error(transparent)]
	RestartTracker(#[from] RestartTrackerError),

	#[error("failed to connect to the system bus: {0}")]
	SystemBus(#[source] zbus_systemd::zbus::Error),

	#[error("failed to create systemd manager proxy: {0}")]
	SystemdManager(#[source] zbus_systemd::zbus::Error),

	#[error("failed to queue restart of systemd unit `{service}`: {source}")]
	RestartUnit {
		service: String,
		#[source]
		source: zbus_systemd::zbus::Error,
	},
}

async fn run(args: Args) -> Result<(), AppError> {
	let mut restart = false;

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
							error!("Failed to parse expected IP file: {err}");
							None
						}
					});

				debug!("expected IPs from file: {expected_ips:#?}");

				let interface_ips = get_interface_ips(args.interface.as_deref()).await;
				debug!("system ips: {:#?}", interface_ips);
				match (interface_ips, expected_ips.as_ref()) {
					(Ok(_), Some(expected_ips)) if {
						expected_ips.is_empty()
					} => {
						error!("expected ips is empty");
					}
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
			let connection = Connection::system()
				.await
				.map_err(|source| AppError::SystemBus(source))?;

			let manager = ManagerProxy::new(&connection)
				.await
				.map_err(|source| AppError::SystemdManager(source))?;

			let job = manager
				.restart_unit(
					args.service.clone(),
					"replace".to_owned(),
				)
			.await
			.map_err(|source| AppError::RestartUnit {
				service: args.service.clone(),
				source,
			})?;

			info!(
				"Queued restart of {} (job: {})",
				args.service,
				job,
			);
		} else {
			info!("Restart limit reached; suppressing restart");
		}

	}

	Ok(())
}


#[tokio::main]
async fn main() -> Result<(), AppError> {
	let args = Args::parse();

	match args.niceness {
		Some(niceness) => {
			let _ = setpriority_process(None, niceness);
		}
		None => {}
	}



	let _guard = init_logging(
		args.log_file.as_deref(),
		args.log_level,
		args.stdout_timestamps,
	).unwrap();

	let res = run(args).await;
	match res {
		Ok(_) => {}
		Err(err) => {
			error!("{err}")
		}

	}

	Ok(())
}
