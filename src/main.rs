
use clap::Parser;
use std::{path::Path, str::FromStr};
use std::path::PathBuf;
use tracing;
use tracing::{debug, error, info, warn};
use uom::si::information::{byte, megabyte, gigabyte};
use humantime;
use rustix::process::setpriority_process;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceIp {
	/// The interface's primary name, even when matched by an altname.
	pub interface: String,
	pub address: IpNet,
}

impl From<InterfaceIp> for IpNet {
	fn from(value: InterfaceIp) -> Self {
		value.address
	}
}
impl From<&InterfaceIp> for IpNet {
	fn from(value: &InterfaceIp) -> Self {
		value.address
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
	Unknown(String),
}

impl FromStr for KeepalivedState {
	type Err = String;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Ok(match s.to_ascii_lowercase().as_str() {
			"master" => Self::Master,
			"backup" => Self::Backup,
			"fault" => Self::Fault,
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

#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
	/// Path to the master IP address list
	#[arg(short = 'i', long = "ips")]
	ips_file: Option<PathBuf>,

	/// Service to restart when a fault is detected
	#[arg(short = 's', long = "service")]
	service: String,

	#[arg(short = 'f', long = "interface")]
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
				address: network,
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

	let expected_ips: Option<Vec<IpNet>> = match args.ips_file.as_deref() {
		Some(path) => Some(parse_ip_file(path).unwrap()),
		None => None,
	};

	debug!("expected IPs from file: {expected_ips:#?}");

	match args.keepalived_state {
		KeepalivedState::Master => {
			info!("Instance became MASTER");
			let timeout = Duration::from_millis(5000);
			let interval = Duration::from_millis(250);
			let start = Instant::now();

			while start.elapsed() < timeout {
				let interface_ips = get_interface_ips(args.interface.as_deref()).await;
				debug!("system ips: {:#?}", interface_ips);
				match (interface_ips, expected_ips.as_ref()) {
					(Ok(interface_ips), Some(expected_ips)) => {
						let if_contains_all_ips = expected_ips.iter().all(|expected| {
							interface_ips.iter()
								.any(|ip| ip.address.contains(expected))
						});
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
						break;
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
		let connection = Connection::system().await?;
		let manager = ManagerProxy::new(&connection).await?;

		manager
			.restart_unit(
				args.service.to_owned(),
				"replace".to_owned(),
			)
		.await?;

		info!("restarted {}", args.service)
	}

	Ok(())
}
