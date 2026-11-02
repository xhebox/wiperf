//! `wiperf` CLI: lightweight iperf3-compatible benchmark client and server
//! built on `completion` and `argh`.

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use argh::FromArgs;
use wiperf::{
	Counters, DEFAULT_PORT, Report, SocketStream, TestParams, bind_tcp, bind_unix, connect_tcp_any,
	connect_unix, resolve, run_stream_client, run_udp_client, serve_ip_once, serve_stream_once,
	to_io,
};

/// Lightweight iperf3-compatible network and vsock benchmark tool.
#[derive(Debug, FromArgs)]
struct Args {
	/// run in server mode
	#[argh(switch, short = 's')]
	server: bool,

	/// run in client mode, connecting to host (IP or vsock CID)
	#[argh(option, short = 'c')]
	client: Option<String>,

	/// unix domain socket path for client or server
	#[argh(option)]
	unix: Option<PathBuf>,

	/// use AF_VSOCK (Linux): in server mode listens on --port; in client mode -c is CID
	#[argh(switch)]
	vsock: bool,

	/// server port to listen on or connect to (default 5201)
	#[argh(option, short = 'p', default = "u32::from(DEFAULT_PORT)")]
	port: u32,

	/// time in seconds to transmit for (default 10)
	#[argh(option, short = 't', default = "10")]
	time: u32,

	/// omit the first N seconds of the test
	#[argh(option, short = 'O', default = "0")]
	omit: u32,

	/// number of parallel client streams to run (default 1)
	#[argh(option, short = 'P', default = "1")]
	parallel: u16,

	/// length of buffer to read or write in bytes (0 for protocol default)
	#[argh(option, short = 'l', default = "0")]
	len: u32,

	/// use UDP rather than TCP
	#[argh(switch, short = 'u')]
	udp: bool,

	/// target bitrate in bits/sec (0 for unlimited)
	#[argh(option, short = 'b')]
	bitrate: Option<u64>,

	/// run in reverse mode (server sends, client receives)
	#[argh(switch, short = 'R')]
	reverse: bool,

	/// handle one client connection then exit (server mode)
	#[argh(switch, short = '1')]
	one_off: bool,

	/// output in JSON format
	#[argh(switch, short = 'J')]
	json: bool,
}

fn main() -> ExitCode {
	let args: Args = argh::from_env();
	match completion::block_on(run(args)) {
		Ok(Ok(())) => ExitCode::SUCCESS,
		Ok(Err(error)) => {
			eprintln!("wiperf: {error}");
			ExitCode::FAILURE
		}
		Err(error) => {
			eprintln!("wiperf: runtime: {error}");
			ExitCode::FAILURE
		}
	}
}

async fn run(args: Args) -> io::Result<()> {
	if (args.vsock && args.unix.is_some()) || (args.server && args.client.is_some()) {
		return Err(io::Error::new(
			io::ErrorKind::InvalidInput,
			"select one transport and one role",
		));
	}
	if args.udp && (args.unix.is_some() || args.vsock) {
		return Err(datagram_over_stream_error());
	}
	if args.server {
		return run_server(&args).await;
	}
	run_client(&args).await
}

async fn run_server(args: &Args) -> io::Result<()> {
	if let Some(path) = &args.unix {
		let listener = bind_unix(path)?;
		loop {
			let (params, report) = serve_stream_once(|| async {
				let sock = listener.accept().await.map_err(to_io)?;
				Ok(SocketStream::new(sock))
			})
			.await?;
			print_summary(&params, &report, args.json);
			if args.one_off {
				return Ok(());
			}
		}
	}

	#[cfg(not(target_os = "linux"))]
	if args.vsock {
		return Err(vsock_unsupported());
	}

	#[cfg(target_os = "linux")]
	if args.vsock {
		let listener = wiperf::bind_vsock(args.port)?;
		loop {
			let (params, report) = serve_stream_once(|| async {
				let sock = listener.accept().await.map_err(to_io)?;
				Ok(SocketStream::new(sock))
			})
			.await?;
			print_summary(&params, &report, args.json);
			if args.one_off {
				return Ok(());
			}
		}
	}

	let bind_addr: SocketAddr = format!("0.0.0.0:{}", args.port)
		.parse()
		.map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
	let (listener, local_addr) = bind_tcp(bind_addr)?;
	loop {
		let (params, report) = serve_ip_once(&listener, local_addr).await?;
		print_summary(&params, &report, args.json);
		if args.one_off {
			return Ok(());
		}
	}
}

async fn run_client(args: &Args) -> io::Result<()> {
	let params = TestParams {
		tcp: (!args.udp).then_some(true),
		udp: args.udp.then_some(true),
		omit: (args.omit > 0).then_some(args.omit),
		time: Some(args.time),
		parallel: Some(args.parallel),
		reverse: args.reverse.then_some(true),
		len: (args.len > 0).then_some(args.len),
		bandwidth: args.bitrate,
		udp_counters_64bit: args.udp.then_some(1),
		client_version: None,
	};

	if args.udp && (args.unix.is_some() || args.vsock) {
		return Err(datagram_over_stream_error());
	}

	if let Some(path) = &args.unix {
		let report = run_stream_client(&params, || async { connect_unix(path) }).await?;
		print_summary(&params, &report, args.json);
		return Ok(());
	}

	let host = args.client.as_deref().ok_or_else(|| {
		io::Error::new(
			io::ErrorKind::InvalidInput,
			"specify -s (server), -c <host> (client), or --unix <path>",
		)
	})?;

	#[cfg(not(target_os = "linux"))]
	if args.vsock {
		return Err(vsock_unsupported());
	}

	#[cfg(target_os = "linux")]
	if args.vsock {
		let cid: u32 = host.parse().map_err(|_| {
			io::Error::new(
				io::ErrorKind::InvalidInput,
				format!("invalid vsock CID {host:?}"),
			)
		})?;
		let port = args.port;
		let report =
			run_stream_client(&params, || async move { wiperf::connect_vsock(cid, port) }).await?;
		print_summary(&params, &report, args.json);
		return Ok(());
	}

	let port = u16::try_from(args.port)
		.map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "TCP/UDP port exceeds 65535"))?;
	let report = if args.udp {
		// UDP is a datagram transport over IP only; resolve the name to the
		// address the control connection and the datagrams both use.
		let addr = resolve(host, port)?
			.into_iter()
			.next()
			.ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no address"))?;
		run_udp_client(&params, addr).await?
	} else {
		run_stream_client(&params, || connect_tcp_any(host, port)).await?
	};
	print_summary(&params, &report, args.json);
	Ok(())
}

fn datagram_over_stream_error() -> io::Error {
	io::Error::new(
		io::ErrorKind::Unsupported,
		"--udp needs a datagram transport: Unix sockets and AF_VSOCK are streams \
		 (VSOCK SEQPACKET is not implemented)",
	)
}

#[cfg(not(target_os = "linux"))]
fn vsock_unsupported() -> io::Error {
	io::Error::new(
		io::ErrorKind::Unsupported,
		"--vsock is only available on Linux (AF_VSOCK)",
	)
}

fn print_summary(params: &TestParams, report: &Report, json: bool) {
	if json {
		let mut sent = 0u64;
		let mut received = 0u64;
		for stream in &report.streams {
			if let Some(s) = stream.sender {
				sent += s.bytes;
			}
			if let Some(r) = stream.receiver {
				received += r.bytes;
			}
		}
		let out = serde_json::json!({
			"seconds": report.seconds,
			"sent_bytes": sent,
			"received_bytes": received,
			"send_bps": sent as f64 * 8.0 / report.seconds,
			"recv_bps": received as f64 * 8.0 / report.seconds,
		});
		println!("{out}");
		return;
	}

	let mut total_sent = Counters::default();
	let mut total_recv = Counters::default();
	for stream in &report.streams {
		let idx = stream.index + 1;
		if let Some(s) = stream.sender {
			total_sent.bytes += s.bytes;
			total_sent.packets += s.packets;
			println!(
				"  stream {idx:>2}  sender    {:>10}  {:>12}",
				format_bytes(s.bytes),
				format_rate(s.bits_per_second(report.seconds))
			);
		}
		if let Some(r) = stream.receiver {
			total_recv.bytes += r.bytes;
			total_recv.packets += r.packets;
			total_recv.lost += r.lost;
			total_recv.jitter_us = total_recv.jitter_us.max(r.jitter_us);
			println!(
				"  stream {idx:>2}  receiver  {:>10}  {:>12}",
				format_bytes(r.bytes),
				format_rate(r.bits_per_second(report.seconds))
			);
		}
	}
	let _ = params;
	if total_sent.packets > 0 {
		println!(
			"  total          sender    {:>10}  {:>12}",
			format_bytes(total_sent.bytes),
			format_rate(total_sent.bits_per_second(report.seconds))
		);
	}
	if total_recv.packets > 0 {
		println!(
			"  total          receiver  {:>10}  {:>12}",
			format_bytes(total_recv.bytes),
			format_rate(total_recv.bits_per_second(report.seconds))
		);
	}
}

fn format_bytes(value: u64) -> String {
	const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
	const MIB: f64 = 1024.0 * 1024.0;
	const KIB: f64 = 1024.0;
	let value = value as f64;
	if value >= GIB {
		format!("{:.3} GiB", value / GIB)
	} else if value >= MIB {
		format!("{:.1} MiB", value / MIB)
	} else {
		format!("{:.1} KiB", value / KIB)
	}
}

fn format_rate(bps: f64) -> String {
	if bps >= 1e9 {
		format!("{:.3} Gbit/s", bps / 1e9)
	} else if bps >= 1e6 {
		format!("{:.1} Mbit/s", bps / 1e6)
	} else {
		format!("{:.1} Kbit/s", bps / 1e3)
	}
}
