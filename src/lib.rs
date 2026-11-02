//! `wiperf`: transport-agnostic iperf3-wire-compatible benchmark library built
//! on [`completion`].
//!
//! The protocol layer speaks the upstream iperf3 v3.x control and data-plane
//! wire format:
//! - 37-byte session cookie (`36` base32 characters + NUL terminator),
//! - 1-byte signed state transitions (`PARAM_EXCHANGE`, `CREATE_STREAMS`,
//!   `TEST_START`, `TEST_RUNNING`, `TEST_END`, `EXCHANGE_RESULTS`,
//!   `DISPLAY_RESULTS`, `IPERF_DONE`),
//! - 4-byte big-endian length-prefixed JSON (`TestParams` and
//!   `TestResultsJson`),
//! - 4-byte UDP stream handshake (`0x36373839` / `0x39383736`) and 16-byte
//!   64-bit UDP datagram header (`[sec: u32 BE][usec: u32 BE][seq: u64 BE]`).
//!
//! Stream tests run over [`StreamIo`] and generic connector/acceptor closures,
//! so the exact same client and server state machines run unmodified over TCP,
//! Unix domain sockets, Linux `AF_VSOCK`, or multiplexed SSH
//! `direct-tcpip` channels. UDP is the one IP-specific transport and lives in
//! its own module; the stream core never names a socket family.
//!
//! A test's `time` includes its `omit` warm-up: a 10 s test with `-O 2` runs
//! for 10 s and reports the last 8 s. [`Window`] carries both instants, and
//! [`Meter`] counts only bytes that arrive between them.

mod meter;
mod protocol;
mod stream;
mod transport;
mod udp;

use std::net::SocketAddr;

use completion::Listener;

pub use meter::{Meter, Window};
pub use protocol::{
	COOKIE_SIZE, Counters, DATAGRAM_HEADER, DEFAULT_PORT, DEFAULT_TCP_BLKSIZE, DEFAULT_UDP_BLKSIZE,
	DatagramHeader, MAX_JSON_LEN, Report, StreamReport, StreamResultJson, TestParams,
	TestResultsJson, TestState, UDP_CONNECT_MSG, UDP_CONNECT_REPLY, decode_datagram,
	encode_datagram, make_cookie, next_stream_id, read_json, read_state, to_io, write_json,
	write_state,
};
pub use stream::{
	SocketStream, Stop, StreamIo, absorb_stream, blast_stream, build_report, read_exact,
	run_stream_client, serve_stream_control, serve_stream_listener, serve_stream_once,
};
pub use transport::{bind_tcp, bind_unix, connect_tcp, connect_tcp_any, connect_unix, resolve};
#[cfg(target_os = "linux")]
pub use transport::{bind_vsock, connect_vsock};
pub use udp::run_udp_client;

/// Serves one iperf3 session on a TCP control [`Listener`].
///
/// The control connection decides the transport: a TCP test accepts its data
/// connections on the same listener, while a UDP test binds `bind_addr` for
/// the datagram flows. The state machine itself is the generic one in
/// [`stream`], so there is no second copy for the IP case.
pub async fn serve_ip_once(
	listener: &Listener,
	bind_addr: SocketAddr,
) -> std::io::Result<(TestParams, Report)> {
	let sock = listener.accept().await.map_err(to_io)?;
	let mut ctrl = SocketStream::new(sock);
	let (cookie, params) = stream::read_params(&mut ctrl).await?;
	let report = if params.is_udp() {
		udp::serve_udp_session(&mut ctrl, &params, bind_addr).await?
	} else {
		stream::serve_stream_session(&mut ctrl, &cookie, &params, || async {
			let sock = listener.accept().await.map_err(to_io)?;
			Ok(SocketStream::new(sock))
		})
		.await?
	};
	Ok((params, report))
}

#[cfg(test)]
mod tests {
	use std::io::{Read, Write};
	use std::time::{Duration, Instant};

	use super::{
		SocketStream, TestParams, TestState, bind_tcp, bind_unix, connect_tcp, connect_unix,
		make_cookie, next_stream_id, run_stream_client, run_udp_client, serve_ip_once,
		serve_stream_listener, serve_stream_once, to_io,
	};

	fn tempdir() -> tempfile::TempDir {
		let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-tmp");
		std::fs::create_dir_all(&base).unwrap();
		tempfile::Builder::new()
			.prefix("wiperf-")
			.tempdir_in(base)
			.unwrap()
	}

	fn params(seconds: u32, omit: u32) -> TestParams {
		TestParams {
			tcp: Some(true),
			time: Some(seconds),
			omit: (omit > 0).then_some(omit),
			..Default::default()
		}
	}

	#[test]
	fn parameters_validate_the_supported_subset() {
		assert!(TestParams::default().validate().is_ok());
		for bad in [
			TestParams {
				parallel: Some(0),
				..Default::default()
			},
			TestParams {
				time: Some(0),
				..Default::default()
			},
			TestParams {
				len: Some(u32::MAX),
				..Default::default()
			},
			TestParams {
				time: Some(1),
				omit: Some(1),
				..Default::default()
			},
			TestParams {
				tcp: Some(true),
				udp: Some(true),
				..Default::default()
			},
		] {
			assert!(bad.validate().is_err());
		}
	}

	#[test]
	fn stream_id_assigns_iperf3_sequence() {
		assert_eq!(next_stream_id(0), 1);
		assert_eq!(next_stream_id(1), 3);
		assert_eq!(next_stream_id(2), 4);
	}

	#[test]
	fn measured_window_excludes_the_omit() {
		assert_eq!(params(10, 0).measured_seconds(), 10.0);
		assert_eq!(params(10, 2).measured_seconds(), 8.0);
	}

	#[test]
	fn udp_on_a_stream_transport_is_rejected() {
		let udp = TestParams {
			udp: Some(true),
			udp_counters_64bit: Some(1),
			time: Some(1),
			..Default::default()
		};
		let error = completion::block_on(run_stream_client::<SocketStream, _, _>(&udp, || async {
			unreachable!("a datagram test is rejected before it connects")
		}))
		.unwrap()
		.unwrap_err();
		assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
	}

	#[test]
	fn tcp_stream_round_trips_forward_and_reverse() {
		completion::block_on(async {
			for reverse in [false, true] {
				let (listener, addr) = bind_tcp("127.0.0.1:0".parse().unwrap()).unwrap();
				let server = completion::spawn(async move {
					serve_stream_once(|| async {
						let sock = listener.accept().await.map_err(to_io)?;
						Ok(SocketStream::new(sock))
					})
					.await
				});
				let params = TestParams {
					parallel: Some(2),
					reverse: Some(reverse),
					len: Some(4096),
					..params(1, 0)
				};
				let client_report = run_stream_client(&params, || connect_tcp(addr))
					.await
					.unwrap();
				let (_srv_params, server_report) = server.await.unwrap();
				assert_eq!(client_report.streams.len(), 2);
				assert_eq!(server_report.streams.len(), 2);
				for stream in &client_report.streams {
					assert!(stream.sender.unwrap().bytes > 0);
					assert!(stream.receiver.unwrap().bytes > 0);
				}
			}
		})
		.unwrap();
	}

	#[test]
	fn unix_stream_round_trips() {
		let dir = tempdir();
		let path = dir.path().join("wiperf.sock");
		completion::block_on(async {
			let listener = bind_unix(&path).unwrap();
			let server = completion::spawn(async move {
				serve_stream_once(|| async {
					let sock = listener.accept().await.map_err(to_io)?;
					Ok(SocketStream::new(sock))
				})
				.await
			});
			let params = TestParams {
				len: Some(1024),
				parallel: Some(2),
				..params(1, 0)
			};
			let client_report = run_stream_client(&params, || async { connect_unix(&path) })
				.await
				.unwrap();
			server.await.unwrap();
			assert_eq!(client_report.streams.len(), 2);
			for stream in &client_report.streams {
				assert!(stream.sender.unwrap().bytes >= 1024);
				assert!(stream.receiver.unwrap().bytes > 0);
			}
		})
		.unwrap();
	}

	#[test]
	fn udp_round_trips_forward_and_reverse() {
		completion::block_on(async {
			for reverse in [false, true] {
				let (listener, addr) = bind_tcp("127.0.0.1:0".parse().unwrap()).unwrap();
				let server = completion::spawn(async move {
					let result = serve_ip_once(&listener, addr).await;
					result.map(|(_, report)| report)
				});
				let params = TestParams {
					udp: Some(true),
					udp_counters_64bit: Some(1),
					time: Some(1),
					len: Some(1460),
					bandwidth: Some(10_000_000),
					reverse: Some(reverse),
					..Default::default()
				};
				let client_report = run_udp_client(&params, addr).await.unwrap();
				let _server_report = server.await.unwrap();
				assert_eq!(client_report.streams.len(), 1);
				assert!(client_report.streams[0].sender.unwrap().packets > 0);
			}
		})
		.unwrap();
	}

	#[test]
	fn a_vanished_client_does_not_leave_server_tasks_attached() {
		let (listener, addr) = bind_tcp("127.0.0.1:0".parse().unwrap()).unwrap();

		// Speak just enough of the protocol to start a long test, then close
		// both connections without a TEST_END. The server must not wait out
		// the data window: cancelling and joining the data tasks is what makes
		// it return at once.
		let client = std::thread::spawn(move || {
			let cookie = make_cookie();
			let mut ctrl = std::net::TcpStream::connect(addr).unwrap();
			ctrl.write_all(&cookie).unwrap();
			let mut state = [0u8; 1];
			ctrl.read_exact(&mut state).unwrap();
			assert_eq!(
				TestState::from_wire(state[0] as i8).unwrap(),
				TestState::ParamExchange
			);
			let body = serde_json::to_vec(&params(5, 0)).unwrap();
			ctrl.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
			ctrl.write_all(&body).unwrap();
			ctrl.read_exact(&mut state).unwrap();
			assert_eq!(
				TestState::from_wire(state[0] as i8).unwrap(),
				TestState::CreateStreams
			);
			let mut data = std::net::TcpStream::connect(addr).unwrap();
			data.write_all(&cookie).unwrap();
			data.shutdown(std::net::Shutdown::Both).unwrap();
			drop(data);
			drop(ctrl);
		});

		let started = Instant::now();
		let result = completion::block_on(async {
			let server = serve_stream_once(|| async {
				let sock = listener.accept().await.map_err(to_io)?;
				Ok(SocketStream::new(sock))
			});
			let timer = completion::timeout(Duration::from_secs(2));
			futures_util::pin_mut!(server, timer);
			match futures_util::future::select(server, timer).await {
				futures_util::future::Either::Left((result, _)) => result,
				futures_util::future::Either::Right(_) => {
					panic!("the server kept its data tasks after the client vanished")
				}
			}
		});
		client.join().unwrap();
		let result = result.unwrap();
		assert!(result.is_err());
		assert!(started.elapsed() < Duration::from_secs(2));
	}

	#[test]
	fn an_existing_unix_path_is_never_removed() {
		let dir = tempdir();
		let path = dir.path().join("not-a-socket");
		std::fs::write(&path, b"keep me").unwrap();
		let error = match bind_unix(&path) {
			Ok(_) => panic!("binding over an existing file must fail"),
			Err(error) => error,
		};
		assert!(matches!(
			error.kind(),
			std::io::ErrorKind::AddrInUse | std::io::ErrorKind::AlreadyExists
		));
		assert_eq!(std::fs::read(&path).unwrap(), b"keep me");
	}

	#[test]
	fn concurrent_stream_sessions_do_not_block_each_other() {
		let dir = tempdir();
		let path = dir.path().join("concurrent.sock");
		let listener = bind_unix(&path).unwrap();

		// Hold one session open after its cookie so a serial accept loop would
		// block behind it, then run a complete second session beside it.
		let stalled_path = path.clone();
		let stalled = std::thread::spawn(move || {
			let mut ctrl = std::os::unix::net::UnixStream::connect(&stalled_path).unwrap();
			ctrl.write_all(&make_cookie()).unwrap();
			let mut state = [0u8; 1];
			ctrl.read_exact(&mut state).unwrap();
			assert_eq!(
				TestState::from_wire(state[0] as i8).unwrap(),
				TestState::ParamExchange
			);
			std::thread::sleep(Duration::from_millis(400));
		});

		completion::block_on(async {
			let server = completion::spawn(async move {
				drop(serve_stream_listener(&listener, |_, _| {}).await);
			});
			let client_path = path.clone();
			let report = run_stream_client(&params(1, 0), || {
				let client_path = client_path.clone();
				async move { connect_unix(&client_path) }
			})
			.await
			.unwrap();
			assert_eq!(report.streams.len(), 1);
			assert!(report.streams[0].sender.unwrap().bytes > 0);
			drop(server);
		})
		.unwrap();
		stalled.join().unwrap();
	}
}
