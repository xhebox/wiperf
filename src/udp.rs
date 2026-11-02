//! The iperf3 UDP data plane.
//!
//! UDP is the one transport this crate implements with IP socket types: the
//! control connection is TCP, the data plane is a set of unconnected datagram
//! sockets, and the server pairs a datagram with a stream by the peer address
//! it came from. Everything above this module is transport independent; a
//! future datagram transport plugs in where [`run_udp_client`] and
//! [`serve_udp_session`] sit.

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
use std::rc::Rc;
use std::time::{Duration, Instant};

use completion::{Buffer, DatagramSocket, OwnedSocket, StreamSocket, timeout};
use futures_util::future::{Either, select};
use futures_util::pin_mut;
use socket2::{Domain, SockAddr, Socket, Type};

use crate::meter::{Meter, Window};
use crate::protocol::{
	Counters, DATAGRAM_HEADER, MAX_JSON_LEN, Report, StreamResultJson, TestParams, TestResultsJson,
	TestState, UDP_CONNECT_MSG, UDP_CONNECT_REPLY, UDP_CONNECT_REPLY_LEGACY, decode_datagram,
	encode_datagram, make_cookie, next_stream_id, read_json, read_state, to_io, write_json,
	write_state,
};
use crate::stream::{
	SocketStream, Stop, StreamIo, build_report, completion_io, control, control_for, until_stopped,
};

/// How often a raw non-blocking socket wakes to look at its deadline.
const RECV_POLL: Duration = Duration::from_millis(50);

/// Grace period a receiver drains after the measured window closes.
const DRAIN_GRACE: Duration = Duration::from_millis(250);

/// How long the UDP connect handshake may take.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// A buffer of exactly `len` bytes that no in-flight operation names.
fn exclusive(buffer: &mut Buffer, len: usize) -> &mut [u8] {
	if buffer.len() != len || buffer.get_mut().is_none() {
		*buffer = Buffer::zeroed(len);
	}
	buffer.get_mut().expect("just made exclusive")
}

fn connect_udp(bind_addr: SocketAddr, server_addr: SocketAddr) -> io::Result<DatagramSocket> {
	let domain = if server_addr.is_ipv4() {
		Domain::IPV4
	} else {
		Domain::IPV6
	};
	let socket = Socket::new(domain, Type::DGRAM, None)?;
	socket.set_nonblocking(true)?;
	socket.bind(&SockAddr::from(bind_addr))?;
	socket.connect(&SockAddr::from(server_addr))?;
	Ok(DatagramSocket::new(OwnedSocket::from(socket)))
}

fn bind_udp_reuse(addr: SocketAddr) -> io::Result<(StdUdpSocket, DatagramSocket)> {
	let domain = if addr.is_ipv4() {
		Domain::IPV4
	} else {
		Domain::IPV6
	};
	let socket = Socket::new(domain, Type::DGRAM, None)?;
	socket.set_reuse_address(true)?;
	socket.set_nonblocking(true)?;
	socket.bind(&SockAddr::from(addr))?;
	let dup = socket.try_clone()?;
	Ok((
		StdUdpSocket::from(socket),
		DatagramSocket::new(OwnedSocket::from(dup)),
	))
}

/// Client-side UDP handshake on a connected [`DatagramSocket`].
async fn udp_handshake_client(socket: &DatagramSocket) -> io::Result<()> {
	let mut send_buf = Buffer::zeroed(4);
	send_buf
		.get_mut()
		.expect("fresh buffer")
		.copy_from_slice(&UDP_CONNECT_MSG.to_ne_bytes());
	let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
	while Instant::now() < deadline {
		socket.send(send_buf.clone()).await.map_err(to_io)?;
		// A cancelled receive may still be retained by the kernel until its
		// CQE, so each attempt uses its own buffer rather than reusing one an
		// in-flight operation could still write.
		let mut recv_buf = Buffer::zeroed(64);
		let recv = socket.recv(recv_buf.clone());
		let timer = timeout(Duration::from_millis(250));
		pin_mut!(recv, timer);
		if let Either::Left((Ok(n), _)) = select(recv, timer).await
			&& n >= 4
		{
			let mut reply = [0u8; 4];
			let bytes = recv_buf.get_mut().expect("recv completed");
			reply.copy_from_slice(&bytes[..4]);
			let reply = u32::from_ne_bytes(reply);
			if reply == UDP_CONNECT_REPLY || reply == UDP_CONNECT_REPLY_LEGACY {
				return Ok(());
			}
		}
	}
	Err(io::Error::new(
		io::ErrorKind::TimedOut,
		"UDP stream connect handshake timed out",
	))
}

async fn udp_send_connected(
	socket: DatagramSocket,
	dgram_len: usize,
	window: Window,
	bitrate: Option<u64>,
	stop: &Stop,
) -> io::Result<Counters> {
	let mut buf = Buffer::zeroed(dgram_len);
	let mut meter = Meter::new(window);
	let started = Instant::now();
	let mut seq = 1u64;
	while !stop.is_cancelled() {
		let now = Instant::now();
		if now >= window.deadline {
			break;
		}
		if let Some(rate) = bitrate.filter(|&r| r > 0) {
			let due =
				started + Duration::from_secs_f64(meter.counted_bytes() as f64 * 8.0 / rate as f64);
			if now < due {
				if until_stopped(
					async { timeout(due - now).await.map_err(to_io) },
					stop,
					window.deadline,
				)
				.await
				.is_none()
				{
					break;
				}
				continue;
			}
		}
		encode_datagram(exclusive(&mut buf, dgram_len), seq);
		match until_stopped(
			completion_io(socket.send(buf.clone())),
			stop,
			window.deadline,
		)
		.await
		{
			Some(Ok(_)) => {
				seq += 1;
				meter.record_stream(Instant::now(), dgram_len as u64);
			}
			Some(Err(error)) => {
				log::debug!("wiperf: udp send stopped: {error}");
				break;
			}
			None => break,
		}
	}
	Ok(meter.finish(Instant::now()))
}

async fn udp_send_to_peer(
	raw: Rc<StdUdpSocket>,
	wait: DatagramSocket,
	peer: SocketAddr,
	dgram_len: usize,
	window: Window,
	bitrate: Option<u64>,
	stop: &Stop,
) -> io::Result<Counters> {
	let mut datagram = Buffer::zeroed(dgram_len);
	let mut meter = Meter::new(window);
	let started = Instant::now();
	let mut seq = 1u64;
	while !stop.is_cancelled() {
		// A raw non-blocking send spends no executor budget, so every turn
		// yields; a saturated sender must not starve the control task or a
		// timer.
		completion::yield_now().await;
		let now = Instant::now();
		if now >= window.deadline {
			break;
		}
		if let Some(rate) = bitrate.filter(|&r| r > 0) {
			let due =
				started + Duration::from_secs_f64(meter.counted_bytes() as f64 * 8.0 / rate as f64);
			if now < due {
				if until_stopped(
					async { timeout(due - now).await.map_err(to_io) },
					stop,
					window.deadline,
				)
				.await
				.is_none()
				{
					break;
				}
				continue;
			}
		}
		encode_datagram(exclusive(&mut datagram, dgram_len), seq);
		match raw.send_to(datagram.get_mut().expect("exclusive"), peer) {
			Ok(_) => {
				seq += 1;
				meter.record_stream(Instant::now(), dgram_len as u64);
			}
			Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
				if until_stopped(
					completion_io(wait.writable()),
					stop,
					window.deadline.min(Instant::now() + RECV_POLL),
				)
				.await
				.is_none()
				{
					break;
				}
			}
			Err(error) => {
				log::debug!("wiperf: udp send_to stopped: {error}");
				break;
			}
		}
	}
	Ok(meter.finish(Instant::now()))
}

async fn udp_recv_connected(
	socket: DatagramSocket,
	dgram_len: usize,
	window: Window,
	stop: &Stop,
) -> io::Result<Counters> {
	let mut buf = Buffer::zeroed(dgram_len.max(DATAGRAM_HEADER + 1));
	let mut meter = Meter::new(window);
	let drain_until = window.deadline + DRAIN_GRACE;
	while !stop.is_cancelled() {
		if Instant::now() >= drain_until {
			break;
		}
		match until_stopped(completion_io(socket.recv(buf.clone())), stop, drain_until).await {
			Some(Ok(n)) if n >= DATAGRAM_HEADER => {
				let bytes = &buf.get_mut().expect("recv completed")[..n];
				if let Ok(header) = decode_datagram(bytes) {
					meter.record_datagram(Instant::now(), &header, n as u64);
				}
			}
			Some(Ok(_)) => continue,
			Some(Err(error)) => return Err(error),
			None => break,
		}
	}
	Ok(meter.finish(Instant::now()))
}

/// Runs an iperf3 UDP client against `server_addr` (control over TCP, data over UDP).
pub async fn run_udp_client(params: &TestParams, server_addr: SocketAddr) -> io::Result<Report> {
	params.validate()?;
	let cookie = make_cookie();
	let ctrl_sock = control("connecting the UDP control channel", async {
		StreamSocket::connect(server_addr).await.map_err(to_io)
	})
	.await?;
	let mut ctrl = SocketStream::new(ctrl_sock);
	control("sending the session cookie", ctrl.write_all_bytes(&cookie)).await?;

	let state = control("waiting for PARAM_EXCHANGE", read_state(&mut ctrl)).await?;
	if state != TestState::ParamExchange {
		return Err(io::Error::new(
			io::ErrorKind::InvalidData,
			format!("expected ParamExchange, got {state:?}"),
		));
	}
	let mut wire_params = params.clone();
	wire_params.tcp = None;
	wire_params.udp = Some(true);
	wire_params.udp_counters_64bit = Some(1);
	wire_params.validate()?;
	if wire_params.client_version.is_none() {
		wire_params.client_version = Some(format!("wiperf-{}", env!("CARGO_PKG_VERSION")));
	}
	control(
		"sending the test parameters",
		write_json(&mut ctrl, &wire_params),
	)
	.await?;

	let state = control("waiting for CREATE_STREAMS", read_state(&mut ctrl)).await?;
	if state != TestState::CreateStreams {
		return Err(io::Error::new(
			io::ErrorKind::InvalidData,
			format!("expected CreateStreams, got {state:?}"),
		));
	}

	let bind_any: SocketAddr = if server_addr.is_ipv4() {
		"0.0.0.0:0".parse().unwrap()
	} else {
		"[::]:0".parse().unwrap()
	};
	let stream_count = wire_params.streams();
	let mut udp_sockets = Vec::with_capacity(stream_count as usize);
	for _ in 0..stream_count {
		let udp = connect_udp(bind_any, server_addr)?;
		control("running the UDP handshake", udp_handshake_client(&udp)).await?;
		udp_sockets.push(udp);
	}

	control("waiting for TEST_RUNNING", async {
		loop {
			match read_state(&mut ctrl).await? {
				TestState::TestStart => continue,
				TestState::TestRunning => return Ok(()),
				other => {
					return Err(io::Error::new(
						io::ErrorKind::InvalidData,
						format!("expected TestStart/TestRunning, got {other:?}"),
					));
				}
			}
		}
	})
	.await?;

	let window = Window::start(wire_params.seconds(), wire_params.omit_seconds());
	let dgram_len = wire_params.blksize();
	let reverse = wire_params.is_reverse();
	let bitrate = wire_params.bandwidth;
	let stop = Stop::new();

	let tasks: Vec<_> = udp_sockets
		.into_iter()
		.enumerate()
		.map(|(index, udp)| {
			let stop = stop.clone();
			completion::spawn(async move {
				let counters = if reverse {
					udp_recv_connected(udp, dgram_len, window, &stop).await?
				} else {
					udp_send_connected(udp, dgram_len, window, bitrate, &stop).await?
				};
				Ok::<(u16, Counters), io::Error>((index as u16, counters))
			})
		})
		.collect();

	let window_result = control_for(
		"running the test window",
		Duration::from_secs(u64::from(wire_params.seconds())) + Duration::from_secs(30),
		async {
			timeout(Duration::from_secs(u64::from(wire_params.seconds())))
				.await
				.map_err(to_io)
		},
	)
	.await;
	if !reverse || window_result.is_err() {
		stop.cancel();
	}

	let mut local_streams = Vec::with_capacity(tasks.len());
	let mut first_error = None;
	for task in tasks {
		match task.await {
			Ok((index, counters)) => local_streams.push(counters.to_wire(next_stream_id(index))),
			Err(error) if first_error.is_none() => first_error = Some(error),
			Err(_) => {}
		}
	}
	window_result?;

	control(
		"sending TEST_END",
		write_state(&mut ctrl, TestState::TestEnd),
	)
	.await?;
	control("waiting for EXCHANGE_RESULTS", async {
		loop {
			match read_state(&mut ctrl).await? {
				TestState::TestRunning => continue,
				TestState::ExchangeResults => return Ok(()),
				other => {
					return Err(io::Error::new(
						io::ErrorKind::InvalidData,
						format!("expected ExchangeResults, got {other:?}"),
					));
				}
			}
		}
	})
	.await?;

	let local_results = TestResultsJson {
		sender_has_retransmits: -1,
		streams: local_streams,
		..Default::default()
	};
	control(
		"sending the client's results",
		write_json(&mut ctrl, &local_results),
	)
	.await?;
	let remote_results: TestResultsJson = control(
		"reading the server's results",
		read_json(&mut ctrl, MAX_JSON_LEN),
	)
	.await?;
	control("waiting for DISPLAY_RESULTS", read_state(&mut ctrl)).await?;
	control(
		"sending IPERF_DONE",
		write_state(&mut ctrl, TestState::IperfDone),
	)
	.await?;
	if let Err(error) = ctrl.shutdown_write().await {
		log::debug!("wiperf: control half-close: {error}");
	}
	if let Some(error) = first_error {
		return Err(error);
	}
	Ok(build_report(
		&wire_params,
		true,
		&local_results,
		&remote_results,
	))
}

/// Serves one UDP test on `bind_addr` after the caller read the control
/// connection's parameters.
#[expect(
	clippy::redundant_pub_crate,
	reason = "keep this helper crate-internal without triggering unreachable_pub"
)]
pub(crate) async fn serve_udp_session(
	ctrl: &mut impl StreamIo,
	params: &TestParams,
	bind_addr: SocketAddr,
) -> io::Result<Report> {
	let (raw_udp, wait_udp) = bind_udp_reuse(bind_addr)?;
	let raw_udp = Rc::new(raw_udp);
	control(
		"sending CREATE_STREAMS",
		write_state(ctrl, TestState::CreateStreams),
	)
	.await?;

	let stream_count = params.streams();
	let mut peers: Vec<SocketAddr> = Vec::with_capacity(stream_count as usize);
	let mut peer_index: HashMap<SocketAddr, usize> = HashMap::new();
	let mut hs_buf = [0u8; 2048];
	let reply_bytes = UDP_CONNECT_REPLY.to_ne_bytes();
	let setup_deadline = Instant::now() + Duration::from_secs(30);

	while peers.len() < stream_count as usize {
		completion::yield_now().await;
		if Instant::now() >= setup_deadline {
			return Err(io::Error::new(
				io::ErrorKind::TimedOut,
				"UDP peers did not announce every stream",
			));
		}
		match raw_udp.recv_from(&mut hs_buf) {
			Ok((n, peer)) => {
				if n < 4 {
					continue;
				}
				let msg = u32::from_ne_bytes(hs_buf[..4].try_into().unwrap());
				if msg == UDP_CONNECT_MSG {
					raw_udp.send_to(&reply_bytes, peer)?;
					if let std::collections::hash_map::Entry::Vacant(entry) = peer_index.entry(peer)
					{
						let idx = peers.len();
						entry.insert(idx);
						peers.push(peer);
					}
				}
			}
			Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
				let readable = wait_udp.readable();
				let timer = timeout(RECV_POLL);
				pin_mut!(readable, timer);
				drop(select(readable, timer).await);
			}
			Err(e) => return Err(e),
		}
	}

	control(
		"sending TEST_START",
		write_state(ctrl, TestState::TestStart),
	)
	.await?;
	control(
		"sending TEST_RUNNING",
		write_state(ctrl, TestState::TestRunning),
	)
	.await?;

	let window = Window::start(params.seconds(), params.omit_seconds());
	let dgram_len = params.blksize();
	let reverse = params.is_reverse();
	let bitrate = params.bandwidth;
	let stop = Stop::new();

	let local_streams: Vec<StreamResultJson> = if reverse {
		let tasks: Vec<_> = peers
			.into_iter()
			.enumerate()
			.map(|(index, peer)| {
				let raw = Rc::clone(&raw_udp);
				let wait = wait_udp.clone();
				let stop = stop.clone();
				completion::spawn(async move {
					let counters =
						udp_send_to_peer(raw, wait, peer, dgram_len, window, bitrate, &stop)
							.await?;
					Ok::<(u16, Counters), io::Error>((index as u16, counters))
				})
			})
			.collect();
		let end = wait_for_test_end(ctrl, params).await;
		stop.cancel();
		let mut streams = Vec::with_capacity(tasks.len());
		let mut first_error = None;
		for task in tasks {
			match task.await {
				Ok((index, counters)) => streams.push(counters.to_wire(next_stream_id(index))),
				Err(error) if first_error.is_none() => first_error = Some(error),
				Err(_) => {}
			}
		}
		if let Some(error) = first_error {
			return Err(error);
		}
		end?;
		streams
	} else {
		let stop_clone = stop.clone();
		let raw = Rc::clone(&raw_udp);
		let wait = wait_udp.clone();
		let recv = completion::spawn(async move {
			let mut meters: Vec<Meter> = (0..stream_count).map(|_| Meter::new(window)).collect();
			let mut buf = Buffer::zeroed(65536);
			let drain_until = window.deadline + DRAIN_GRACE;
			while !stop_clone.is_cancelled() {
				completion::yield_now().await;
				let now = Instant::now();
				if now >= drain_until {
					break;
				}
				match raw.recv_from(buf.get_mut().expect("raw receive buffer")) {
					Ok((n, peer)) => {
						if n >= DATAGRAM_HEADER
							&& let Some(&index) = peer_index.get(&peer)
							&& let Ok(header) = decode_datagram(&buf.get_mut().expect("recv")[..n])
						{
							meters[index].record_datagram(now, &header, n as u64);
						}
					}
					Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
						if until_stopped(
							completion_io(wait.readable()),
							&stop_clone,
							drain_until.min(Instant::now() + RECV_POLL),
						)
						.await
						.is_none()
						{
							break;
						}
					}
					Err(e) => return Err(e),
				}
			}
			let finished = Instant::now();
			Ok::<Vec<StreamResultJson>, io::Error>(
				meters
					.into_iter()
					.enumerate()
					.map(|(index, meter)| {
						meter.finish(finished).to_wire(next_stream_id(index as u16))
					})
					.collect(),
			)
		});
		let end = wait_for_test_end(ctrl, params).await;
		if end.is_err() {
			stop.cancel();
		}
		let streams = recv.await?;
		end?;
		streams
	};

	control(
		"sending EXCHANGE_RESULTS",
		write_state(ctrl, TestState::ExchangeResults),
	)
	.await?;
	let remote_results: TestResultsJson = control(
		"reading the client's results",
		read_json(ctrl, MAX_JSON_LEN),
	)
	.await?;
	let local_results = TestResultsJson {
		sender_has_retransmits: -1,
		streams: local_streams,
		..Default::default()
	};
	control(
		"sending the server's results",
		write_json(ctrl, &local_results),
	)
	.await?;
	control(
		"sending DISPLAY_RESULTS",
		write_state(ctrl, TestState::DisplayResults),
	)
	.await?;
	control("waiting for IPERF_DONE", read_state(ctrl)).await?;
	Ok(build_report(params, false, &local_results, &remote_results))
}

/// Waits for the client's `TEST_END` with a bound that covers the test itself.
async fn wait_for_test_end(ctrl: &mut impl StreamIo, params: &TestParams) -> io::Result<()> {
	control_for(
		"waiting for TEST_END",
		Duration::from_secs(u64::from(params.seconds())) + Duration::from_secs(30),
		async {
			loop {
				match read_state(ctrl).await? {
					TestState::TestEnd | TestState::ClientTerminate => return Ok(()),
					_ => continue,
				}
			}
		},
	)
	.await
}
