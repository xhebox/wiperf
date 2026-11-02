//! The stream data plane and the client/server state machines that run over
//! any [`StreamIo`].
//!
//! A stream test opens one control connection and one data connection per
//! stream, both through the same caller-supplied connect/accept closure. The
//! state machine is the iperf3 one; the only transport-specific part is the
//! closure, which is why TCP, `AF_UNIX`, `AF_VSOCK`, and an SSH `direct-tcpip`
//! channel all run the same code.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::net::Shutdown;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use completion::{Buffer, Listener, StreamSocket, timeout};
use event_listener::Event;
use futures_util::future::{Either, select};
use futures_util::pin_mut;

use crate::meter::{Meter, Window};
use crate::protocol::{
	COOKIE_SIZE, Counters, MAX_JSON_LEN, Report, StreamReport, TestParams, TestResultsJson,
	TestState, next_stream_id, read_json, read_state, to_io, write_json, write_state,
};

/// How long the control channel may take for one handshake step.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(30);

/// Grace period a receiver drains after the measured window closes.
const DRAIN_GRACE: Duration = Duration::from_millis(250);

/// Receiving a stream must not turn a small sender write into a mandatory
/// small read: the benchmark should measure the sender's packet cost.
const RECEIVE_BLOCK: usize = 128 * 1024;

/// Any ordered byte stream used as an iperf3 control or data connection.
pub trait StreamIo: 'static {
	fn read_into(&mut self, buf: &mut [u8]) -> impl Future<Output = io::Result<usize>>;
	fn write_all_bytes(&mut self, buf: &[u8]) -> impl Future<Output = io::Result<()>>;
	fn shutdown_write(&mut self) -> impl Future<Output = io::Result<()>>;
}

/// [`completion::StreamSocket`] paired with reusable I/O buffers so hot-path
/// transfers do not allocate per call.
pub struct SocketStream {
	socket: StreamSocket,
	read_buf: Buffer,
	write_buf: Buffer,
}

impl SocketStream {
	pub fn new(socket: StreamSocket) -> Self {
		Self {
			socket,
			read_buf: Buffer::zeroed(0),
			write_buf: Buffer::zeroed(0),
		}
	}

	pub fn into_inner(self) -> StreamSocket {
		self.socket
	}

	/// A buffer of at least `len` bytes whose bytes belong to no in-flight
	/// operation.
	///
	/// A cancelled operation keeps its buffer alive until the kernel reports
	/// the completion, so `get_mut` is `None` while that is outstanding:
	/// replacing the buffer, never mutating it, is what keeps the next
	/// transfer from aliasing bytes the kernel still reads or writes.
	fn reusable(buffer: &mut Buffer, len: usize) {
		if buffer.len() < len || buffer.get_mut().is_none() {
			*buffer = Buffer::zeroed(len);
		}
	}
}

impl StreamIo for SocketStream {
	async fn read_into(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		if buf.is_empty() {
			return Ok(0);
		}
		Self::reusable(&mut self.read_buf, buf.len());
		let span = self.read_buf.slice(..buf.len());
		let n = self.socket.recv(span).await.map_err(to_io)?;
		if n > 0 {
			let src = self.read_buf.get_mut().expect("recv completed");
			buf[..n].copy_from_slice(&src[..n]);
		}
		Ok(n)
	}

	async fn write_all_bytes(&mut self, buf: &[u8]) -> io::Result<()> {
		if buf.is_empty() {
			return Ok(());
		}
		Self::reusable(&mut self.write_buf, buf.len());
		self.write_buf.get_mut().expect("no write in flight")[..buf.len()].copy_from_slice(buf);
		let span = self.write_buf.slice(..buf.len());
		self.socket.send_all(span).await.map_err(to_io)?;
		Ok(())
	}

	async fn shutdown_write(&mut self) -> io::Result<()> {
		self.socket.shutdown(Shutdown::Write)
	}
}

/// Reads exact `buf.len()` bytes from `stream`.
pub async fn read_exact<S: StreamIo>(stream: &mut S, buf: &mut [u8]) -> io::Result<()> {
	let mut filled = 0;
	while filled < buf.len() {
		let n = stream.read_into(&mut buf[filled..]).await?;
		if n == 0 {
			return Err(io::Error::new(
				io::ErrorKind::UnexpectedEof,
				"peer closed before frame completed",
			));
		}
		filled += n;
	}
	Ok(())
}

/// A wakeable stop signal shared by the control task and the data tasks.
///
/// `completion::spawn` has no abort handle: dropping the returned future only
/// detaches the task, which would leave it holding sockets and buffers until
/// its own deadline. Every data loop therefore races its I/O against this
/// signal, and the coordinating task awaits each spawned future before it
/// returns.
#[derive(Clone)]
pub struct Stop {
	flag: Arc<AtomicBool>,
	event: Arc<Event>,
}

impl Stop {
	pub fn new() -> Self {
		Self {
			flag: Arc::new(AtomicBool::new(false)),
			event: Arc::new(Event::new()),
		}
	}

	pub fn cancel(&self) {
		self.flag.store(true, Ordering::Release);
		self.event.notify(usize::MAX);
	}

	pub fn is_cancelled(&self) -> bool {
		self.flag.load(Ordering::Acquire)
	}

	/// Resolves when [`Stop::cancel`] runs, or at `deadline`.
	pub(crate) async fn wait(&self, deadline: Instant) {
		loop {
			// Register before the flag check: a cancel between the check and
			// the wait then wakes this listener instead of being missed.
			let listener = self.event.listen();
			if self.is_cancelled() {
				return;
			}
			let remaining = deadline.saturating_duration_since(Instant::now());
			let sleep = timeout(remaining);
			pin_mut!(listener, sleep);
			if matches!(select(listener, sleep).await, Either::Left(_)) {
				return;
			}
			if Instant::now() >= deadline {
				return;
			}
		}
	}
}

impl Default for Stop {
	fn default() -> Self {
		Self::new()
	}
}

/// Runs `op`, unless `stop` is cancelled or `deadline` passes first.
#[expect(
	clippy::redundant_pub_crate,
	reason = "keep this helper crate-internal without triggering unreachable_pub"
)]
pub(crate) async fn until_stopped<T>(
	op: impl Future<Output = io::Result<T>>,
	stop: &Stop,
	deadline: Instant,
) -> Option<io::Result<T>> {
	let stopping = stop.wait(deadline);
	pin_mut!(op, stopping);
	match select(op, stopping).await {
		Either::Left((result, _)) => Some(result),
		Either::Right(_) => None,
	}
}

/// Sends `blksize` chunks on `stream` until the window closes or `stop` is set.
pub async fn blast_stream<S: StreamIo>(
	stream: &mut S,
	blksize: usize,
	window: Window,
	stop: &Stop,
) -> io::Result<Counters> {
	let block = vec![0x5au8; blksize.max(1)];
	let mut meter = Meter::new(window);
	while !stop.is_cancelled() {
		let now = Instant::now();
		if now >= window.deadline {
			break;
		}
		match until_stopped(stream.write_all_bytes(&block), stop, window.deadline).await {
			Some(Ok(())) => meter.record_stream(Instant::now(), block.len() as u64),
			// A peer that stopped reading is how a sender learns the test is
			// over when the control channel is already gone.
			Some(Err(error)) => {
				log::debug!("wiperf: stream send stopped: {error}");
				break;
			}
			None => break,
		}
	}
	if let Err(error) = stream.shutdown_write().await {
		log::debug!("wiperf: stream half-close: {error}");
	}
	Ok(meter.finish(Instant::now()))
}

/// Reads up to `blksize` chunks from `stream` until EOF, `deadline + DRAIN_GRACE`,
/// or `stop` is set. Post-deadline bytes are discarded while draining; they do
/// not contribute to the measured throughput.
pub async fn absorb_stream<S: StreamIo>(
	stream: &mut S,
	blksize: usize,
	window: Window,
	stop: &Stop,
) -> io::Result<Counters> {
	let mut buf = vec![0u8; blksize.max(1)];
	let mut meter = Meter::new(window);
	let drain_until = window.deadline + DRAIN_GRACE;
	while !stop.is_cancelled() {
		let now = Instant::now();
		if now >= drain_until {
			break;
		}
		match until_stopped(stream.read_into(&mut buf), stop, drain_until).await {
			Some(Ok(0)) => break,
			Some(Ok(n)) => meter.record_stream(Instant::now(), n as u64),
			Some(Err(error))
				if matches!(
					error.kind(),
					io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
				) =>
			{
				break;
			}
			Some(Err(error)) => return Err(error),
			None => break,
		}
	}
	Ok(meter.finish(Instant::now()))
}

/// Combines local and remote [`TestResultsJson`] into a [`Report`].
pub fn build_report(
	params: &TestParams,
	client_is_local: bool,
	local: &TestResultsJson,
	remote: &TestResultsJson,
) -> Report {
	let sender_is_local = client_is_local != params.is_reverse();
	let count = params.streams();
	let mut streams = Vec::with_capacity(count as usize);
	for index in 0..count {
		let id = next_stream_id(index);
		let local_c = local
			.streams
			.iter()
			.find(|s| s.id == id)
			.or_else(|| local.streams.get(index as usize))
			.map(Counters::from_wire);
		let remote_c = remote
			.streams
			.iter()
			.find(|s| s.id == id)
			.or_else(|| remote.streams.get(index as usize))
			.map(Counters::from_wire);
		let (sender, receiver) = if sender_is_local {
			(local_c, remote_c)
		} else {
			(remote_c, local_c)
		};
		streams.push(StreamReport {
			index,
			sender,
			receiver,
		});
	}
	Report {
		streams,
		seconds: params.measured_seconds(),
	}
}

/// Runs a control-channel operation under [`CONTROL_TIMEOUT`].
#[expect(
	clippy::redundant_pub_crate,
	reason = "keep this helper crate-internal without triggering unreachable_pub"
)]
pub(crate) async fn control<T>(
	what: &str,
	op: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
	control_for(what, CONTROL_TIMEOUT, op).await
}

/// Runs a control-channel operation under an explicit limit.
#[expect(
	clippy::redundant_pub_crate,
	reason = "keep this helper crate-internal without triggering unreachable_pub"
)]
pub(crate) async fn control_for<T>(
	what: &str,
	limit: Duration,
	op: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
	let timer = timeout(limit);
	pin_mut!(op, timer);
	match select(op, timer).await {
		Either::Left((result, _)) => result,
		Either::Right(_) => Err(io::Error::new(
			io::ErrorKind::TimedOut,
			format!("{what} timed out after {limit:?}"),
		)),
	}
}

/// Converts a completion operation into an [`io::Result`].
#[expect(
	clippy::redundant_pub_crate,
	reason = "keep this helper crate-internal without triggering unreachable_pub"
)]
pub(crate) async fn completion_io<T>(
	op: impl Future<Output = completion::Result<T>>,
) -> io::Result<T> {
	op.await.map_err(to_io)
}

/// Reads the session cookie and `PARAM_EXCHANGE` parameters from `ctrl`.
#[expect(
	clippy::redundant_pub_crate,
	reason = "keep this helper crate-internal without triggering unreachable_pub"
)]
pub(crate) async fn read_params<S: StreamIo>(
	ctrl: &mut S,
) -> io::Result<([u8; COOKIE_SIZE], TestParams)> {
	let mut cookie = [0u8; COOKIE_SIZE];
	control("reading the session cookie", read_exact(ctrl, &mut cookie)).await?;
	control(
		"sending PARAM_EXCHANGE",
		write_state(ctrl, TestState::ParamExchange),
	)
	.await?;
	let params: TestParams =
		control("reading the test parameters", read_json(ctrl, MAX_JSON_LEN)).await?;
	params.validate()?;
	Ok((cookie, params))
}

/// Accepts one connection and rejects a datagram test on a stream transport.
pub async fn serve_stream_once<S, F, Fut>(mut accept: F) -> io::Result<(TestParams, Report)>
where
	S: StreamIo,
	F: FnMut() -> Fut,
	Fut: Future<Output = io::Result<S>>,
{
	let mut ctrl = control("accepting the control connection", accept()).await?;
	let (cookie, params) = read_params(&mut ctrl).await?;
	if params.is_udp() {
		return Err(io::Error::new(
			io::ErrorKind::Unsupported,
			"UDP requires a datagram transport",
		));
	}
	let report = serve_stream_session(&mut ctrl, &cookie, &params, &mut accept).await?;
	Ok((params, report))
}

/// Serves one stream test whose control connection already presented
/// `cookie`, and whose data connections come from `accept`.
///
/// A listener that accepts many connections at once reads every connection's
/// cookie itself and routes it: this is the entry point for the control
/// connections it does not recognise as data.
pub async fn serve_stream_control<S, F, Fut>(
	mut ctrl: S,
	cookie: [u8; COOKIE_SIZE],
	mut accept: F,
) -> io::Result<(TestParams, Report)>
where
	S: StreamIo,
	F: FnMut() -> Fut,
	Fut: Future<Output = io::Result<S>>,
{
	control(
		"sending PARAM_EXCHANGE",
		write_state(&mut ctrl, TestState::ParamExchange),
	)
	.await?;
	let params: TestParams = control(
		"reading the test parameters",
		read_json(&mut ctrl, MAX_JSON_LEN),
	)
	.await?;
	params.validate()?;
	if params.is_udp() {
		return Err(io::Error::new(
			io::ErrorKind::Unsupported,
			"UDP requires a datagram transport",
		));
	}
	let report = serve_stream_session(&mut ctrl, &cookie, &params, &mut accept).await?;
	Ok((params, report))
}

/// Active sessions waiting for their client to open data streams, keyed by
/// the 37-byte session cookie.
type Routes = Rc<RefCell<HashMap<[u8; COOKIE_SIZE], Rc<DataQueue>>>>;

/// Replays the cookie consumed while routing a data connection. Control
/// connections have an empty prelude because [`serve_stream_control`] already
/// takes their cookie as an argument.
struct Prelude {
	cookie: Vec<u8>,
	offset: usize,
	stream: SocketStream,
}

impl Prelude {
	fn new(stream: SocketStream, cookie: Vec<u8>) -> Self {
		Self {
			cookie,
			offset: 0,
			stream,
		}
	}
}

impl StreamIo for Prelude {
	async fn read_into(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		if self.offset < self.cookie.len() {
			let take = (self.cookie.len() - self.offset).min(buf.len());
			buf[..take].copy_from_slice(&self.cookie[self.offset..self.offset + take]);
			self.offset += take;
			return Ok(take);
		}
		self.stream.read_into(buf).await
	}

	async fn write_all_bytes(&mut self, buf: &[u8]) -> io::Result<()> {
		self.stream.write_all_bytes(buf).await
	}

	async fn shutdown_write(&mut self) -> io::Result<()> {
		self.stream.shutdown_write().await
	}
}

struct DataQueue {
	sockets: RefCell<VecDeque<Prelude>>,
	event: Event,
}

impl DataQueue {
	fn new() -> Self {
		Self {
			sockets: RefCell::new(VecDeque::new()),
			event: Event::new(),
		}
	}

	fn push(&self, socket: Prelude) {
		self.sockets.borrow_mut().push_back(socket);
		self.event.notify(usize::MAX);
	}

	async fn pop(&self) -> io::Result<Prelude> {
		loop {
			let listener = self.event.listen();
			if let Some(socket) = self.sockets.borrow_mut().pop_front() {
				return Ok(socket);
			}
			listener.await;
		}
	}
}

/// Serves concurrent stream sessions on `listener`, routing each accepted
/// connection by its 37-byte cookie so one active or stalled session does not
/// block another from handshaking or transferring.
pub async fn serve_stream_listener<F>(listener: &Listener, on_session: F) -> io::Result<()>
where
	F: Fn(TestParams, Report) + 'static,
{
	let routes: Routes = Rc::new(RefCell::new(HashMap::new()));
	let on_session = Rc::new(on_session);
	loop {
		let socket = listener.accept().await.map_err(to_io)?;
		let routes = Rc::clone(&routes);
		let on_session = Rc::clone(&on_session);
		drop(completion::spawn(async move {
			let mut ctrl = SocketStream::new(socket);
			let mut cookie = [0u8; COOKIE_SIZE];
			if let Err(error) = control(
				"reading the session cookie",
				read_exact(&mut ctrl, &mut cookie),
			)
			.await
			{
				log::debug!("wiperf: {error}");
				return;
			}
			if let Some(queue) = routes.borrow().get(&cookie).cloned() {
				queue.push(Prelude::new(ctrl, cookie.to_vec()));
				return;
			}
			let queue = Rc::new(DataQueue::new());
			routes.borrow_mut().insert(cookie, Rc::clone(&queue));
			let accept = {
				let queue = Rc::clone(&queue);
				move || {
					let queue = Rc::clone(&queue);
					async move { queue.pop().await }
				}
			};
			let ctrl = Prelude::new(ctrl, Vec::new());
			match serve_stream_control(ctrl, cookie, accept).await {
				Ok((params, report)) => on_session(params, report),
				Err(error) => log::debug!("wiperf: session ended: {error}"),
			}
			routes.borrow_mut().remove(&cookie);
		}));
	}
}

/// Serves one stream test after its parameters were read.
#[expect(
	clippy::redundant_pub_crate,
	reason = "keep this helper crate-internal without triggering unreachable_pub"
)]
pub(crate) async fn serve_stream_session<S, F, Fut>(
	ctrl: &mut S,
	cookie: &[u8; COOKIE_SIZE],
	params: &TestParams,
	mut accept: F,
) -> io::Result<Report>
where
	S: StreamIo,
	F: FnMut() -> Fut,
	Fut: Future<Output = io::Result<S>>,
{
	control(
		"sending CREATE_STREAMS",
		write_state(ctrl, TestState::CreateStreams),
	)
	.await?;
	let stream_count = params.streams();
	let mut data_streams = Vec::with_capacity(stream_count as usize);
	while data_streams.len() < stream_count as usize {
		let mut stream = control("accepting a data stream", accept()).await?;
		let mut stream_cookie = [0u8; COOKIE_SIZE];
		match control(
			"reading a data-stream cookie",
			read_exact(&mut stream, &mut stream_cookie),
		)
		.await
		{
			Ok(()) if stream_cookie == *cookie => data_streams.push(stream),
			Ok(()) => {
				if let Err(error) = write_state(&mut stream, TestState::AccessDenied).await {
					log::debug!("wiperf: denying a stray stream: {error}");
				}
				log::debug!("wiperf: a data stream presented the wrong cookie");
			}
			Err(error) => log::debug!("wiperf: a data stream never identified itself: {error}"),
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
	let blksize = params.blksize();
	let reverse = params.is_reverse();
	let stop = Stop::new();

	let tasks: Vec<_> = data_streams
		.into_iter()
		.enumerate()
		.map(|(index, mut stream)| {
			let stop = stop.clone();
			completion::spawn(async move {
				let counters = if reverse {
					blast_stream(&mut stream, blksize, window, &stop).await?
				} else {
					absorb_stream(&mut stream, RECEIVE_BLOCK, window, &stop).await?
				};
				Ok::<(u16, Counters), io::Error>((index as u16, counters))
			})
		})
		.collect();

	// The client sends TEST_END when its own window closes. A client that
	// vanishes instead fails this read, which then cancels and joins the data
	// tasks rather than leaving them attached to the executor.
	let wait = Duration::from_secs(u64::from(params.seconds())) + CONTROL_TIMEOUT;
	let end = control_for("waiting for TEST_END", wait, async {
		loop {
			match read_state(ctrl).await? {
				TestState::TestEnd | TestState::ClientTerminate => return Ok(()),
				_ => continue,
			}
		}
	})
	.await;
	// A receiver keeps reading for its drain grace so bytes already in flight
	// are counted; only a vanished client needs its tasks woken early.
	if end.is_err() || reverse {
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
		sender_has_retransmits: if reverse { -1 } else { 0 },
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

	let report = build_report(params, false, &local_results, &remote_results);
	match (end, first_error) {
		(Ok(()), None) => Ok(report),
		(Err(error), _) => Err(error),
		(Ok(()), Some(error)) => Err(error),
	}
}

/// Runs an iperf3 stream client over any async stream connector `connect`.
///
/// `connect` is invoked once for the control connection and `params.streams()`
/// times during `CREATE_STREAMS`.
pub async fn run_stream_client<S, F, Fut>(params: &TestParams, mut connect: F) -> io::Result<Report>
where
	S: StreamIo,
	F: FnMut() -> Fut,
	Fut: Future<Output = io::Result<S>>,
{
	params.validate()?;
	if params.is_udp() {
		return Err(io::Error::new(
			io::ErrorKind::Unsupported,
			"UDP requires a datagram transport",
		));
	}
	let cookie = crate::protocol::make_cookie();
	let mut ctrl = control("connecting the control channel", connect()).await?;
	control("sending the session cookie", ctrl.write_all_bytes(&cookie)).await?;

	let state = control("waiting for PARAM_EXCHANGE", read_state(&mut ctrl)).await?;
	if state != TestState::ParamExchange {
		return Err(io::Error::new(
			io::ErrorKind::InvalidData,
			format!("expected ParamExchange, got {state:?}"),
		));
	}
	let mut wire_params = params.clone();
	wire_params.tcp = Some(true);
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

	let stream_count = wire_params.streams();
	let mut data_streams = Vec::with_capacity(stream_count as usize);
	for _ in 0..stream_count {
		let mut stream = control("connecting a data stream", connect()).await?;
		control(
			"identifying the data stream",
			stream.write_all_bytes(&cookie),
		)
		.await?;
		data_streams.push(stream);
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
	let blksize = wire_params.blksize();
	let reverse = wire_params.is_reverse();
	let stop = Stop::new();

	let tasks: Vec<_> = data_streams
		.into_iter()
		.enumerate()
		.map(|(index, mut stream)| {
			let stop = stop.clone();
			completion::spawn(async move {
				let counters = if reverse {
					absorb_stream(&mut stream, RECEIVE_BLOCK, window, &stop).await?
				} else {
					blast_stream(&mut stream, blksize, window, &stop).await?
				};
				Ok::<(u16, Counters), io::Error>((index as u16, counters))
			})
		})
		.collect();

	// Both directions run for the full `time`; the data loops stop themselves
	// at the window's deadline.
	let window_result = control_for(
		"running the test window",
		Duration::from_secs(u64::from(wire_params.seconds())) + CONTROL_TIMEOUT,
		async {
			timeout(Duration::from_secs(u64::from(wire_params.seconds())))
				.await
				.map_err(to_io)
		},
	)
	.await;
	// Drain after the measurement only to let the peer finish without writing
	// into a closed socket. These late bytes are excluded from throughput;
	// sender and receiver totals can differ due to buffering and window skew.
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
		sender_has_retransmits: if reverse { 0 } else { -1 },
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

	let state = control("waiting for DISPLAY_RESULTS", read_state(&mut ctrl)).await?;
	if state != TestState::DisplayResults {
		return Err(io::Error::new(
			io::ErrorKind::InvalidData,
			format!("expected DisplayResults, got {state:?}"),
		));
	}
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
