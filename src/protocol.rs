//! iperf3 wire format: the session cookie, the control-channel state bytes,
//! the length-prefixed JSON frames, and the 64-bit UDP datagram header.
//!
//! This module is transport independent: it only names the bytes both peers
//! exchange, not how they reach each other.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::stream::{StreamIo, read_exact};

/// Size of the iperf3 authentication cookie on the wire (36 chars + NUL).
pub const COOKIE_SIZE: usize = 37;

/// Base32-like alphabet used by iperf3's `make_cookie()`.
const COOKIE_CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Maximum JSON payload length accepted on the control channel (64 KiB).
pub const MAX_JSON_LEN: usize = 64 * 1024;

/// Default bytes per write for stream tests (128 KiB, matching iperf3).
pub const DEFAULT_TCP_BLKSIZE: u32 = 128 * 1024;

/// Default bytes per datagram for UDP tests (1460 B).
pub const DEFAULT_UDP_BLKSIZE: u32 = 1460;

/// Default iperf3 TCP/UDP port.
pub const DEFAULT_PORT: u16 = 5201;

/// UDP handshake magic sent by the client to open a UDP stream (`"6789"`).
pub const UDP_CONNECT_MSG: u32 = 0x3637_3839;

/// UDP handshake reply sent by the server (`"9876"`).
pub const UDP_CONNECT_REPLY: u32 = 0x3938_3736;

/// Legacy iperf3 UDP connect reply constant accepted for interoperability.
#[expect(
	clippy::redundant_pub_crate,
	reason = "keep this helper crate-internal without triggering unreachable_pub"
)]
pub(crate) const UDP_CONNECT_REPLY_LEGACY: u32 = 0xb168_de3a;

/// Bytes in the 64-bit iperf3 UDP datagram header: `[sec: u32][usec: u32][seq: u64]`.
pub const DATAGRAM_HEADER: usize = 16;

/// Convert a [`completion::Error`] into [`io::Error`].
pub fn to_io(error: completion::Error) -> io::Error {
	io::Error::try_from(error).unwrap_or_else(io::Error::other)
}

/// Generates a random 37-byte iperf3 cookie.
pub fn make_cookie() -> [u8; COOKIE_SIZE] {
	let mut random = [0u8; COOKIE_SIZE - 1];
	getrandom::fill(&mut random).expect("OS randomness unavailable");
	let mut cookie = [0u8; COOKIE_SIZE];
	for (dst, &byte) in cookie[..COOKIE_SIZE - 1].iter_mut().zip(&random) {
		*dst = COOKIE_CHARSET[(byte as usize) % COOKIE_CHARSET.len()];
	}
	cookie[COOKIE_SIZE - 1] = 0;
	cookie
}

/// iperf3 control-channel state byte (`iperf_api.h`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestState {
	TestStart,
	TestRunning,
	TestEnd,
	ParamExchange,
	CreateStreams,
	ServerTerminate,
	ClientTerminate,
	ExchangeResults,
	DisplayResults,
	IperfStart,
	IperfDone,
	AccessDenied,
	ServerError,
}

impl TestState {
	pub const fn to_wire(self) -> i8 {
		match self {
			Self::TestStart => 1,
			Self::TestRunning => 2,
			Self::TestEnd => 4,
			Self::ParamExchange => 9,
			Self::CreateStreams => 10,
			Self::ServerTerminate => 11,
			Self::ClientTerminate => 12,
			Self::ExchangeResults => 13,
			Self::DisplayResults => 14,
			Self::IperfStart => 15,
			Self::IperfDone => 16,
			Self::AccessDenied => -1,
			Self::ServerError => -2,
		}
	}

	pub fn from_wire(byte: i8) -> io::Result<Self> {
		match byte {
			1 => Ok(Self::TestStart),
			2 => Ok(Self::TestRunning),
			4 => Ok(Self::TestEnd),
			9 => Ok(Self::ParamExchange),
			10 => Ok(Self::CreateStreams),
			11 => Ok(Self::ServerTerminate),
			12 => Ok(Self::ClientTerminate),
			13 => Ok(Self::ExchangeResults),
			14 => Ok(Self::DisplayResults),
			15 => Ok(Self::IperfStart),
			16 => Ok(Self::IperfDone),
			-1 => Ok(Self::AccessDenied),
			-2 => Ok(Self::ServerError),
			other => Err(io::Error::new(
				io::ErrorKind::InvalidData,
				format!("unknown iperf3 state byte {other}"),
			)),
		}
	}
}

fn is_false_opt(value: &Option<bool>) -> bool {
	matches!(value, None | Some(false))
}

/// Parameters exchanged during `PARAM_EXCHANGE` in iperf3 JSON wire format.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestParams {
	#[serde(skip_serializing_if = "is_false_opt", default)]
	pub tcp: Option<bool>,
	#[serde(skip_serializing_if = "is_false_opt", default)]
	pub udp: Option<bool>,
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub omit: Option<u32>,
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub time: Option<u32>,
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub parallel: Option<u16>,
	#[serde(skip_serializing_if = "is_false_opt", default)]
	pub reverse: Option<bool>,
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub len: Option<u32>,
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub bandwidth: Option<u64>,
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub udp_counters_64bit: Option<i32>,
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub client_version: Option<String>,
}

impl TestParams {
	/// Validate the subset implemented by wiperf before opening data streams.
	pub fn validate(&self) -> io::Result<()> {
		let invalid = |message| io::Error::new(io::ErrorKind::InvalidInput, message);
		if self.tcp == Some(true) && self.udp == Some(true) {
			return Err(invalid("tcp and udp are mutually exclusive"));
		}
		if self.parallel == Some(0) || self.streams() > 128 {
			return Err(invalid("parallel must be in 1..=128"));
		}
		if self.seconds() == 0 || self.seconds() > 86400 {
			return Err(invalid("time must be in 1..=86400 seconds"));
		}
		if self.omit_seconds() >= self.seconds() {
			return Err(invalid("omit must be smaller than time"));
		}
		if self.len.is_some_and(|len| len == 0 || len > 1024 * 1024) {
			return Err(invalid("len must be in 1..=1048576 bytes"));
		}
		if self.is_udp() && (self.blksize() > 65507 || self.udp_counters_64bit != Some(1)) {
			return Err(invalid(
				"UDP requires 64-bit counters and a payload of at most 65507 bytes",
			));
		}
		Ok(())
	}

	pub fn is_udp(&self) -> bool {
		self.udp.unwrap_or(false)
	}

	pub fn is_reverse(&self) -> bool {
		self.reverse.unwrap_or(false)
	}

	pub fn streams(&self) -> u16 {
		self.parallel.unwrap_or(1).max(1)
	}

	/// Total test duration, warm-up included.
	pub fn seconds(&self) -> u32 {
		self.time.unwrap_or(10)
	}

	/// Leading part of [`TestParams::seconds`] that is not measured.
	pub fn omit_seconds(&self) -> u32 {
		self.omit.unwrap_or(0)
	}

	/// The window a report covers: `time - omit`. The omission is part of
	/// `time`, not added to it, so a 10 s test with a 2 s omit reports 8 s.
	pub fn measured_seconds(&self) -> f64 {
		f64::from(self.seconds().saturating_sub(self.omit_seconds())).max(1.0)
	}

	pub fn blksize(&self) -> usize {
		let default = if self.is_udp() {
			DEFAULT_UDP_BLKSIZE
		} else {
			DEFAULT_TCP_BLKSIZE
		};
		let raw = self.len.unwrap_or(default);
		let size = if raw == 0 { default } else { raw } as usize;
		if self.is_udp() {
			size.max(DATAGRAM_HEADER + 1)
		} else {
			size.max(1)
		}
	}
}

fn de_retransmit_sentinel<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
	D: serde::Deserializer<'de>,
{
	struct Visitor;
	impl serde::de::Visitor<'_> for Visitor {
		type Value = i64;
		fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
			f.write_str("an i64 or u64::MAX sentinel")
		}
		fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<i64, E> {
			Ok(value)
		}
		fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<i64, E> {
			Ok(if value > i64::MAX as u64 {
				-1
			} else {
				value as i64
			})
		}
	}
	deserializer.deserialize_any(Visitor)
}

fn default_retransmits() -> i64 {
	-1
}

/// Per-stream entry inside [`TestResultsJson`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StreamResultJson {
	pub id: i32,
	pub bytes: u64,
	#[serde(
		default = "default_retransmits",
		deserialize_with = "de_retransmit_sentinel"
	)]
	pub retransmits: i64,
	#[serde(default)]
	pub jitter: f64,
	#[serde(default)]
	pub errors: u64,
	#[serde(default)]
	pub omitted_errors: u64,
	#[serde(default)]
	pub packets: u64,
	#[serde(default)]
	pub omitted_packets: u64,
	#[serde(default)]
	pub start_time: f64,
	#[serde(default)]
	pub end_time: f64,
}

/// Results payload exchanged in `EXCHANGE_RESULTS` on the control channel.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TestResultsJson {
	#[serde(default)]
	pub cpu_util_total: f64,
	#[serde(default)]
	pub cpu_util_user: f64,
	#[serde(default)]
	pub cpu_util_system: f64,
	#[serde(
		default = "default_retransmits",
		deserialize_with = "de_retransmit_sentinel"
	)]
	pub sender_has_retransmits: i64,
	#[serde(default)]
	pub streams: Vec<StreamResultJson>,
}

/// Assigns stream IDs matching iperf3's `iperf_add_stream` (`1, 3, 4, 5, ...`).
pub const fn next_stream_id(existing_index: u16) -> i32 {
	if existing_index == 0 {
		1
	} else {
		(existing_index as i32) + 2
	}
}

/// Counters measured on one side of a single stream.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Counters {
	pub bytes: u64,
	pub packets: u64,
	pub lost: u64,
	pub jitter_us: u64,
	pub millis: u64,
}

impl Counters {
	pub fn bits_per_second(&self, seconds: f64) -> f64 {
		self.bytes as f64 * 8.0 / seconds.max(1e-6)
	}

	pub fn to_wire(&self, id: i32) -> StreamResultJson {
		let end_time = self.millis as f64 / 1000.0;
		StreamResultJson {
			id,
			bytes: self.bytes,
			retransmits: -1,
			jitter: self.jitter_us as f64 / 1_000_000.0,
			errors: self.lost,
			omitted_errors: 0,
			packets: self.packets,
			omitted_packets: 0,
			start_time: 0.0,
			end_time,
		}
	}

	pub fn from_wire(wire: &StreamResultJson) -> Self {
		let secs = (wire.end_time - wire.start_time).max(0.0);
		Self {
			bytes: wire.bytes,
			packets: wire.packets,
			lost: wire.errors,
			jitter_us: (wire.jitter * 1_000_000.0).round().max(0.0) as u64,
			millis: (secs * 1000.0).round().max(0.0) as u64,
		}
	}
}

/// Combined sender and receiver counters for one stream.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StreamReport {
	pub index: u16,
	pub sender: Option<Counters>,
	pub receiver: Option<Counters>,
}

/// Complete report for one benchmark run.
#[derive(Clone, Debug, Default)]
pub struct Report {
	pub streams: Vec<StreamReport>,
	pub seconds: f64,
}

/// Decoded iperf3 64-bit UDP datagram header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatagramHeader {
	pub seq: u64,
	pub sent_ns: u128,
}

/// Encodes `[sec: u32 BE][usec: u32 BE][seq: u64 BE]` at the front of `datagram`.
pub fn encode_datagram(datagram: &mut [u8], seq: u64) {
	let now = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or_default();
	datagram[0..4].copy_from_slice(&(now.as_secs() as u32).to_be_bytes());
	datagram[4..8].copy_from_slice(&now.subsec_micros().to_be_bytes());
	datagram[8..16].copy_from_slice(&seq.to_be_bytes());
}

/// Decodes the 16-byte iperf3 UDP datagram header.
pub fn decode_datagram(datagram: &[u8]) -> io::Result<DatagramHeader> {
	if datagram.len() < DATAGRAM_HEADER {
		return Err(io::Error::new(
			io::ErrorKind::InvalidData,
			"datagram shorter than 16-byte header",
		));
	}
	let sec = u64::from(u32::from_be_bytes(datagram[0..4].try_into().unwrap()));
	let usec = u64::from(u32::from_be_bytes(datagram[4..8].try_into().unwrap()));
	let seq = u64::from_be_bytes(datagram[8..16].try_into().unwrap());
	Ok(DatagramHeader {
		seq,
		sent_ns: u128::from(sec) * 1_000_000_000 + u128::from(usec) * 1_000,
	})
}

/// Writes one signed iperf3 state byte to `stream`.
pub async fn write_state<S: StreamIo>(stream: &mut S, state: TestState) -> io::Result<()> {
	stream.write_all_bytes(&[state.to_wire() as u8]).await
}

/// Reads one signed iperf3 state byte from `stream`.
pub async fn read_state<S: StreamIo>(stream: &mut S) -> io::Result<TestState> {
	let mut byte = [0u8; 1];
	read_exact(stream, &mut byte).await?;
	TestState::from_wire(byte[0] as i8)
}

/// Writes a 4-byte BE length-prefixed JSON frame to `stream`.
pub async fn write_json<S: StreamIo, T: Serialize>(stream: &mut S, value: &T) -> io::Result<()> {
	let body =
		serde_json::to_vec(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
	let len = u32::try_from(body.len())
		.map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "JSON frame exceeds u32"))?;
	stream.write_all_bytes(&len.to_be_bytes()).await?;
	stream.write_all_bytes(&body).await
}

/// Reads a 4-byte BE length-prefixed JSON frame from `stream`.
pub async fn read_json<S: StreamIo, T: DeserializeOwned>(
	stream: &mut S,
	max_len: usize,
) -> io::Result<T> {
	let mut head = [0u8; 4];
	read_exact(stream, &mut head).await?;
	let len = u32::from_be_bytes(head) as usize;
	if len == 0 || (max_len > 0 && len > max_len) {
		return Err(io::Error::new(
			io::ErrorKind::InvalidData,
			format!("invalid iperf3 JSON length {len} (max {max_len})"),
		));
	}
	let mut body = vec![0u8; len];
	read_exact(stream, &mut body).await?;
	serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests;
