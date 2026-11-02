//! Byte fixtures for the implemented wire subset, independent of our peer.
use std::io;

use super::{
	DATAGRAM_HEADER, MAX_JSON_LEN, TestParams, TestState, UDP_CONNECT_MSG, UDP_CONNECT_REPLY,
	decode_datagram, encode_datagram, make_cookie, read_json, read_state, write_json, write_state,
};
use crate::stream::StreamIo;

#[derive(Default)]
struct MemoryStream(io::Cursor<Vec<u8>>);

impl StreamIo for MemoryStream {
	async fn read_into(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		io::Read::read(&mut self.0, buf)
	}
	async fn write_all_bytes(&mut self, buf: &[u8]) -> io::Result<()> {
		io::Write::write_all(&mut self.0, buf)
	}
	async fn shutdown_write(&mut self) -> io::Result<()> {
		Ok(())
	}
}

#[test]
fn cookie_and_state_bytes_match_wire_layout() {
	let cookie = make_cookie();
	assert_eq!(cookie.len(), 37);
	assert_eq!(cookie[36], 0);
	assert!(
		cookie[..36]
			.iter()
			.all(|byte| b"abcdefghijklmnopqrstuvwxyz234567".contains(byte))
	);
	for (state, byte) in [
		(TestState::TestStart, 1),
		(TestState::TestRunning, 2),
		(TestState::TestEnd, 4),
		(TestState::ParamExchange, 9),
		(TestState::CreateStreams, 10),
		(TestState::ServerTerminate, 11),
		(TestState::ClientTerminate, 12),
		(TestState::ExchangeResults, 13),
		(TestState::DisplayResults, 14),
		(TestState::IperfStart, 15),
		(TestState::IperfDone, 16),
		(TestState::AccessDenied, -1),
		(TestState::ServerError, -2),
	] {
		assert_eq!(state.to_wire(), byte);
		assert_eq!(TestState::from_wire(byte).unwrap(), state);
	}
}

#[test]
fn json_frame_uses_big_endian_length_and_signed_state() {
	completion::block_on(async {
		let mut stream = MemoryStream::default();
		write_state(&mut stream, TestState::AccessDenied)
			.await
			.unwrap();
		write_json(&mut stream, &serde_json::json!({"tcp": true}))
			.await
			.unwrap();
		assert_eq!(stream.0.get_ref(), b"\xff\x00\x00\x00\x0c{\"tcp\":true}");
		stream.0.set_position(0);
		assert_eq!(
			read_state(&mut stream).await.unwrap(),
			TestState::AccessDenied
		);
		let params: TestParams = read_json(&mut stream, MAX_JSON_LEN).await.unwrap();
		assert_eq!(params.tcp, Some(true));
	})
	.unwrap();
}

#[test]
fn datagram_header_has_timestamp_then_big_endian_64_bit_sequence() {
	let bytes = [0, 0, 0, 2, 0, 0, 0, 3, 1, 2, 3, 4, 5, 6, 7, 8];
	let header = decode_datagram(&bytes).unwrap();
	assert_eq!(header.sent_ns, 2_000_003_000);
	assert_eq!(header.seq, 0x0102030405060708);
	let mut encoded = [0; DATAGRAM_HEADER];
	encode_datagram(&mut encoded, header.seq);
	assert_eq!(&encoded[8..], &bytes[8..]);
	// Handshake words use native order, unlike the datagram header.
	assert_eq!(UDP_CONNECT_MSG, 0x36373839);
	assert_eq!(UDP_CONNECT_REPLY, 0x39383736);
}
