//! Deterministic accounting for the measured part of a test.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::protocol::{Counters, DatagramHeader};

/// The measured window of one test: the leading `omit` seconds of the total
/// duration are run but not counted, exactly as iperf3's `-O` does.
#[derive(Clone, Copy, Debug)]
pub struct Window {
	/// First instant whose bytes count.
	pub measure_from: Instant,
	/// Last instant whose bytes count.
	pub deadline: Instant,
}

impl Window {
	/// Starts a test now: `seconds` of total duration, of which the first
	/// `omit` seconds are warm-up.
	pub fn start(seconds: u32, omit: u32) -> Self {
		let start = Instant::now();
		let omit = Duration::from_secs(u64::from(omit));
		Self {
			measure_from: start + omit,
			deadline: start + Duration::from_secs(u64::from(seconds)),
		}
	}

	/// The window's length in seconds, never below one so a summary divides by
	/// something.
	pub fn measured_seconds(&self) -> f64 {
		self.deadline
			.saturating_duration_since(self.measure_from)
			.as_secs_f64()
			.max(1.0)
	}

	fn counting(&self, now: Instant) -> bool {
		now >= self.measure_from && now <= self.deadline
	}
}

/// Accumulates stream or datagram counters over a [`Window`].
///
/// Bytes are only recorded while the window is measuring; `millis` is the
/// measured time that actually elapsed, so a report never divides by a window
/// the transfer did not fill.
pub struct Meter {
	window: Window,
	counters: Counters,
	first_seq: Option<u64>,
	last_seq: u64,
	last_transit_ns: Option<i128>,
	jitter_ns: f64,
}

impl Meter {
	pub fn new(window: Window) -> Self {
		Self {
			window,
			counters: Counters::default(),
			first_seq: None,
			last_seq: 0,
			last_transit_ns: None,
			jitter_ns: 0.0,
		}
	}

	/// Bytes counted so far, for a paced sender's schedule.
	pub fn counted_bytes(&self) -> u64 {
		self.counters.bytes
	}

	pub fn record_stream(&mut self, now: Instant, bytes: u64) {
		if !self.window.counting(now) {
			return;
		}
		self.counters.bytes += bytes;
		self.counters.packets += 1;
	}

	pub fn record_datagram(&mut self, now: Instant, header: &DatagramHeader, bytes: u64) {
		if !self.window.counting(now) {
			return;
		}
		self.counters.bytes += bytes;
		self.counters.packets += 1;
		if self.first_seq.is_none() {
			self.first_seq = Some(header.seq);
		}
		self.last_seq = self.last_seq.max(header.seq);

		let now_ns = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or_default()
			.as_nanos() as i128;
		let transit = now_ns - header.sent_ns as i128;
		if let Some(last) = self.last_transit_ns {
			let delta = (transit - last).unsigned_abs() as f64;
			self.jitter_ns += (delta - self.jitter_ns) / 16.0;
		}
		self.last_transit_ns = Some(transit);
	}

	/// Finishes the meter at `now`, counting only time inside the window.
	pub fn finish(mut self, now: Instant) -> Counters {
		let end = now.min(self.window.deadline);
		self.counters.millis = end
			.saturating_duration_since(self.window.measure_from)
			.as_millis() as u64;
		if let Some(first) = self.first_seq {
			let expected = self.last_seq.saturating_sub(first) + 1;
			self.counters.lost = expected.saturating_sub(self.counters.packets);
		}
		self.counters.jitter_us = (self.jitter_ns / 1000.0).round().max(0.0) as u64;
		self.counters
	}
}

#[cfg(test)]
mod tests {
	use std::time::{Duration, Instant};

	use super::{Meter, Window};

	#[test]
	fn omit_is_part_of_the_duration() {
		let window = Window::start(10, 2);
		assert!((window.measured_seconds() - 8.0).abs() < 1e-9);
		// start() is "now", and the deadline is the full duration from it.
		let full = window
			.deadline
			.saturating_duration_since(window.deadline - Duration::from_secs(10));
		assert_eq!(full, Duration::from_secs(10));
	}

	#[test]
	fn warm_up_bytes_are_not_counted() {
		let base = Instant::now();
		let window = Window {
			measure_from: base + Duration::from_secs(1),
			deadline: base + Duration::from_secs(3),
		};
		let mut meter = Meter::new(window);
		meter.record_stream(base, 100);
		meter.record_stream(window.measure_from, 200);
		meter.record_stream(window.deadline + Duration::from_secs(1), 400);
		let counters = meter.finish(window.deadline);
		assert_eq!(counters.bytes, 200);
		assert_eq!(counters.packets, 1);
		assert_eq!(counters.millis, 2000);
	}
}
