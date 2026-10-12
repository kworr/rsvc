//! In-memory log ring (last ~8 KiB of service output) with optional logfile.
//! Followers track an absolute offset; falling behind the ring is detected
//! and reported instead of blocking the writer.

use std::fs::File;
use std::io::Write;

use event_listener::Event;

pub const RING: usize = 8192;

pub struct Log {
	buf: Vec<u8>,
	/// absolute number of bytes ever pushed
	total: u64,
	sink: Option<File>,
	pub event: Event,
}

/// Result of reading from a position.
pub struct Chunk {
	pub data: Vec<u8>,
	pub next: u64,
	/// the reader was lapped; `data` starts at the oldest byte still held
	pub lost: bool,
}

impl Default for Log {
	fn default() -> Self {
		Self::new()
	}
}

impl Log {
	pub fn new() -> Self {
		Self { buf: vec![0; RING], total: 0, sink: None, event: Event::new() }
	}

	pub fn set_sink(&mut self, f: Option<File>) {
		self.sink = f;
	}

	pub fn push(&mut self, data: &[u8]) {
		if data.is_empty() {
			return;
		}
		if let Some(f) = &mut self.sink {
			let _ = f.write_all(data); // a broken logfile must not stop the service
		}
		for &b in data {
			let i = (self.total % RING as u64) as usize;
			self.buf[i] = b;
			self.total += 1;
		}
		self.event.notify(usize::MAX);
	}

	pub fn end(&self) -> u64 {
		self.total
	}

	pub fn start(&self) -> u64 {
		self.total.saturating_sub(RING as u64)
	}

	/// Everything from `pos` up to the current end.
	pub fn read_from(&self, pos: u64) -> Chunk {
		let (pos, lost) = if pos < self.start() { (self.start(), true) } else { (pos.min(self.total), false) };
		let data = (pos..self.total).map(|i| self.buf[(i % RING as u64) as usize]).collect();
		Chunk { data, next: self.total, lost }
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn ring_wraps_and_reports_loss() {
		let mut l = Log::new();
		l.push(b"hello\n");
		let c = l.read_from(0);
		assert_eq!(c.data, b"hello\n");
		assert!(!c.lost);
		let pos = c.next;
		l.push(&vec![b'x'; RING + 10]);
		let c = l.read_from(pos);
		assert!(c.lost);
		assert_eq!(c.data.len(), RING);
		assert_eq!(l.read_from(l.end()).data.len(), 0);
	}
}
