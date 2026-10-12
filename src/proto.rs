//! Wire protocol (compatible with the C svc, plus an rc trailer).
//!
//! Request: one line, `argv[1..]` joined by spaces; space, backslash and
//! newline inside an argument are escaped with a backslash.
//!
//! Response: raw text, dot-stuffed, terminated by a line `.`; then (new) a
//! line `rc N`. Old clients stop at `.`; a new client talking to an old daemon
//! sees EOF instead of `rc N` and assumes 0.
//!
//! Stuffing (fixes the C code, which corrupted lines made only of dots): a
//! line that consists only of N >= 1 dots is sent with N + 1 dots. The
//! receiver strips one dot from lines of >= 2 dots only; a lone `.` is the
//! terminator.

pub const END: &[u8] = b".\n";

pub fn encode_args<S: AsRef<str>>(args: &[S]) -> String {
	let mut out = String::new();
	for (i, a) in args.iter().enumerate() {
		if i > 0 {
			out.push(' ');
		}
		for c in a.as_ref().chars() {
			if matches!(c, ' ' | '\\' | '\n') {
				out.push('\\');
			}
			out.push(c);
		}
	}
	out
}

/// Inverse of [`encode_args`]. The trailing newline must already be removed.
pub fn decode_args(line: &str) -> Vec<String> {
	let mut args = vec![String::new()];
	let mut esc = false;
	for c in line.chars() {
		if esc {
			args.last_mut().unwrap().push(c);
			esc = false;
		} else if c == '\\' {
			esc = true;
		} else if c == ' ' {
			args.push(String::new());
		} else {
			args.last_mut().unwrap().push(c);
		}
	}
	if line.is_empty() {
		args.clear();
	}
	args
}

/// Streaming dot-stuffer; state survives chunk boundaries.
#[derive(Default)]
pub struct Escaper {
	/// dots seen at the start of the current line, not yet emitted
	pending: usize,
	mid_line: bool,
}

impl Escaper {
	pub fn push(&mut self, chunk: &[u8], out: &mut Vec<u8>) {
		for &b in chunk {
			match b {
				b'\n' => {
					if self.pending > 0 {
						out.extend(std::iter::repeat_n(b'.', self.pending + 1));
					}
					out.push(b'\n');
					self.pending = 0;
					self.mid_line = false;
				}
				b'.' if !self.mid_line => self.pending += 1,
				_ => {
					out.extend(std::iter::repeat_n(b'.', self.pending));
					self.pending = 0;
					self.mid_line = true;
					out.push(b);
				}
			}
		}
	}

	/// End of data: make sure the last line is terminated.
	pub fn finish(&mut self, out: &mut Vec<u8>) {
		if self.pending > 0 || self.mid_line {
			self.push(b"\n", out);
		}
	}
}

/// What a received line means.
#[derive(Debug, PartialEq, Eq)]
pub enum Line<'a> {
	End,
	Data(std::borrow::Cow<'a, [u8]>),
}

/// Classify one received line (without its `\n`) and undo the stuffing.
pub fn unstuff(line: &[u8]) -> Line<'_> {
	if line == b"." {
		Line::End
	} else if line.len() >= 2 && line.iter().all(|&c| c == b'.') {
		Line::Data(std::borrow::Cow::Borrowed(&line[1..]))
	} else {
		Line::Data(std::borrow::Cow::Borrowed(line))
	}
}

/// Parse the optional trailer line (`rc N`).
pub fn parse_rc(line: &str) -> Option<i32> {
	line.trim_end().strip_prefix("rc ")?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn args_roundtrip() {
		let cases: Vec<Vec<&str>> = vec![
			vec!["status", "web"],
			vec!["init", "a b", "back\\slash", "new\nline", "", "x"],
			vec!["-r", "5", "init", "l", "sh", "-c", "echo  hi"],
		];
		for c in cases {
			let enc = encode_args(&c);
			assert!(!enc.contains('\n') || enc.contains("\\\n"));
			let dec = decode_args(&enc);
			assert_eq!(dec, c, "enc={enc:?}");
		}
		assert!(decode_args("").is_empty());
	}

	fn stuff(chunks: &[&[u8]]) -> Vec<u8> {
		let mut e = Escaper::default();
		let mut out = Vec::new();
		for c in chunks {
			e.push(c, &mut out);
		}
		e.finish(&mut out);
		out
	}

	fn unstuff_all(data: &[u8]) -> Vec<u8> {
		let mut out = Vec::new();
		for l in data.split_inclusive(|&b| b == b'\n') {
			let l = l.strip_suffix(b"\n").unwrap_or(l);
			match unstuff(l) {
				Line::End => panic!("early end"),
				Line::Data(d) => {
					out.extend_from_slice(&d);
					out.push(b'\n');
				}
			}
		}
		out
	}

	#[test]
	fn stuffing_basic() {
		assert_eq!(stuff(&[b".\n"]), b"..\n");
		assert_eq!(stuff(&[b"..\n"]), b"...\n");
		assert_eq!(stuff(&[b".foo\n"]), b".foo\n");
		assert_eq!(stuff(&[b"a.\n"]), b"a.\n");
		assert_eq!(stuff(&[b"abc"]), b"abc\n");
		assert_eq!(stuff(&[b"."]), b"..\n");
		assert_eq!(stuff(&[b""]), b"");
	}

	#[test]
	fn chunk_boundaries_do_not_matter() {
		let data: &[u8] = b"x\n.\n..\n...\n.a\n..b\na.\n\n.\n";
		let whole = stuff(&[data]);
		for split in 0..=data.len() {
			let (a, b) = data.split_at(split);
			assert_eq!(stuff(&[a, b]), whole, "split at {split}");
		}
		// bytewise
		let bytes: Vec<&[u8]> = data.chunks(1).collect();
		assert_eq!(stuff(&bytes), whole);
		// never produces a lone "." line and round-trips
		assert!(!whole.split(|&b| b == b'\n').any(|l| l == b"."));
		assert_eq!(unstuff_all(&whole), data);
	}

	#[test]
	fn terminator_and_rc() {
		assert_eq!(unstuff(b"."), Line::End);
		assert_eq!(parse_rc("rc 2\n"), Some(2));
		assert_eq!(parse_rc("garbage"), None);
	}
}
