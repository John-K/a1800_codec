/// Bitstream reader for A1800 encoded frames.
///
/// Reads bits MSB-first from a sequence of 16-bit words,
/// matching the original DLL's `read_bit` function at 0x10003820.

use crate::fixedpoint::{add, shl, shr, sub};

/// Bitstream reader state.
///
/// Mirrors the 6-field state struct used by the DLL:
///   [0] bits_remaining_in_word  (0..16)
///   [1] current_word
///   [2,3] pointer (replaced by slice + index)
///   [4] total_bits_remaining
///   [5] last_bit
pub struct BitstreamReader<'a> {
    data: &'a [i16],
    pos: usize,
    bits_remaining: i16,
    current_word: i16,
    pub total_bits_remaining: i16,
    pub last_bit: i16,
}

impl<'a> BitstreamReader<'a> {
    /// Create a new bitstream reader.
    ///
    /// `data` is the encoded frame data as 16-bit words.
    /// `total_bits` is the bit budget for this frame (bitrate / 50).
    pub fn new(data: &'a [i16], total_bits: i16) -> Self {
        BitstreamReader {
            data,
            pos: 0,
            bits_remaining: 0,
            current_word: 0,
            total_bits_remaining: total_bits,
            last_bit: 0,
        }
    }

    /// Read a single bit from the bitstream (MSB-first).
    ///
    /// The result is stored in `self.last_bit` (0 or 1).
    /// Matches `read_bit` / `FUN_10003820` exactly.
    pub fn read_bit(&mut self) {
        if self.bits_remaining == 0 {
            self.current_word = self.data[self.pos];
            self.pos += 1;
            self.bits_remaining = 16;
        }
        let new_remaining = sub(self.bits_remaining, 1);
        self.bits_remaining = new_remaining;
        let shifted = shr(self.current_word, new_remaining);
        self.last_bit = (shifted as u16 & 1) as i16;
    }

    /// Read `n` bits MSB-first and return as an i16.
    ///
    /// This matches the common pattern used in `decode_frame_params`:
    ///   value = 0; for n bits: read_bit(); value = add(shl(value, 1), last_bit);
    pub fn read_bits(&mut self, n: i32) -> i16 {
        let mut value: i16 = 0;
        for _ in 0..n {
            self.read_bit();
            value = add(shl(value, 1), self.last_bit);
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_single_bits() {
        // 0xA5C3 = 1010_0101_1100_0011 in binary
        let data = [0xA5C3u16 as i16];
        let mut bs = BitstreamReader::new(&data, 16);

        // Read all 16 bits MSB-first
        let expected = [1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1];
        for (i, &exp) in expected.iter().enumerate() {
            bs.read_bit();
            assert_eq!(bs.last_bit, exp, "bit {} mismatch", i);
        }
    }

    #[test]
    fn test_read_across_words() {
        // Two words: 0xFF00 = 1111_1111_0000_0000, 0x00FF = 0000_0000_1111_1111
        let data = [0xFF00u16 as i16, 0x00FFi16];
        let mut bs = BitstreamReader::new(&data, 32);

        // First 8 bits should be 1
        for i in 0..8 {
            bs.read_bit();
            assert_eq!(bs.last_bit, 1, "bit {} should be 1", i);
        }
        // Next 8 bits should be 0
        for i in 8..16 {
            bs.read_bit();
            assert_eq!(bs.last_bit, 0, "bit {} should be 0", i);
        }
        // Next 8 bits should be 0
        for i in 16..24 {
            bs.read_bit();
            assert_eq!(bs.last_bit, 0, "bit {} should be 0", i);
        }
        // Last 8 bits should be 1
        for i in 24..32 {
            bs.read_bit();
            assert_eq!(bs.last_bit, 1, "bit {} should be 1", i);
        }
    }

    #[test]
    fn test_read_bits_multi() {
        // 0xA5C3 = 1010_0101_1100_0011
        let data = [0xA5C3u16 as i16];
        let mut bs = BitstreamReader::new(&data, 16);

        // Read 4 bits: 1010 = 10
        let val = bs.read_bits(4);
        assert_eq!(val, 0b1010);

        // Read 4 bits: 0101 = 5
        let val = bs.read_bits(4);
        assert_eq!(val, 0b0101);

        // Read 5 bits: 11000 = 24
        let val = bs.read_bits(5);
        assert_eq!(val, 0b11000);

        // Read 3 bits: 011 = 3
        let val = bs.read_bits(3);
        assert_eq!(val, 0b011);
    }

    #[test]
    fn test_read_bits_5bit_value() {
        // The gain decoder reads a 5-bit initial index.
        // 0x7C00 = 0111_1100_0000_0000 → first 5 bits = 01111 = 15
        let data = [0x7C00u16 as i16];
        let mut bs = BitstreamReader::new(&data, 16);

        let val = bs.read_bits(5);
        assert_eq!(val, 15);
    }
}
