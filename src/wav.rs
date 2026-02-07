/// Simple mono 16-bit PCM WAV file writer.

use std::io::{self, Write};

/// Write a complete WAV file with mono 16-bit PCM samples.
pub fn write_wav<W: Write>(
    writer: &mut W,
    samples: &[i16],
    sample_rate: u32,
) -> io::Result<()> {
    let num_channels: u16 = 1;
    let bits_per_sample: u16 = 16;
    let byte_rate = sample_rate * (num_channels as u32) * (bits_per_sample as u32 / 8);
    let block_align = num_channels * (bits_per_sample / 8);
    let data_size = (samples.len() * 2) as u32;
    let riff_size = 36 + data_size;

    // RIFF header
    writer.write_all(b"RIFF")?;
    writer.write_all(&riff_size.to_le_bytes())?;
    writer.write_all(b"WAVE")?;

    // fmt sub-chunk
    writer.write_all(b"fmt ")?;
    writer.write_all(&16u32.to_le_bytes())?; // sub-chunk size
    writer.write_all(&1u16.to_le_bytes())?; // audio format (PCM)
    writer.write_all(&num_channels.to_le_bytes())?;
    writer.write_all(&sample_rate.to_le_bytes())?;
    writer.write_all(&byte_rate.to_le_bytes())?;
    writer.write_all(&block_align.to_le_bytes())?;
    writer.write_all(&bits_per_sample.to_le_bytes())?;

    // data sub-chunk
    writer.write_all(b"data")?;
    writer.write_all(&data_size.to_le_bytes())?;
    for &sample in samples {
        writer.write_all(&sample.to_le_bytes())?;
    }

    Ok(())
}

/// Streaming WAV writer that writes header first, then samples incrementally.
pub struct WavWriter<W: Write> {
    inner: W,
    sample_count: u32,
    sample_rate: u32,
}

impl<W: Write + io::Seek> WavWriter<W> {
    /// Create a new WAV writer. Writes the header immediately (with placeholder sizes).
    pub fn new(mut writer: W, sample_rate: u32) -> io::Result<Self> {
        // Write placeholder header (sizes will be patched on finish)
        let header = [0u8; 44];
        writer.write_all(&header)?;
        Ok(WavWriter {
            inner: writer,
            sample_count: 0,
            sample_rate,
        })
    }

    /// Write a block of samples.
    pub fn write_samples(&mut self, samples: &[i16]) -> io::Result<()> {
        for &s in samples {
            self.inner.write_all(&s.to_le_bytes())?;
        }
        self.sample_count += samples.len() as u32;
        Ok(())
    }

    /// Finalize the WAV file by patching the header with correct sizes.
    pub fn finish(mut self) -> io::Result<W> {
        use std::io::SeekFrom;

        let data_size = self.sample_count * 2;
        let riff_size = 36 + data_size;
        let byte_rate = self.sample_rate * 2; // mono 16-bit
        let sample_rate = self.sample_rate;

        self.inner.seek(SeekFrom::Start(0))?;

        // RIFF header
        self.inner.write_all(b"RIFF")?;
        self.inner.write_all(&riff_size.to_le_bytes())?;
        self.inner.write_all(b"WAVE")?;

        // fmt sub-chunk
        self.inner.write_all(b"fmt ")?;
        self.inner.write_all(&16u32.to_le_bytes())?;
        self.inner.write_all(&1u16.to_le_bytes())?; // PCM
        self.inner.write_all(&1u16.to_le_bytes())?; // mono
        self.inner.write_all(&sample_rate.to_le_bytes())?;
        self.inner.write_all(&byte_rate.to_le_bytes())?;
        self.inner.write_all(&2u16.to_le_bytes())?; // block align
        self.inner.write_all(&16u16.to_le_bytes())?; // bits per sample

        // data sub-chunk
        self.inner.write_all(b"data")?;
        self.inner.write_all(&data_size.to_le_bytes())?;

        Ok(self.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_wav_header() {
        let samples = [0i16; 320];
        let mut buf = Vec::new();
        write_wav(&mut buf, &samples, 16000).unwrap();

        // Check RIFF header
        assert_eq!(&buf[0..4], b"RIFF");
        let riff_size = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        assert_eq!(riff_size, 36 + 640); // 320 samples * 2 bytes
        assert_eq!(&buf[8..12], b"WAVE");

        // Check fmt
        assert_eq!(&buf[12..16], b"fmt ");
        let fmt_size = u32::from_le_bytes(buf[16..20].try_into().unwrap());
        assert_eq!(fmt_size, 16);
        let audio_fmt = u16::from_le_bytes(buf[20..22].try_into().unwrap());
        assert_eq!(audio_fmt, 1); // PCM

        // Check data
        assert_eq!(&buf[36..40], b"data");
        let data_size = u32::from_le_bytes(buf[40..44].try_into().unwrap());
        assert_eq!(data_size, 640);

        // Total size
        assert_eq!(buf.len(), 44 + 640);
    }
}
