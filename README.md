# a1800_codec
![a1800_codec PyPi](https://img.shields.io/pypi/v/a1800_codec)

A Rust encoder and decoder for the GeneralPlus A1800 audio codec, reverse-engineered from `A1800.DLL`.

The A1800 is a fixed-point subband audio codec that splits 320-sample frames (20 ms at 16 kHz) into 32 subbands using a 5-stage butterfly filterbank. It supports bitrates from 4800 to 32000 bps in steps of 800. All arithmetic uses ITU-T G.729-style saturating i16/i32 operations.

See [Codec.md](Codec.md) for the full technical reference, including the decode/encode pipelines, constant tables, DLL function map, and known differences between this implementation and the original DLL.

## Authoring

This code was co-developed with Claude Opus 4.6 and made use of [Ghidra 12.0.2](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.0.2_build) and [ghidra-mcp v2.0.0](https://github.com/bethington/ghidra-mcp/releases/tag/v2.0.0)

## Building

```
cargo build --release
```

No external dependencies.

## Usage

```
# Decode .a18 to WAV
a1800_codec decode input.a18 output.wav [--sample-rate 16000]

# Encode WAV to .a18
a1800_codec encode input.wav output.a18 [--bitrate 16000]
```

Input WAV files must be mono 16-bit PCM. The default sample rate is 16000 Hz and the default bitrate is 16000 bps.

## .a18 File Format

| Offset | Size | Type   | Description                        |
|--------|------|--------|------------------------------------|
| 0x00   | 4    | LE u32 | Byte count of frame data           |
| 0x04   | 2    | LE u16 | Bitrate                            |
| 0x06   | ...  | bytes  | Frames, each (bitrate/800) x 2 bytes |

## Round-trip Quality

At 16 kHz / 16 kbps:

- Overall correlation: ~0.60
- RMS ratio (output/input): ~1.02
- 1 kHz sine SNR: ~15 dB

Bitrates 4800-24000 bps are supported for encoding. Decoding works at all bitrates.

## Tests

See [Testing.md](Testing.md) for more information about non-synthetic tests.

```
cargo test
```

52 tests cover fixed-point arithmetic, bitstream I/O, encoder/decoder round-trips at multiple bitrates, filterbank invertibility, and a 5-second WAV round-trip.

## License

This is an independent clean-room reimplementation based on static analysis of the original DLL. No original source code or proprietary headers were used.

## Other Resources
 * A python implementation of the encoder by @prekageo at [a1800_codec](https://github.com/prekageo/a1800_codec)
 * Furby reverse engineering tools which decode via python and proprietary `A1800.DLL` [Furby](https://github.com/benbalter/Furby)
