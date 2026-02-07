# A1800 Codec Testing

## Test Input: `test_input.wav`

5-second synthetic WAV file for codec round-trip testing.

**Format:** 16 kHz, mono, 16-bit PCM (80,000 samples, 250 frames)

### Segments

| Time (s) | Frames  | Content                      | Amplitude | Purpose                          |
|----------|---------|------------------------------|-----------|----------------------------------|
| 0–1      | 0–49    | 440 Hz sine                  | 8000      | Basic mid-frequency tone         |
| 1–2      | 50–99   | 1 kHz sine                   | 12000     | Higher frequency, higher energy  |
| 2–3      | 100–149 | 200 + 800 + 2000 Hz mix      | 4000 each | Exercises multiple subbands      |
| 3–4      | 150–199 | Chirp sweep 100 Hz to 4 kHz  | 10000     | Sweeps across subbands           |
| 4–5      | 200–249 | 600 Hz decaying to silence   | 10000→0   | Amplitude transition             |

### Generation

```bash
python3 -c "
import struct, math, wave

sr = 16000
n = sr * 5
samples = []

for i in range(n):
    t = i / sr
    if t < 1.0:
        s = 8000.0 * math.sin(2 * math.pi * 440 * t)
    elif t < 2.0:
        s = 12000.0 * math.sin(2 * math.pi * 1000 * t)
    elif t < 3.0:
        s = (4000.0 * math.sin(2 * math.pi * 200 * t)
           + 4000.0 * math.sin(2 * math.pi * 800 * t)
           + 4000.0 * math.sin(2 * math.pi * 2000 * t))
    elif t < 4.0:
        frac = t - 3.0
        freq = 100.0 + 3900.0 * frac
        phase = 2 * math.pi * (100.0 * frac + 0.5 * 3900.0 * frac * frac)
        s = 10000.0 * math.sin(phase)
    else:
        frac = t - 4.0
        env = max(0.0, 1.0 - frac)
        s = 10000.0 * env * math.sin(2 * math.pi * 600 * t)
    samples.append(max(-32768, min(32767, int(round(s)))))

with wave.open('test_input.wav', 'w') as w:
    w.setnchannels(1)
    w.setsampwidth(2)
    w.setframerate(sr)
    w.writeframes(struct.pack('<' + 'h' * len(samples), *samples))
"
```

### Usage

Encode and decode at a given bitrate:

```bash
cargo run -- encode test_input.wav test.a18 --bitrate 16000
cargo run -- decode test.a18 test_output.wav
```

Compare input and output in an audio editor or with a spectral analysis tool to evaluate codec quality.
