# GeneralPlus A1800 Audio Codec — Technical Reference

Reverse-engineered from `A1800.DLL` (32-bit x86 Windows PE), a GeneralPlus proprietary audio codec. This document captures everything known (and unknown) about the codec from static analysis and decompilation.

---

## 1. Codec Overview

**Type**: Subband audio coder (NOT CELP, NOT transform/MDCT)

**Key parameters**:
- Sample rate: 16 kHz (presumed; see unknowns)
- Frame size: 320 samples (20 ms at 16 kHz)
- Supported bitrates: 4800–32000 bps in steps of 800
- Arithmetic: ITU-T G.729-style fixed-point (i16/i32 with saturation)
- Channels: Mono

**Architecture**: 5-stage butterfly filterbank splitting 320 time-domain samples into 32 subbands of 10 samples each. Only the first 8–14 subbands are coded (depending on bitrate); the rest are zeroed.

---

## 2. File Format (.a18)

```
Offset  Size  Type     Description
──────  ────  ────     ───────────
0x00    4     LE u32   data_length — total bytes of frame data after the header
0x04    2     LE u16   bitrate — e.g. 16000
0x06    ...   bytes    encoded frames, each (bitrate / 800) × 2 bytes
```

Each encoded frame is `bitrate / 800` 16-bit little-endian words. For example, at 16000 bps: 20 words = 40 bytes per frame.

---

## 3. Bitrate-Dependent Parameters

| Bitrate Range  | num_subbands | bits_per_frame | encoded_frame_size (i16 words) |
|----------------|-------------|----------------|-------------------------------|
| 4800–9599      | 8           | bitrate/50     | bitrate/800                   |
| 9600–11999     | 10          | "              | "                             |
| 12000–15999    | 12          | "              | "                             |
| 16000–32000    | 14          | "              | "                             |

Subbands beyond `num_subbands` are zeroed. Each subband contains 20 samples (10 samples × 2 subframes, or equivalently 20 interleaved).

---

## 4. Decode Pipeline

Per frame, the decode pipeline is:

```
Bitstream → Gain Decode → Bit Allocation → Subframe Decode → Inverse Filterbank → Synthesis
```

### 4.1. Gain Decode (`decode_gains` / DLL 0x10003050)

1. Read 5-bit initial gain index → `initial_gain = index - 7`
2. For each additional subband (up to num_subbands - 1):
   - Huffman-decode a differential using GAIN_HUFFMAN_TREE
   - Tree has 13 sections of 23 nodes each (one per subband differential)
   - Node index starts at section × 23; positive = child, negative/zero = leaf (negate for symbol)
3. Cumulative gains: `gain[i+1] = gain[i] + differential[i] - 12`
4. Compute scale_param (controls synthesis scaling exponent):
   - Start sp=9
   - Compute total_cost from SCALE_FACTOR_BITS, find max effective gain
   - Iteratively halve cost, reduce gain by 2, decrement sp until constraints met
5. Final scale factors: `scale_factor[i] = SCALE_FACTOR_BITS[gain[i] + sp*2 + 24]`

### 4.2. Read 4-bit Frame Parameter

A 4-bit value consumed from the bitstream after gains. Used to fine-tune bit allocation via `increment_allocation_bins`.

### 4.3. Bit Allocation (`compute_bit_alloc_for_frame` / DLL 0x10001d30)

Three-step process:

1. **Budget adjustment**: If remaining bits > 320, compress excess: `budget = ((remaining - 320) * 5) >> 3 + 320`

2. **Binary search for threshold** (`search_threshold` / DLL 0x100020f0):
   - Start threshold = -32, step = 32
   - For each subband: `alloc[i] = clamp((threshold - gain[i]) >> 1, 0, 7)`
   - Compute cost = sum of BIT_ALLOC_COST[alloc[i]]
   - If cost >= budget - 32, keep threshold
   - Halve step, repeat until step = 0

3. **Greedy optimization** (`optimize_allocation` / DLL 0x10001dc0):
   - 15 iterations of adjusting allocations up/down to balance cost against 2× budget
   - Under budget → decrease worst subband (smallest `threshold - gain - 2*step` metric)
   - Over budget → increase best subband (largest metric, scanning from top subband down)
   - Records operations in a swap log

4. **Apply frame parameter**: The 4-bit value indexes into the swap log to replay N increment operations.

### 4.4. Subframe Decode (`decode_subframes` / DLL 0x100032e0)

For each subband, based on its allocation step (0–7):

**Steps 0–4**: Pure codebook decode
- Huffman-decode a symbol from CODEBOOK_TREE_{0..6}
- Inverse quantize: decompose symbol into digits via iterated division
  - `quotient = mult(val, QUANT_STEP_SIZE[step])`
  - `remainder = val - quotient * (QUANT_INV_STEP[step] + 1)`
  - digit = remainder, then val = quotient; repeat for QUANT_LEVELS_M1[step] digits
- Read sign bits (one per nonzero digit)
- Reconstruct: `sample = extract_l(L_shr(L_mult0(scale_factor, QUANT_RECON_LEVELS[step][digit]), 12))`
- Apply sign: if sign bit = 0 → negate

**Steps 5–6**: Codebook decode + conditional noise fill
- Same codebook decode as above
- After decode, fill any remaining zero samples with shaped noise
- `noise_level = mult(scale_factor, NOISE_GAINS[step - 5])`
- NOISE_GAINS = [0x16A1, 0x2000, 0x5A82]
- Two PRNG calls per subband (one for first 10 samples, one for last 10)
- Each PRNG output bit determines noise sign (+noise_level or -noise_level)
- Only applied to samples that are still zero

**Step 7**: Full noise fill (no codebook decode)
- All 20 samples replaced with noise
- `noise_level = mult(scale_factor, NOISE_GAINS[2])` (= 0x5A82)
- Same PRNG-based sign selection

**Error handling**: If bitstream runs out mid-decode, remaining subbands are set to step 7 (noise-filled).

### 4.5. Noise PRNG (`noise_prng` / DLL 0x10003870)

4-tap linear feedback register:
```
sum = state[0] + state[3]
if sum is negative, add 1
shift state: [3] ← [2] ← [1] ← [0] ← sum
return sum
```
Initialized to [1, 1, 1, 1].

### 4.6. Inverse Filterbank (`inverse_filterbank` / DLL 0x10002740)

Three phases operating on 320 samples:

**Phase 1: 5-stage butterfly decomposition**

Each stage splits groups into sums (front) and differences (back):
- Stage 0 (1 group of 320): 32-bit precision
  - `sum = extract_l(L_shr(L_add(a, b), 1))`
  - `diff = extract_l(L_shr(L_add(a, -b), 1))`
- Stages 1–4 (2/4/8/16 groups): 16-bit precision
  - `sum = add(a, b)`
  - `diff = add(a, negate(b))`

Uses ping-pong between two 320-element scratch buffers.

**Phase 2: Cosine modulation**

32 groups of 10 samples, each multiplied by a shared 10×10 cosine matrix.

```
output[g*10 + k] = extract_h(L_shr(
    sum(j=0..9: L_mac(acc, butterfly[g*10+j], COSINE_MOD_MATRIX[k + j*10])),
    1))
```

Only the first 100 entries of COSINE_MOD_MATRIX are meaningful (the 10×10 matrix). The remaining 220 entries are small noise-like values (possibly padding/unrelated data in the DLL's .rdata).

**Phase 3: 5-stage reconstruction with filterbank coefficients**

Stages 4→0, each using a coefficient table (FILTERBANK_COEFF_0 through FILTERBANK_COEFF_4). Each stage processes groups with a 4-coefficient butterfly:

```
Given inputs a, b (first half) and c, d (second half), and coefficients c0–c3:
A = extract_h(L_shl(L_mac(L_mac(0, c0, a), negate(c1), c), 1))  → front
C = extract_h(L_shl(L_mac(L_mac(0, c2, b), c3, d), 1))          → front+1
B = extract_h(L_shl(L_mac(L_mac(0, c1, a), c0, c), 1))          → back-1
D = extract_h(L_shl(L_mac(L_mac(0, c3, b), negate(c2), d), 1))  → back-2
```

Outputs are placed in interleaved front/back order within each group.

Coefficient table sizes: 20, 40, 80, 160, 320 entries (4 coefficients per butterfly × half_group/2 iterations × 1 set reused across all groups in the stage).

| Stage | Group Size | Num Groups | Coeff Table          | Entries |
|-------|-----------|------------|----------------------|---------|
| 4     | 20        | 16         | FILTERBANK_COEFF_0   | 20      |
| 3     | 40        | 8          | FILTERBANK_COEFF_1   | 40      |
| 2     | 80        | 4          | FILTERBANK_COEFF_2   | 80      |
| 1     | 160       | 2          | FILTERBANK_COEFF_3   | 160     |
| 0     | 320       | 1          | FILTERBANK_COEFF_4   | 320     |

**Final scaling**: If frame_size == 320 (always true in practice), all output samples are shifted left by 1 via `shl(sample, 1)`.

### 4.7. Synthesis Filter (`synthesis_filter` / DLL 0x10001b60)

Windowed overlap-add producing 320 PCM samples from inverse filterbank output + 160-sample memory from previous frame.

1. Call inverse_filterbank → `filtered[0..319]`
2. Apply scale_param: if > 0, `shr(sample, scale_param)`; if < 0, `shl(sample, -scale_param)`
3. First 160 output samples:
   ```
   output[k] = extract_h(L_shl(
       L_mac(L_mac(0, SYNTH_OVERLAP[k], filtered[159-k]),
             SYNTH_OVERLAP[319-k], memory[k]),
       2))
   ```
4. Second 160 output samples:
   ```
   output[160+k] = extract_h(L_shl(
       L_mac(L_mac(0, SYNTH_OVERLAP[160+k], filtered[k]),
             negate(SYNTH_OVERLAP[159-k]), memory[159-k]),
       2))
   ```
5. Update memory: `memory[k] = filtered[160+k]` for k=0..159

Note: only `filtered[0..159]` is used in output computation; `filtered[160..319]` is saved as next frame's overlap memory. This is classic overlap-add where the current frame's second half contributes to the next frame.

---

## 5. Encode Pipeline

Per frame, the encode pipeline mirrors the decode pipeline in reverse:

```
PCM → Analysis Filter → Gain Encode → Bit Allocation → Subframe Encode → Bitstream Pack
```

### 5.1. Analysis Filter (`analysis_filter` / DLL 0x10004ba0)

Converts 320 PCM samples to 320 subband samples + returns `scale_param`:
1. Calls `forward_filterbank(pcm_input, g_enc_filterbank_memory, subband_buf, 320)`
2. Computes `scale_param` from the subband energy distribution

### 5.2. Forward Filterbank (`forward_filterbank` / DLL 0x10002280)

Same 3-phase structure as the inverse filterbank but with key differences:

**Butterfly stages**: Uses `L_shr` *before* `L_add/L_sub` (pre-scaling to prevent overflow):
```
sum  = extract_l(L_add(L_shr(a, 1), L_shr(b, 1)))
diff = extract_l(L_sub(L_shr(a, 1), L_shr(b, 1)))
```
vs. the inverse which does `L_add` then `L_shr`.

**Cosine modulation**: Uses `FWD_COSINE_MOD_MATRIX` (0x1000bb88) and `extract_h(acc)` directly (no `L_shr(acc, 1)` as in the inverse).

**Reconstruction**: Uses `FWD_FILTERBANK_COEFF_PTRS` (0x1000bb70). Same 4-coefficient butterfly formula as the inverse but without the `L_shl(1)` wrapper — `extract_h(L_mac(...))` directly.

### 5.3. Gain Encode (`encode_gains` / DLL 0x100040b0)

1. For each subband, compute energy: `sum(sample² for 20 samples)` via `L_mac0`
2. Convert to log-scale gain index (normalize via leading-zero count)
3. Clamp first gain to [-6, 24], subsequent differentials to [-15, 24]
4. Huffman-encode differentials using `GAIN_HUFFMAN_BIT_WIDTHS` and `GAIN_HUFFMAN_CODES` tables
5. Returns total bits consumed by gain encoding

### 5.4. Encode Frame (`encode_frame` / DLL 0x10003ad0)

1. `encode_gains` → gain indices + Huffman codes
2. `compute_bit_alloc_for_frame` → per-subband allocation (same function as decoder)
3. `prescale_subbands` → normalize subband samples by gain (right-shift proportional to gain)
4. `encode_subframes` → quantize each subband via `forward_quantize`, pack into coded data
5. `write_bitstream` → assemble gain codes + 4-bit frame parameter + coded subbands into output words

### 5.5. Bitstream Packing (`write_bitstream` / DLL 0x10003c30)

Packs the following into 16-bit LE output words:
1. Per-subband gain Huffman codes (variable width)
2. 4-bit frame parameter (from optimization swap count)
3. Per-subband coded data: Huffman symbols + sign bits

Parameters: `(encoded_data, subband_bits, gain_codes, gain_bit_widths, output, frame_param_code, num_subbands, frame_param_bits=4, bits_per_frame)`

### 5.6. enc_frame / enc_frame_init Entry Points

```
enc_frame_init(bitrate, &enc_frame_words_out, &dec_frame_size_out) → 0=ok, 8=bad bitrate
    Calls a1800_enc_frame_init, then returns encoded frame word count and decoded frame size (320).

enc_frame(pcm_input, output_bitstream) → 0
    Calls analysis_filter(pcm, g_enc_filterbank_memory, subbands, 320) → scale_param
    Calls encode_frame(g_enc_bits_per_frame, g_enc_num_subbands, subbands, scale_param, output)
```

---

## 6. Constant Tables

All tables were extracted from the DLL's .rdata section via Ghidra memory inspection.

| Table                 | Address      | Size      | Purpose                                      |
|-----------------------|-------------|-----------|----------------------------------------------|
| BIT_ALLOC_COST        | 0x1000d9f0  | 8 i16     | Cost in bits per quantizer step (0–7)        |
| SCALE_FACTOR_BITS     | 0x100105a8  | 128 i16   | Exponential power curve + plateau + mirror    |
| QUANT_LEVELS_M1       | 0x100106b8  | 8 i16     | Number of quantizer digits minus 1            |
| QUANT_NUM_COEFF       | 0x100106c8  | 8 i16     | Subframes per subband per quantizer step      |
| QUANT_INV_STEP        | 0x100106d8  | 8 i16     | Inverse quantizer step sizes                  |
| QUANT_STEP_SIZE       | 0x100106e8  | 8 i16     | Quantizer step sizes (Q15 reciprocals)        |
| QUANT_RECON_LEVELS    | 0x1000d8f0  | 8×16 i16  | Reconstruction levels per step                |
| GAIN_HUFFMAN_TREE     | 0x1000d3e8  | 300×2 i16 | 13 sections × 23 nodes, binary tree           |
| COSINE_MOD_MATRIX     | 0x1000bed0  | 320 i16   | First 100 = 10×10 cosine matrix; rest unused  |
| FILTERBANK_COEFF_0    | 0x1000C498  | 20 i16    | Reconstruction stage 4 coefficients           |
| FILTERBANK_COEFF_1    | 0x1000C4C0  | 40 i16    | Reconstruction stage 3 coefficients           |
| FILTERBANK_COEFF_2    | 0x1000C510  | 80 i16    | Reconstruction stage 2 coefficients           |
| FILTERBANK_COEFF_3    | 0x1000C5B0  | 160 i16   | Reconstruction stage 3 coefficients           |
| FILTERBANK_COEFF_4    | 0x1000C6F0  | 320 i16   | Reconstruction stage 0 coefficients           |
| FILTERBANK_COEFF_5    | 0x1000C970  | 640 i16   | Encoder-only (not used in decoder)            |
| CODEBOOK_TREE_0..6    | various     | various   | 7 Huffman codebook trees for quantizer steps  |
| SYNTH_OVERLAP_OFFSETS | 0x10010998  | 320 i16   | Synthesis window coefficients (monotonic rise) |
| Coeff pointer table   | 0x1000ce70  | 6 ptrs    | Pointers to FILTERBANK_COEFF_0..5             |

### SCALE_FACTOR_BITS Structure

128 entries with a distinctive pattern:
- Indices 0–21: all zeros
- Indices 22–53: exponential power curve (1, 1, 1, 1, 2, 3, 4, 6, ... 16384, 23170)
- Indices 54–63: zeros
- Indices 64–88: plateau at 32767
- Indices 89–127: descending mirror of the rising portion

### Codebook Trees

Flat arrays where `tree[node*2]` = left child, `tree[node*2+1]` = right child. Positive values are child node indices; negative/zero values are leaf symbols (negate to get the decoded symbol). Tree sizes vary: 360, 186, 94, 1038, 416, 382, 62 entries for steps 0–6 respectively.

---

## 7. Fixed-Point Arithmetic

All arithmetic matches ITU-T G.729 basic operations. Key functions:

| Function    | Signature            | Semantics                                     |
|-------------|---------------------|-----------------------------------------------|
| saturate    | i32 → i16           | Clamp to [-32768, 32767]                      |
| add         | (i16, i16) → i16    | Saturating 16-bit addition                    |
| sub         | (i16, i16) → i16    | Saturating 16-bit subtraction                 |
| negate      | i16 → i16           | Saturating negate (-32768 → 32767)            |
| abs_s       | i16 → i16           | Saturating absolute value                     |
| shl         | (i16, i16) → i16    | Left shift with overflow saturation           |
| shr         | (i16, i16) → i16    | Arithmetic right shift                        |
| mult        | (i16, i16) → i16    | Q15 multiply: (a*b) >> 15                     |
| L_mult      | (i16, i16) → i32    | a*b*2 with saturation for 0x40000000          |
| L_mac       | (i32, i16, i16) → i32 | acc + a*b*2                                |
| L_add       | (i32, i32) → i32    | Saturating 32-bit addition                    |
| L_sub       | (i32, i32) → i32    | Saturating 32-bit subtraction                 |
| L_shl       | (i32, i16) → i32    | 32-bit left shift with saturation             |
| L_shr       | (i32, i16) → i32    | 32-bit arithmetic right shift                 |
| extract_h   | i32 → i16           | High 16 bits (val >> 16)                      |
| extract_l   | i32 → i16           | Low 16 bits (val as i16)                      |
| L_deposit_l | i16 → i32           | Sign-extend 16-bit to 32-bit                  |
| norm_s      | i16 → i16           | Count leading redundant sign bits             |
| L_mult0     | (i16, i16) → i32    | a*b (no ×2)                                   |
| L_mac0      | (i32, i16, i16) → i32 | acc + a*b (no ×2)                           |

---

## 8. DLL Function Map

### Decoder Functions

| DLL Function                    | Address     | Rust Location                  |
|---------------------------------|------------|-------------------------------|
| a1800_dec_frame_init            | 0x10002ca0 | decoder.rs::DecoderState::new |
| a1800_dec_frame / dec_frame     | 0x10002e70 | decoder.rs::decode_frame_to_subbands |
| decode_frame_params             | 0x10002f60 | decoder.rs::decode_frame_params |
| decode_gains                    | 0x10003050 | decoder.rs::decode_gains      |
| read_bit                        | 0x10003820 | bitstream.rs::read_bit        |
| compute_bit_alloc_for_frame     | 0x10001d30 | decoder.rs::compute_bit_alloc_for_frame |
| search_bit_allocation_threshold | 0x100020f0 | decoder.rs::search_threshold  |
| compute_bit_allocation          | 0x10002200 | decoder.rs::compute_allocation |
| optimize_bit_allocation         | 0x10001dc0 | decoder.rs::optimize_allocation |
| increment_allocation_bins       | 0x10003290 | decoder.rs::increment_allocation_bins |
| decode_subframes                | 0x100032e0 | decoder.rs::decode_subframes  |
| inverse_quantize                | 0x10003760 | decoder.rs::inverse_quantize  |
| noise_prng                      | 0x10003870 | decoder.rs::noise_prng        |
| inverse_filterbank              | 0x10002740 | filterbank.rs::inverse        |
| synthesis_filter                | 0x10001b60 | synthesis.rs::synthesize      |
| saturate...norm_s               | 0x100016e0–0x10001b20 | fixedpoint.rs     |

### Encoder Functions

| DLL Function                    | Address     | Description                                   |
|---------------------------------|------------|-----------------------------------------------|
| a1800_enc_frame_init            | 0x100038c0 | Validate bitrate, set globals, zero memory    |
| enc_frame_init                  | 0x100039a0 | Wrapper: inits + returns frame sizes          |
| a1800_enc_frame                 | 0x10003a20 | Per-frame encode (analysis → encode_frame)    |
| enc_frame                       | 0x100039d0 | Wrapper: analysis_filter + encode_frame       |
| analysis_filter                 | 0x10004ba0 | PCM → subbands (forward filterbank + scaling) |
| forward_filterbank              | 0x10002280 | Forward 5-stage butterfly + cosine mod        |
| encode_frame                    | 0x10003ad0 | Encode subbands to bitstream                  |
| encode_gains                    | 0x100040b0 | Compute gain indices + Huffman encode         |
| prescale_subbands               | 0x10003fe0 | Normalize subbands by gain                    |
| encode_subframes                | 0x100043e0 | Quantize + encode per-subband samples         |
| forward_quantize                | 0x10004730 | Forward quantizer for one subband             |
| write_bitstream                 | 0x10003c30 | Pack gains + subframe data into output words  |

### DLL API Exports

| Export          | Address     | Signature                                                           |
|-----------------|------------|---------------------------------------------------------------------|
| a1800_enc       | 0x10001000 | (input_wav_path, output_a18_path, bitrate, output_info, progress_cb) → int |
| a1800_dec       | 0x10001370 | (src_path, dst_path, &bitrate, sample_rate, progress_cb) → int     |
| get_bitrate_info| 0x10001660 | (&num_bitrates_out, &bitrate_step_out) → ptr to BITRATE_TABLE      |
| get_bitrate     | 0x10001680 | (bitrate) → validated bitrate or 0                                 |
| get_err_str     | 0x100015d0 | (error_code) → error string pointer                                |

### WAV / CRT Helper Functions

| Function             | Address     | Description                                    |
|----------------------|------------|------------------------------------------------|
| wav_get_sample_rate  | 0x10004b30 | Find "fmt " chunk, read sample rate (u32 LE)  |
| wav_find_chunk       | 0x10004ad0 | Search RIFF chunks for matching chunk ID       |
| file_get_sample_count| 0x10004aa0 | Find "data" chunk, return byte_size / 2        |
| wav_header_init      | 0x100049e0 | Initialize 44-byte WAV header struct           |
| wav_header_set_params| 0x10004a70 | Set sample rate / format in header             |
| wav_header_update_size| 0x10004a50| Patch data size after encoding                 |
| crt_fopen            | 0x10005260 | fopen(filename, mode) — SH_DENYNO             |
| crt_fread            | 0x10004fd1 | fread(buf, elem_size, count, file)             |
| crt_fwrite           | 0x100050e8 | fwrite(buf, elem_size, count, file)            |
| crt_fseek            | 0x10004e90 | fseek(file, offset, whence)                    |
| crt_ftell            | 0x10005273 | ftell(file)                                    |

---

## 9. Decoder State

Persistent state across frames:
- `prng_state: [i16; 4]` — noise PRNG, initialized to [1, 1, 1, 1]
- `synth_memory: [i16; 320]` — only first 160 used for overlap-add, initialized to zeros
- `filterbank_memory: [i16; 640]` — allocated but **purpose unclear** (filterbank is stateless in our analysis; see unknowns)

---

## 10. Bugs Found During Reverse Engineering

### shl overflow condition (fixedpoint.rs)
The DLL at 0x10001780 has the condition `(shift < 16 || val == 0)` for the non-overflow path. An initial reading misinterpreted this as `shift < 16 && val != 0`, which caused `shl(0, 1)` to incorrectly return -32768 instead of 0.

### SCALE_FACTOR_BITS table size
Initially extracted as 32 entries. The gain decoder accesses indices up to ~53 (gain + scale_param * 2 + 24), which was out of bounds. Inspecting memory at 0x100105a8 revealed 128 entries forming a symmetric exponential power curve.

---

## 11. Things I Don't Know / Open Questions

### File Format
- **Is the .a18 header always exactly 6 bytes?** The 4-byte length + 2-byte bitrate was determined from one analysis path. There may be additional header fields in some variants.
- **Is the data_length field in bytes or some other unit?** We assume bytes based on context but haven't confirmed with multiple files.
- **Are there any other container formats** that embed A1800 frames? The DLL exports suggest it can work with raw frame buffers.

### Sample Rate
- **Is 16 kHz the only supported sample rate?** The DLL's decode function takes a sample rate parameter but the codec itself doesn't embed it in the bitstream. We default to 16 kHz. Other rates (8 kHz, 32 kHz) might be used with different frame sizes, or the same 320-sample frame at a different rate.
- **What frame sizes other than 320 are valid?** The filterbank has a `frame_size` parameter and special-cases 320 with a final ×2 scaling. Other sizes may exist but are untested.

### Encoder Side
- **The encoder is not implemented in Rust**, but all DLL encoder functions have been identified and their roles understood (see Section 8).
- **FILTERBANK_COEFF_5** (640 entries at 0x1000C970): Used by the forward filterbank encoder. The forward filterbank uses a separate coefficient pointer table at `FWD_FILTERBANK_COEFF_PTRS` (0x1000bb70) and a different cosine modulation matrix at `FWD_COSINE_MOD_MATRIX` (0x1000bb88). Unlike the decoder's `FILTERBANK_COEFF_PTRS` (0x1000ce70) which has 6 entries (5 used), the forward table structure needs further investigation.
- **How does the encoder decide the 4-bit frame parameter?** The `encode_subframes` function (0x100043e0) uses `optimize_bit_allocation`'s swap log to iteratively adjust bit allocation. The 4-bit frame parameter encodes the number of swap operations from the optimization phase that should be replayed on the decoder side.
- **Forward filterbank differences from inverse**: The forward filterbank (0x10002280) uses `L_shr` before `L_add/L_sub` in its butterfly stages (vs. inverse which uses `L_add` then `L_shr`). The reconstruction phase omits the `L_shl(1)` that the inverse uses. The cosine modulation uses `extract_h(acc)` directly (no `L_shr(acc, 1)`).

### Bit Allocation
- **Why the budget cap at 320?** The budget adjustment formula `((excess - 320) * 5) >> 3 + 320` limits effective bits, but the rationale is unclear.
- **Why 15 optimization iterations (num_iterations=16, loop runs max_iter=15)?** This seems like a fixed constant but may relate to maximum meaningful adjustments.

### Decoder State
- **What is `filterbank_memory` (640 entries) used for?** The inverse filterbank uses only local stack buffers (three 320-element arrays). The 640-entry allocation in the decoder state may be:
  - Dead/unused (over-allocated in the DLL)
  - Used by a different code path not yet analyzed (e.g., error concealment, PLC)
  - Used by the encoder side
- **Is `synth_memory` really 320 or 160 entries?** Only 160 are used for synthesis overlap-add. The DLL allocates a larger state struct, and we sized it at 320 as a conservative match.

### COSINE_MOD_MATRIX
- **What are the last 220 entries?** Only the first 100 (10×10 matrix) are accessed by the cosine modulation phase. The remaining values are small (-8 to +11 range) and appear to be unrelated data or padding in the DLL's .rdata section. They may be:
  - A different table that was laid out adjacently
  - Initialization data for something else
  - Artifacts of compiler/linker padding

### Gain Huffman Tree
- **Why 23 nodes per section?** Each of the 13 sections (for up to 13 subband differentials) has exactly 23 nodes. The first 23 entries (section 0) are all zeros and appear unused. The symbol range is 0–23, which maps well to differential gain values, but the exact meaning of the 23-node size is unclear.
- **The tree has 300 entries (13 × 23 + 1 unused section).** With max 14 subbands, only 13 differentials are needed, so 13 sections suffice. The zeros at the beginning may be a sentinel/padding.

### Quantizer Details
- **QUANT_STEP_SIZE values are approximate Q15 reciprocals** of (QUANT_INV_STEP + 1). For example, step 0: QUANT_STEP_SIZE[0] = 2341 ≈ 32768/14. This is used for the iterated division in inverse_quantize via `mult(val, step_size)`. The precision implications of this approximation are unexplored.
- **Step 7 is "noise only"** — but what's the quantizer tree for step 7? CODEBOOK_TREE_6 (62 entries) is selected for step 6. Step 7 goes directly to noise fill without any codebook decode, so no tree is needed. But the QUANT_RECON_LEVELS[7] table exists with values [0, 8019] — is this ever used?

### Error Concealment
- **What happens on corrupted frames?** The current implementation detects bitstream exhaustion and fills remaining subbands with step-7 noise. The DLL also subtracts 1 from total_bits_remaining after error. But there may be more sophisticated error concealment that wasn't captured.

### DLL Exports and Calling Convention
- **The DLL exports** `a1800_dec_frame_init` and `a1800_dec_frame` (and encoder equivalents). The exact calling convention for the state struct pointer and its full layout beyond what we use is partially known:
  - The state struct is at least ~0x400 bytes
  - State offset 0x000: bitrate-derived parameters
  - State offset 0x1b0: synthesis memory (passed to synthesis_filter)
  - State offset 0x360: PRNG state (4 i16 values)
  - Full struct layout is not mapped

### Bit-Exactness
- **Has the decoder been validated against the DLL's output?** No. All code was written from decompiled pseudocode. True bit-exact verification requires:
  1. Real .a18 test files
  2. Reference output from the DLL (e.g., running it via Wine or on Windows)
  3. Sample-by-sample comparison
- **The PRNG initialization** [1, 1, 1, 1] was read from the DLL's init function. If this is wrong, all noise-filled subbands will differ.

### Encoder Implementation (Rust — not started)
- All encoder DLL functions have been identified and parameter-named in Ghidra (see Section 8).
- `analysis_filter` (0x10004ba0): Calls `forward_filterbank` then computes `scale_param` — full decompilation available but not yet traced in detail.
- `encode_gains` (0x100040b0): Computes per-subband energy (sum of squares via `L_mac0`), log-scale gain, differential Huffman encoding using `GAIN_HUFFMAN_BIT_WIDTHS` (0x1000cea8) and `GAIN_HUFFMAN_CODES` (0x1000d148).
- `prescale_subbands` (0x10003fe0): Right-shifts subband samples proportional to gain index, normalizing them before quantization.
- `forward_quantize` (0x10004730): Converts normalized subband samples into Huffman-coded symbols — the inverse of `inverse_quantize`.
- `write_bitstream` (0x10003c30): Packs gain codes, frame parameter, and encoded subband data into 16-bit output words.

---

## 12. Rust Implementation Structure

```
src/
├── main.rs          CLI: a1800_codec decode <input.a18> <output.wav>
├── lib.rs           Public API: A1800Decoder
├── fixedpoint.rs    ITU-T G.729-style basic operations (25 functions)
├── bitstream.rs     MSB-first bit reader from 16-bit LE words
├── decoder.rs       Frame decoder: gains, bit allocation, subframe decode
├── filterbank.rs    5-stage butterfly + cosine mod + reconstruction
├── synthesis.rs     Inverse filterbank + scaling + overlap-add
├── tables.rs        All constant tables from the DLL
└── wav.rs           Mono 16-bit PCM WAV writer
```

25 tests cover: fixed-point ops (9), bitstream reader (4), decoder core (6), filterbank (3), synthesis (2), WAV writer (1).

---

## 13. CLI Usage

```
a1800_codec decode <input.a18> <output.wav> [--sample-rate N]
```

Default sample rate is 16000 Hz. The decoder reads the bitrate from the .a18 header.
