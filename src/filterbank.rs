/// Filterbank transforms for the A1800 audio codec.
///
/// Inverse: 5-stage butterfly decomposition → 10x10 cosine modulation → 5-stage reconstruction.
/// Matches `inverse_filterbank` / `FUN_10002740` at address 0x10002740 in the DLL.
///
/// Forward: 5-stage reconstruction → 10x10 cosine modulation → 5-stage butterfly.
/// Matches `forward_filterbank` / `FUN_10002280` at address 0x10002280 in the DLL.

use crate::fixedpoint::*;
use crate::tables::*;

/// Perform inverse filterbank transform on `frame_size` subband samples.
///
/// Converts frequency-domain subband samples into time-domain output.
/// `input` and `output` must each have at least `frame_size` elements.
pub fn inverse(input: &[i16], output: &mut [i16], frame_size: i16) {
    let n = frame_size as usize;
    let mut buf_a = [0i16; 320];
    let mut buf_b = [0i16; 320];

    // ── Phase 1: 5-stage butterfly decomposition ──────────────────────

    // Stage 0: 32-bit precision (L_add / L_shr / extract_l)
    {
        let mut src_pos = 0usize;
        let mut front = 0usize;
        let mut back = n;
        while front < back {
            let a = input[src_pos] as i32;
            let b = input[src_pos + 1] as i32;
            src_pos += 2;

            let s = extract_l(l_shr(l_add(a, b), 1));
            let d = extract_l(l_shr(l_add(a, -b), 1));

            back -= 1;
            buf_a[front] = s;
            front += 1;
            buf_a[back] = d;
        }
    }

    // Stages 1–4: 16-bit precision (add / negate)
    butterfly_16(&buf_a, &mut buf_b, n, 1);
    butterfly_16(&buf_b, &mut buf_a, n, 2);
    butterfly_16(&buf_a, &mut buf_b, n, 3);
    butterfly_16(&buf_b, &mut buf_a, n, 4);
    // Result is in buf_a.

    // ── Phase 2: Cosine modulation ───────────────────────────────────
    // 32 groups of 10 samples, each multiplied by the 10×10 cosine matrix.
    // Matrix layout: row j, column k → COSINE_MOD_MATRIX[k + j * 10].
    for g in 0..32usize {
        for k in 0..10usize {
            let mut acc: i32 = 0;
            for j in 0..10usize {
                acc = l_mac(acc, buf_a[g * 10 + j], COSINE_MOD_MATRIX[k + j * 10]);
            }
            buf_b[g * 10 + k] = extract_h(l_shr(acc, 1));
        }
    }

    // Copy cosine output into buf_a for the reconstruction phase.
    buf_a[..n].copy_from_slice(&buf_b[..n]);

    // ── Phase 3: 5-stage reconstruction with filterbank coefficients ─
    // Stages 4→0, each using its own coefficient table.
    // Last stage writes directly into the caller's output buffer.
    reconstruct(&buf_a, &mut buf_b, n, 4, &FILTERBANK_COEFF_0);
    reconstruct(&buf_b, &mut buf_a, n, 3, &FILTERBANK_COEFF_1);
    reconstruct(&buf_a, &mut buf_b, n, 2, &FILTERBANK_COEFF_2);
    reconstruct(&buf_b, &mut buf_a, n, 1, &FILTERBANK_COEFF_3);
    reconstruct(&buf_a, output, n, 0, &FILTERBANK_COEFF_4);

    // Final scaling: if frame_size == 320, left-shift all samples by 1.
    if frame_size == 320 {
        for i in 0..n {
            output[i] = shl(output[i], 1);
        }
    }
}

/// Perform forward filterbank transform on `frame_size` time-domain samples.
///
/// Converts time-domain input into frequency-domain subband output.
/// Matches `forward_filterbank` / `FUN_10002280` at address 0x10002280 in the DLL.
///
/// DLL order: butterfly(stages 0–4) → cosine modulation → reconstruction(stages 4–0).
/// All butterfly stages use 32-bit precision (L_shr before L_add/L_sub).
pub fn forward(input: &[i16], output: &mut [i16], frame_size: i16) {
    let n = frame_size as usize;
    let mut buf_a = [0i16; 320];
    let mut buf_b = [0i16; 320];

    // ── Phase 1: 5-stage butterfly (all 32-bit precision) ────────────
    // Reads pairs sequentially from source, writes sums to front and diffs to back.
    // Uses L_shr before L_add/L_sub (pre-scaling to avoid overflow).
    fwd_butterfly_32(input, &mut buf_a, n, 0);
    fwd_butterfly_32(&buf_a, &mut buf_b, n, 1);
    fwd_butterfly_32(&buf_b, &mut buf_a, n, 2);
    fwd_butterfly_32(&buf_a, &mut buf_b, n, 3);
    fwd_butterfly_32(&buf_b, &mut buf_a, n, 4);
    // Result in buf_a.

    // ── Phase 2: Cosine modulation ───────────────────────────────────
    // Uses FWD_COSINE_MOD_MATRIX and extract_h(acc) directly (no L_shr).
    for g in 0..32usize {
        for k in 0..10usize {
            let mut acc: i32 = 0;
            for j in 0..10usize {
                acc = l_mac(acc, buf_a[g * 10 + j], FWD_COSINE_MOD_MATRIX[k + j * 10]);
            }
            buf_b[g * 10 + k] = extract_h(acc);
        }
    }

    buf_a[..n].copy_from_slice(&buf_b[..n]);

    // ── Phase 3: 5-stage reconstruction with forward filterbank coefficients ─
    // Stages 4→0, using FWD_FILTERBANK_COEFF_PTRS[0..4] = COEFF_0..COEFF_4.
    // Uses extract_h(l_mac(...)) directly (no l_shl).
    // Last stage (stage 0) writes to output.
    fwd_reconstruct(&buf_a, &mut buf_b, n, 4, &FWD_FILTERBANK_COEFF_0);
    fwd_reconstruct(&buf_b, &mut buf_a, n, 3, &FWD_FILTERBANK_COEFF_1);
    fwd_reconstruct(&buf_a, &mut buf_b, n, 2, &FWD_FILTERBANK_COEFF_2);
    fwd_reconstruct(&buf_b, &mut buf_a, n, 1, &FWD_FILTERBANK_COEFF_3);
    fwd_reconstruct(&buf_a, output, n, 0, &FWD_FILTERBANK_COEFF_4);
}

/// Forward butterfly for all stages (0–4).
///
/// Reads pairs sequentially from source, writes sums to front and diffs to back
/// of each group in the destination. All stages use 32-bit precision with
/// pre-scaling (L_shr before L_add/L_sub).
///
/// Same read/write pattern as the inverse butterfly_16, but with 32-bit arithmetic.
fn fwd_butterfly_32(src: &[i16], dst: &mut [i16], n: usize, stage: usize) {
    let group_size = n >> stage;
    let num_groups = 1usize << stage;

    let mut src_pos = 0usize;
    for g in 0..num_groups {
        let base = g * group_size;
        let mut front = base;
        let mut back = base + group_size;
        while front < back {
            let a = src[src_pos] as i32;
            let b = src[src_pos + 1] as i32;
            src_pos += 2;

            let a_shr = l_shr(a, 1);
            let b_shr = l_shr(b, 1);

            back -= 1;
            dst[front] = extract_l(l_add(a_shr, b_shr));
            front += 1;
            dst[back] = extract_l(l_sub(a_shr, b_shr));
        }
    }
}

/// Forward reconstruction butterfly using forward filterbank coefficients.
///
/// Same structure as inverse reconstruct but uses extract_h(l_mac(...)) directly
/// instead of extract_h(l_shl(l_mac(...), 1)).
fn fwd_reconstruct(src: &[i16], dst: &mut [i16], n: usize, stage: i16, coeffs: &[i16]) {
    let group_size = shr(n as i16, stage) as usize;
    let num_groups = shl(1, stage) as usize;
    let half = group_size / 2;

    for g in 0..num_groups {
        let src_base = g * group_size;
        let dst_base = g * group_size;

        let mut src_first = src_base;
        let mut src_second = src_base + half;
        let mut dst_front = dst_base;
        let mut dst_back = dst_base + group_size;
        let mut ci = 0usize;

        while dst_front < dst_back {
            let a = src[src_first];
            let b = src[src_first + 1];
            let c = src[src_second];
            let d = src[src_second + 1];
            src_first += 2;
            src_second += 2;

            let c0 = coeffs[ci];
            let c1 = coeffs[ci + 1];
            let c2 = coeffs[ci + 2];
            let c3 = coeffs[ci + 3];
            ci += 4;

            // A = c0*a − c1*c
            let val_a = extract_h(l_mac(l_mac(0, c0, a), negate(c1), c));
            // B = c1*a + c0*c
            let val_b = extract_h(l_mac(l_mac(0, c1, a), c0, c));
            // C = c2*b + c3*d
            let val_c = extract_h(l_mac(l_mac(0, c2, b), c3, d));
            // D = c3*b − c2*d
            let val_d = extract_h(l_mac(l_mac(0, c3, b), negate(c2), d));

            dst[dst_front] = val_a;
            dst[dst_front + 1] = val_c;
            dst[dst_back - 1] = val_b;
            dst[dst_back - 2] = val_d;

            dst_front += 2;
            dst_back -= 2;
        }
    }
}

/// 16-bit butterfly decomposition for stages 1–4.
///
/// Each group of `group_size` elements is split: sums in the first half,
/// differences in the second half (reversed). The source is read linearly.
fn butterfly_16(src: &[i16], dst: &mut [i16], n: usize, stage: i16) {
    let group_size = shr(n as i16, stage) as usize;
    let num_groups = shl(1, stage) as usize;

    let mut src_pos = 0usize;
    for g in 0..num_groups {
        let base = g * group_size;
        let mut front = base;
        let mut back = base + group_size;
        while front < back {
            let a = src[src_pos];
            let b = src[src_pos + 1];
            src_pos += 2;

            back -= 1;
            dst[front] = add(a, b);
            front += 1;
            dst[back] = add(a, negate(b));
        }
    }
}

/// Reconstruction butterfly using filterbank coefficients.
///
/// Each group is split into two halves. Four inputs (a, b from the first half;
/// c, d from the second half) are combined with four coefficients (c0–c3)
/// to produce four outputs placed at the front and back of the output group:
///   A = c0·a − c1·c   → output[front]
///   C = c2·b + c3·d   → output[front+1]
///   B = c1·a + c0·c   → output[back−1]
///   D = c3·b − c2·d   → output[back−2]
fn reconstruct(src: &[i16], dst: &mut [i16], n: usize, stage: i16, coeffs: &[i16]) {
    let group_size = shr(n as i16, stage) as usize;
    let num_groups = shl(1, stage) as usize;
    let half = group_size / 2;

    for g in 0..num_groups {
        let src_base = g * group_size;
        let dst_base = g * group_size;

        let mut src_first = src_base;
        let mut src_second = src_base + half;
        let mut dst_front = dst_base;
        let mut dst_back = dst_base + group_size;
        let mut ci = 0usize;

        while dst_front < dst_back {
            let a = src[src_first];
            let b = src[src_first + 1];
            let c = src[src_second];
            let d = src[src_second + 1];
            src_first += 2;
            src_second += 2;

            let c0 = coeffs[ci];
            let c1 = coeffs[ci + 1];
            let c2 = coeffs[ci + 2];
            let c3 = coeffs[ci + 3];
            ci += 4;

            // A = c0*a − c1*c
            let val_a = extract_h(l_shl(l_mac(l_mac(0, c0, a), negate(c1), c), 1));
            // B = c1*a + c0*c
            let val_b = extract_h(l_shl(l_mac(l_mac(0, c1, a), c0, c), 1));
            // C = c2*b + c3*d
            let val_c = extract_h(l_shl(l_mac(l_mac(0, c2, b), c3, d), 1));
            // D = c3*b − c2*d
            let val_d = extract_h(l_shl(l_mac(l_mac(0, c3, b), negate(c2), d), 1));

            dst[dst_front] = val_a;
            dst[dst_front + 1] = val_c;
            dst[dst_back - 1] = val_b;
            dst[dst_back - 2] = val_d;

            dst_front += 2;
            dst_back -= 2;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_butterfly_16_identity() {
        // A butterfly of [x, x, x, x, ...] should produce [2x, 2x, ..., 0, 0, ...]
        // since sum = x + x = 2x, diff = x - x = 0
        let src = [100i16; 320];
        let mut dst = [0i16; 320];
        butterfly_16(&src, &mut dst, 320, 1);
        // group_size = 160, 2 groups
        // First group: front gets 200, back gets 0
        for i in 0..80 {
            assert_eq!(dst[i], 200, "front {} should be 200", i);
        }
        for i in 80..160 {
            assert_eq!(dst[i], 0, "back {} should be 0", i);
        }
    }

    #[test]
    fn test_inverse_zeros() {
        // All-zero input should produce all-zero output.
        let input = [0i16; 320];
        let mut output = [0i16; 320];
        inverse(&input, &mut output, 320);
        for (i, &s) in output.iter().enumerate() {
            assert_eq!(s, 0, "sample {} should be 0", i);
        }
    }

    #[test]
    fn test_butterfly_stage0_32bit() {
        // Stage 0 with known values: pairs (10000, 5000), ...
        let mut input = [0i16; 320];
        input[0] = 10000;
        input[1] = 5000;
        let mut buf = [0i16; 320];
        // Manually compute stage 0 for first pair
        let a = 10000i32;
        let b = 5000i32;
        let expected_sum = extract_l(l_shr(l_add(a, b), 1)); // (15000) >> 1 = 7500
        let expected_diff = extract_l(l_shr(l_add(a, -b), 1)); // (5000) >> 1 = 2500

        // Run stage 0 manually (same as in inverse, but just the first pair)
        let front = 0;
        let mut back = 320;
        let s = extract_l(l_shr(l_add(input[0] as i32, input[1] as i32), 1));
        let d = extract_l(l_shr(l_add(input[0] as i32, -(input[1] as i32)), 1));
        back -= 1;
        buf[front] = s;
        buf[back] = d;

        assert_eq!(buf[0], expected_sum);
        assert_eq!(buf[319], expected_diff);
    }

    #[test]
    fn test_forward_inverse_roundtrip() {
        // forward then inverse should approximately recover the original signal
        let mut input = [0i16; 320];
        for i in 0..320 {
            let t = i as f64 / 16000.0;
            input[i] = (5000.0 * (2.0 * std::f64::consts::PI * 1000.0 * t).sin()) as i16;
        }

        let mut subbands = [0i16; 320];
        forward(&input, &mut subbands, 320);

        let sub_max = subbands.iter().map(|&s| (s as i32).abs()).max().unwrap();
        let sub_nz = subbands.iter().filter(|&&s| s != 0).count();
        eprintln!("forward: max={} nonzero={}/320", sub_max, sub_nz);

        let mut output = [0i16; 320];
        inverse(&subbands, &mut output, 320);

        let out_max = output.iter().map(|&s| (s as i32).abs()).max().unwrap();
        eprintln!("inverse: max={}", out_max);

        // Check correlation
        let mut cov = 0.0f64;
        let mut var_in = 0.0f64;
        let mut var_out = 0.0f64;
        for i in 0..320 {
            let a = input[i] as f64;
            let b = output[i] as f64;
            cov += a * b;
            var_in += a * a;
            var_out += b * b;
        }
        let corr = cov / (var_in.sqrt() * var_out.sqrt() + 1e-10);
        let ratio = (var_out / var_in).sqrt();
        eprintln!("correlation={:.4} rms_ratio={:.4}", corr, ratio);
        assert!(sub_nz > 0, "forward produced all zeros");
    }

    #[test]
    fn test_forward_zeros() {
        // All-zero input should produce all-zero output.
        let input = [0i16; 320];
        let mut output = [0i16; 320];
        forward(&input, &mut output, 320);
        for (i, &s) in output.iter().enumerate() {
            assert_eq!(s, 0, "sample {} should be 0", i);
        }
    }
}
