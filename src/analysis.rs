/// Analysis filter for the A1800 audio codec encoder.
///
/// Encode-side counterpart of synthesis.rs.
/// Applies windowed overlap, scaling, and forward filterbank.
/// Matches `analysis_filter` at 0x10004ba0 in the DLL.

use crate::filterbank;
use crate::fixedpoint::*;
use crate::tables::ANALYSIS_WINDOW;

/// Analyze one frame of PCM input into subband samples.
///
/// - `pcm_input`: 320 PCM samples
/// - `memory`: overlap state buffer (320 i16, persists across frames)
/// - `subband_output`: destination for subband samples (320 i16)
/// - `frame_size`: number of samples per frame (320)
///
/// Returns `scale_param` — the per-frame scaling exponent.
pub fn analysis_filter(
    pcm_input: &[i16],
    memory: &mut [i16],
    subband_output: &mut [i16],
    frame_size: i16,
) -> i16 {
    let n = frame_size as usize;
    let half = shr(frame_size, 1) as usize; // 160
    let mut windowed = [0i16; 320];

    // Step 1: Windowed overlap
    // Matches DLL analysis_filter. Note: DLL uses extract_h(acc) without L_shl.
    //
    // DLL first loop: iterates backward through window and memory, combining
    // window[half+k-1] * memory[...] pairs. The pointer arithmetic is complex
    // but the structure is: for each output sample, multiply two pairs of
    // window coefficients with memory/input samples.
    //
    // For first frame (memory=zeros), first half produces all zeros.
    // Second half uses pcm_input directly.
    for k in 0..half {
        let acc = l_mac(0, ANALYSIS_WINDOW[half - 1 - k], memory[half - 1 - k]);
        let acc = l_mac(acc, ANALYSIS_WINDOW[half + k], memory[half + k]);
        windowed[k] = extract_h(acc);
    }

    // DLL second loop: combines window coefficients with pcm_input
    // DLL pointer trace (psVar15 walks ANALYSIS_WINDOW backward from [n-1],
    // psVar16 walks forward from [0]):
    //   windowed[half+k] = extract_h(L_mac(L_mac(0, WINDOW[n-1-k], pcm[k]),
    //                                       negate(WINDOW[k]), pcm[n-1-k]))
    for k in 0..half {
        let acc = l_mac(0, ANALYSIS_WINDOW[n - 1 - k], pcm_input[k]);
        let neg = negate(ANALYSIS_WINDOW[k]);
        let acc = l_mac(acc, neg, pcm_input[n - 1 - k]);
        windowed[half + k] = extract_h(acc);
    }

    // Step 2: Copy ALL input into memory for next frame's overlap
    // DLL copies param_4 (320) shorts from pcm_input to memory
    memory[..n].copy_from_slice(&pcm_input[..n]);

    // Step 3: Find max |sample| and compute scale_param
    // Matches DLL analysis_filter at 0x10004ba0
    let mut max_abs: i16 = 0;
    for i in 0..n {
        let a = abs_s(windowed[i]);
        if sub(a, max_abs) > 0 {
            max_abs = a;
        }
    }

    let mut scale_param = if sub(max_abs, 14000) >= 0 {
        // Large amplitude → no prescaling needed
        0
    } else {
        // Small amplitude → compute prescaling exponent
        let adj = if sub(max_abs, 0x1b6) < 0 {
            add(max_abs, 1)
        } else {
            max_abs
        };
        let product = l_mult(adj, 0x2573); // multiply by 9587
        let shifted = l_shr(product, 0x14); // shift right 20
        let val = extract_l(shifted);
        let norm_val = norm_s(val);
        if norm_val == 0 {
            9
        } else {
            sub(norm_val, 6)
        }
    };

    // Step 3b: Check if sum of |samples| >> 7 exceeds max_abs → decrement
    let mut sum_abs: i32 = 0;
    for i in 0..n {
        let a = abs_s(windowed[i]);
        sum_abs = l_add(sum_abs, a as i32);
    }
    let sum_shifted = l_shr(sum_abs, 7);
    if (max_abs as i32) < sum_shifted {
        scale_param = sub(scale_param, 1);
    }

    // Step 4: Apply scaling to windowed buffer
    if scale_param > 0 {
        for i in 0..n {
            windowed[i] = shl(windowed[i], scale_param);
        }
    } else if scale_param < 0 {
        let shift = negate(scale_param);
        for i in 0..n {
            windowed[i] = shr(windowed[i], shift);
        }
    }

    // Step 5: Forward filterbank to produce subbands
    filterbank::forward(&windowed, subband_output, frame_size);

    scale_param
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_zeros() {
        let pcm = [0i16; 320];
        let mut memory = [0i16; 320];
        let mut output = [0i16; 320];
        let sp = analysis_filter(&pcm, &mut memory, &mut output, 320);
        assert_eq!(sp, 9); // max_abs == 0 => sp = 9
        for (i, &s) in output.iter().enumerate() {
            assert_eq!(s, 0, "subband[{}] should be 0", i);
        }
    }
}
