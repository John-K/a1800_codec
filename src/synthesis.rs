/// Synthesis filter for the A1800 audio codec.
///
/// Applies inverse filterbank, scaling, and windowed overlap-add.
/// Matches `synthesis_filter` / `FUN_10001b60` at address 0x10001b60 in the DLL.

use crate::filterbank;
use crate::fixedpoint::*;
use crate::tables::SYNTH_OVERLAP_OFFSETS;

/// Synthesize one frame of PCM output from subband samples.
///
/// - `subband_samples`: decoded subband data (320 i16 values)
/// - `memory`: overlap-add state buffer (160 i16 values, persists across frames)
/// - `output`: destination for PCM samples (320 i16 values)
/// - `frame_size`: number of samples per frame (320)
/// - `scale_param`: per-frame scaling exponent from the gain decoder
pub fn synthesize(
    subband_samples: &[i16],
    memory: &mut [i16],
    output: &mut [i16],
    frame_size: i16,
    scale_param: i16,
) {
    let n = frame_size as usize;
    let half = shr(frame_size, 1) as usize; // 160
    let mut filtered = [0i16; 320];

    // Step 1: Inverse filterbank
    filterbank::inverse(subband_samples, &mut filtered, frame_size);

    // Step 2: Apply scaling
    if scale_param > 0 {
        for i in 0..n {
            filtered[i] = shr(filtered[i], scale_param);
        }
    } else if scale_param < 0 {
        let shift = negate(scale_param);
        for i in 0..n {
            filtered[i] = shl(filtered[i], shift);
        }
    }

    // Step 3: First half output (samples 0..half)
    // output[k] = extract_h(L_shl(
    //   L_mac(L_mac(0, SYNTH[k], filtered[half-1-k]), SYNTH[n-1-k], memory[k]),
    // 2))
    for k in 0..half {
        let acc = l_mac(0, SYNTH_OVERLAP_OFFSETS[k], filtered[half - 1 - k]);
        let acc = l_mac(acc, SYNTH_OVERLAP_OFFSETS[n - 1 - k], memory[k]);
        output[k] = extract_h(l_shl(acc, 2));
    }

    // Step 4: Second half output (samples half..n)
    // output[half+k] = extract_h(L_shl(
    //   L_mac(L_mac(0, SYNTH[half+k], filtered[k]), negate(SYNTH[half-1-k]), memory[half-1-k]),
    // 2))
    for k in 0..half {
        let acc = l_mac(0, SYNTH_OVERLAP_OFFSETS[half + k], filtered[k]);
        let acc = l_mac(acc, negate(SYNTH_OVERLAP_OFFSETS[half - 1 - k]), memory[half - 1 - k]);
        output[half + k] = extract_h(l_shl(acc, 2));
    }

    // Step 5: Update memory — second half of filtered becomes next frame's overlap
    memory[..half].copy_from_slice(&filtered[half..half + half]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_synthesize_zeros() {
        let subband = [0i16; 320];
        let mut memory = [0i16; 160];
        let mut output = [0i16; 320];
        synthesize(&subband, &mut memory, &mut output, 320, 0);
        for (i, &s) in output.iter().enumerate() {
            assert_eq!(s, 0, "sample {} should be 0", i);
        }
    }

    #[test]
    fn test_memory_update() {
        // After synthesis, memory should contain filtered[160..320].
        // With zero input and zero memory, filtered is all zeros,
        // so memory stays zero.
        let subband = [0i16; 320];
        let mut memory = [0i16; 160];
        let mut output = [0i16; 320];
        synthesize(&subband, &mut memory, &mut output, 320, 0);
        for (i, &m) in memory.iter().enumerate() {
            assert_eq!(m, 0, "memory[{}] should be 0", i);
        }
    }
}
