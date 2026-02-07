/// A1800 codec frame decoder.
///
/// Implements the decode pipeline: gain decode -> bit allocation -> subframe decode.
/// Matches the original DLL functions at addresses 0x10002ca0-0x10003870.

use crate::bitstream::BitstreamReader;
use crate::fixedpoint::*;
use crate::tables::*;

const MAX_SUBBANDS: usize = 14;
const SAMPLES_PER_SUBBAND: usize = 20;
pub const FRAME_SIZE: usize = 320;

/// Noise gain constants for steps 5, 6, 7 (local_14 in decode_subframes).
const NOISE_GAINS: [i16; 3] = [0x16a1, 0x2000, 0x5a82];

/// Decoder state persisting across frames.
pub struct DecoderState {
    pub bitrate: u16,
    pub bits_per_frame: i16,
    pub encoded_frame_size: i16,
    pub num_subbands: i16,
    pub prng_state: [i16; 4],
    pub synth_memory: [i16; 320],
    pub filterbank_memory: [i16; 640],
}

impl DecoderState {
    /// Initialize decoder for the given bitrate.
    /// Matches `a1800_dec_frame_init` at 0x10002ca0.
    pub fn new(bitrate: u16) -> Result<Self, u32> {
        let (validated, err) = if bitrate < 4800 || bitrate > 32000 {
            (16000u16, 8u32)
        } else {
            let snapped = ((bitrate as u32 + 400) / 800 * 800) as u16;
            if snapped != bitrate {
                (snapped, 8)
            } else {
                (bitrate, 0)
            }
        };

        let bits_per_frame = (validated as i32 / 50) as i16;
        let encoded_frame_size = (validated as i32 / 800) as i16;
        let num_subbands = if validated >= 16000 {
            14
        } else if validated >= 12000 {
            12
        } else if validated >= 9600 {
            10
        } else {
            8
        };

        let state = DecoderState {
            bitrate: validated,
            bits_per_frame,
            encoded_frame_size,
            num_subbands,
            prng_state: [1, 1, 1, 1],
            synth_memory: [0; 320],
            filterbank_memory: [0; 640],
        };

        if err != 0 {
            Err(err)
        } else {
            Ok(state)
        }
    }

    /// Decode one frame of encoded data into subband-domain samples.
    /// Returns the scale parameter for synthesis.
    pub fn decode_frame_to_subbands(
        &mut self,
        input: &[i16],
        output: &mut [i16; FRAME_SIZE],
    ) -> i16 {
        let mut bs = BitstreamReader::new(input, self.bits_per_frame);
        let mut scale_param: i16 = 0;
        self.decode_frame_params(&mut bs, output, &mut scale_param);
        scale_param
    }

    /// Main frame parameter decoder.
    /// Matches `decode_frame_params` at 0x10002f60.
    fn decode_frame_params(
        &mut self,
        bs: &mut BitstreamReader,
        output: &mut [i16; FRAME_SIZE],
        scale_param: &mut i16,
    ) {
        let ns = self.num_subbands as usize;
        let total_samples = ns * SAMPLES_PER_SUBBAND;

        let mut gains = [0i16; MAX_SUBBANDS];
        let mut scale_factors = [0i16; MAX_SUBBANDS];

        self.decode_gains(bs, ns, &mut scale_factors, &mut gains, scale_param);

        // Read 4-bit frame parameter
        let frame_param = bs.read_bits(4);
        bs.total_bits_remaining = sub(bs.total_bits_remaining, 4);

        // Compute bit allocation
        let mut alloc = [0i16; MAX_SUBBANDS];
        let mut scratch = [0i16; 32];
        let remaining = bs.total_bits_remaining;
        Self::compute_bit_alloc_for_frame(
            remaining,
            self.num_subbands,
            &gains[..ns],
            &mut alloc[..ns],
            &mut scratch,
        );

        // Apply frame parameter adjustments
        Self::increment_allocation_bins(frame_param, &mut alloc, &scratch);

        // Decode subframe samples
        self.decode_subframes(bs, ns, &scale_factors, &mut alloc, output);

        // Zero remaining samples beyond active subbands
        for s in output[total_samples..FRAME_SIZE].iter_mut() {
            *s = 0;
        }
    }

    /// Decode subband gains and scale factors.
    /// Matches `decode_lsp_and_gains` at 0x10003050.
    fn decode_gains(
        &self,
        bs: &mut BitstreamReader,
        num_subbands: usize,
        scale_factors_out: &mut [i16; MAX_SUBBANDS],
        gains_out: &mut [i16; MAX_SUBBANDS],
        scale_param: &mut i16,
    ) {
        // Read 5-bit initial gain index
        let initial_index = bs.read_bits(5);
        bs.total_bits_remaining = sub(bs.total_bits_remaining, 5);
        let initial_gain = sub(initial_index, 7);

        // Huffman decode differential gains for remaining subbands
        let mut differentials = [0i16; MAX_SUBBANDS];
        if num_subbands > 1 {
            let mut tree_base: usize = 23;
            for d in 0..(num_subbands - 1) {
                let mut node: i16 = 0;
                loop {
                    bs.read_bit();
                    let entry = node as usize + tree_base;
                    node = if bs.last_bit == 0 {
                        GAIN_HUFFMAN_TREE[entry][0]
                    } else {
                        GAIN_HUFFMAN_TREE[entry][1]
                    };
                    bs.total_bits_remaining = sub(bs.total_bits_remaining, 1);
                    if node <= 0 {
                        break;
                    }
                }
                differentials[d] = negate(node);
                tree_base += 23;
            }
        }

        // Set first gain
        gains_out[0] = initial_gain;

        // Cumulative gains: gain[i+1] = gain[i] + differential[i] - 12
        for i in 0..(num_subbands - 1) {
            let sum = l_add(gains_out[i] as i32, differentials[i] as i32);
            let sum2 = l_add(sum, -12);
            gains_out[i + 1] = extract_l(sum2);
        }

        // Compute total cost and max effective gain
        let mut total_cost: i16 = 0;
        let mut max_eff_gain: i16 = 0;
        for i in 0..num_subbands {
            let eff = l_add(gains_out[i] as i32, 0x18);
            let eff_i16 = extract_l(eff);
            let diff = sub(eff_i16, max_eff_gain);
            if diff > 0 {
                max_eff_gain = eff_i16;
            }
            total_cost = add(total_cost, SCALE_FACTOR_BITS[eff_i16 as usize]);
        }

        // Find scale parameter via iterative reduction
        let mut sp: i16 = 9;
        let mut cost_check = sub(total_cost, 8);
        let mut gain_check = sub(max_eff_gain, 0x1c);
        loop {
            if cost_check < 0 && gain_check < 1 {
                break;
            }
            sp = sub(sp, 1);
            total_cost = shr(total_cost, 1);
            max_eff_gain = sub(max_eff_gain, 2);
            cost_check = sub(total_cost, 8);
            gain_check = sub(max_eff_gain, 0x1c);
            if sp < 0 {
                break;
            }
        }
        *scale_param = sp;

        // Compute final per-subband scale factors
        let offset = (sp * 2 + 0x18) as i16;
        for i in 0..num_subbands {
            let idx = l_add(gains_out[i] as i32, offset as i32);
            let idx_i16 = extract_l(idx);
            scale_factors_out[i] = SCALE_FACTOR_BITS[idx_i16 as usize];
        }
    }

    /// Compute bit allocation for frame.
    /// Matches `compute_bit_alloc_for_frame` at 0x10001d30.
    fn compute_bit_alloc_for_frame(
        remaining_bits: i16,
        num_subbands: i16,
        gains: &[i16],
        alloc: &mut [i16],
        scratch: &mut [i16],
    ) {
        let budget = if sub(remaining_bits, 0x140) > 0 {
            let excess = sub(remaining_bits, 0x140);
            let scaled = l_mult0(excess, 5);
            let reduced = shr(extract_l(scaled), 3);
            add(reduced, 0x140)
        } else {
            remaining_bits
        };

        let threshold = Self::search_threshold(gains, num_subbands, budget);
        Self::compute_allocation(alloc, gains, num_subbands, threshold);
        Self::optimize_allocation(alloc, scratch, gains, budget, num_subbands, 16, threshold);
    }

    /// Binary search for bit allocation threshold.
    /// Matches `search_bit_allocation_threshold` at 0x100020f0.
    fn search_threshold(gains: &[i16], num_subbands: i16, budget: i16) -> i16 {
        let ns = num_subbands as usize;
        let mut thresh: i16 = -32;
        let mut step: i16 = 32;

        loop {
            let candidate = add(thresh, step);
            let mut local_alloc = [0i16; MAX_SUBBANDS];

            for i in 0..ns {
                let diff = sub(candidate, gains[i]);
                let mut q = shr(diff, 1);
                if q < 0 {
                    q = 0;
                }
                if sub(q, 7) > 0 {
                    q = sub(8, 1);
                }
                local_alloc[i] = q;
            }

            let mut cost: i16 = 0;
            for i in 0..ns {
                cost = add(cost, BIT_ALLOC_COST[local_alloc[i] as usize]);
            }

            let target = sub(budget, 0x20);
            let slack = sub(cost, target);
            if slack >= 0 {
                thresh = candidate;
            }

            step = shr(step, 1);
            if step <= 0 {
                break;
            }
        }

        thresh
    }

    /// Compute per-subband allocation from threshold and gains.
    /// Matches `compute_bit_allocation` at 0x10002200.
    fn compute_allocation(alloc: &mut [i16], gains: &[i16], num_subbands: i16, threshold: i16) {
        for i in 0..(num_subbands as usize) {
            let diff = sub(threshold, gains[i]);
            let mut q = shr(diff, 1);
            if q < 0 {
                q = 0;
            }
            if sub(q, 7) > 0 {
                q = sub(8, 1);
            }
            alloc[i] = q;
        }
    }

    /// Greedy bit allocation optimization.
    /// Matches `optimize_bit_allocation` at 0x10001dc0.
    fn optimize_allocation(
        alloc: &mut [i16],
        scratch: &mut [i16],
        gains: &[i16],
        budget: i16,
        num_subbands: i16,
        num_iterations: i16,
        threshold: i16,
    ) {
        let ns = num_subbands as usize;

        // Compute initial cost
        let mut inc_cost: i16 = 0;
        for i in 0..ns {
            inc_cost = add(inc_cost, BIT_ALLOC_COST[alloc[i] as usize]);
        }

        // Working copies
        let mut dec_alloc = [0i16; MAX_SUBBANDS];
        let mut inc_alloc = [0i16; MAX_SUBBANDS];
        for i in 0..ns {
            dec_alloc[i] = alloc[i];
            inc_alloc[i] = alloc[i];
        }

        let mut dec_cost = inc_cost;
        let max_iter = num_iterations - 1;
        let mut low_idx = num_iterations;
        let mut high_idx = num_iterations;
        let mut swap_log = [0i16; 32];

        for _ in 0..max_iter {
            let total = add(dec_cost, inc_cost);
            let doubled_budget = shl(budget, 1);
            let balance = sub(total, doubled_budget);

            if balance < 1 {
                // Under budget: decrease one subband
                let mut best_idx: i16 = 0;
                let mut best_metric: i16 = 99;
                let mut idx: i16 = 0;
                for i in 0..ns {
                    if dec_alloc[i] > 0 {
                        let step_x2 = shl(dec_alloc[i], 1);
                        let diff = sub(threshold, gains[i]);
                        let metric = sub(diff, step_x2);
                        let cmp = sub(metric, best_metric);
                        if cmp < 0 {
                            best_idx = idx;
                            best_metric = metric;
                        }
                    }
                    idx += 1;
                }
                low_idx = sub(low_idx, 1);
                swap_log[low_idx as usize] = best_idx;

                let old_step = dec_alloc[best_idx as usize];
                dec_cost = sub(dec_cost, BIT_ALLOC_COST[old_step as usize]);
                dec_alloc[best_idx as usize] = sub(old_step, 1);
                let new_step = dec_alloc[best_idx as usize];
                dec_cost = add(dec_cost, BIT_ALLOC_COST[new_step as usize]);
            } else {
                // Over budget: increase one subband
                let mut best_idx: i16 = 0;
                let mut best_metric: i16 = -99;
                let mut idx = sub(num_subbands, 1);
                while idx >= 0 {
                    let i = idx as usize;
                    if sub(inc_alloc[i], 7) < 0 {
                        let step_x2 = shl(inc_alloc[i], 1);
                        let diff = sub(threshold, gains[i]);
                        let metric = sub(diff, step_x2);
                        let cmp = sub(metric, best_metric);
                        if cmp > 0 {
                            best_metric = metric;
                            best_idx = idx;
                        }
                    }
                    idx -= 1;
                }
                swap_log[high_idx as usize] = best_idx;
                high_idx = add(high_idx, 1);

                let old_step = inc_alloc[best_idx as usize];
                if sub(old_step, 7) < 0 {
                    inc_cost = sub(inc_cost, BIT_ALLOC_COST[old_step as usize]);
                    inc_alloc[best_idx as usize] = add(old_step, 1);
                    let new_step = inc_alloc[best_idx as usize];
                    inc_cost = add(inc_cost, BIT_ALLOC_COST[new_step as usize]);
                }
            }
        }

        // Copy decrease allocation to output
        for i in 0..ns {
            alloc[i] = dec_alloc[i];
        }

        // Copy swap log to scratch buffer
        let mut out_idx: i16 = 0;
        let mut log_idx = low_idx;
        while out_idx < max_iter {
            scratch[out_idx as usize] = swap_log[log_idx as usize];
            log_idx += 1;
            out_idx += 1;
        }
    }

    /// Apply frame parameter to adjust allocation.
    /// Matches `increment_allocation_bins` at 0x10003290.
    fn increment_allocation_bins(count: i16, alloc: &mut [i16], scratch: &[i16]) {
        let mut remaining = count;
        let mut idx = 0usize;
        while remaining > 0 {
            let subband = scratch[idx] as usize;
            alloc[subband] = add(alloc[subband], 1);
            idx += 1;
            remaining = sub(remaining, 1);
        }
    }

    /// Decode subframe samples for all subbands.
    /// Matches `decode_subframes` at 0x100032e0.
    fn decode_subframes(
        &mut self,
        bs: &mut BitstreamReader,
        num_subbands: usize,
        scale_factors: &[i16; MAX_SUBBANDS],
        alloc: &mut [i16; MAX_SUBBANDS],
        output: &mut [i16; FRAME_SIZE],
    ) {
        let mut error = false;

        for sb in 0..num_subbands {
            let step = alloc[sb];
            let scale = scale_factors[sb];
            let out_base = sb * SAMPLES_PER_SUBBAND;

            // Initialize output for this subband to zero
            for k in 0..SAMPLES_PER_SUBBAND {
                output[out_base + k] = 0;
            }

            if sub(step, 7) < 0 && !error {
                // Codebook decode path (steps 0-6)
                let tree = codebook_tree(step);
                let num_subframes = QUANT_NUM_COEFF[step as usize];
                let num_levels = QUANT_LEVELS_M1[step as usize];

                if num_subframes >= 1 {
                    let mut out_pos = out_base;
                    let mut sf = 0i16;

                    'subframe_loop: while sf < num_subframes {
                        // Check bits before Huffman decode
                        if bs.total_bits_remaining < 1 {
                            error = true;
                            self.set_error_state(sb, num_subbands, alloc);
                            break;
                        }

                        // Huffman tree decode
                        let mut node: i16 = 0;
                        loop {
                            if bs.total_bits_remaining < 1 {
                                error = true;
                                self.set_error_state(sb, num_subbands, alloc);
                                // Zero current subband
                                for k in 0..SAMPLES_PER_SUBBAND {
                                    output[out_base + k] = 0;
                                }
                                break 'subframe_loop;
                            }
                            bs.read_bit();
                            let child = if bs.last_bit == 0 {
                                tree[(node as usize) * 2]
                            } else {
                                tree[(node as usize) * 2 + 1]
                            };
                            node = child;
                            bs.total_bits_remaining =
                                sub(bs.total_bits_remaining, 1);
                            if child <= 0 {
                                break;
                            }
                        }

                        if error {
                            break;
                        }

                        let symbol = negate(node);

                        // Inverse quantize
                        let mut digits = [0i16; 6];
                        let num_nonzero = inverse_quantize(symbol, &mut digits, step);

                        // Check bit budget for sign bits
                        if sub(bs.total_bits_remaining, num_nonzero) < 0 {
                            error = true;
                            self.set_error_state(sb, num_subbands, alloc);
                            for k in 0..SAMPLES_PER_SUBBAND {
                                output[out_base + k] = 0;
                            }
                            break;
                        }

                        // Read sign bits
                        let mut sign_bits: i16 = 0;
                        let mut sign_mask: i16 = 0;
                        if num_nonzero != 0 {
                            for _ in 0..num_nonzero {
                                bs.read_bit();
                                sign_bits = add(shl(sign_bits, 1), bs.last_bit);
                                bs.total_bits_remaining =
                                    sub(bs.total_bits_remaining, 1);
                            }
                            sign_mask = shl(1, sub(num_nonzero, 1));
                        }

                        // Reconstruct samples
                        if num_levels > 0 {
                            for j in 0..(num_levels as usize) {
                                let recon =
                                    QUANT_RECON_LEVELS[step as usize][digits[j] as usize];
                                let product = l_mult0(scale, recon);
                                let shifted = l_shr(product, 12);
                                let mut sample = extract_l(shifted);

                                if sample != 0 {
                                    if (sign_mask as u16 & sign_bits as u16) == 0 {
                                        sample = negate(sample);
                                    }
                                    sign_mask = shr(sign_mask, 1);
                                }

                                output[out_pos] = sample;
                                out_pos += 1;
                            }
                        }

                        sf += 1;
                    }
                }
            } else if error {
                // Already in error state: set this subband to step 7
                alloc[sb] = 7;
            }

            // Noise fill for steps 5 and 6 (conditional: only zero samples)
            let current_step = alloc[sb];
            if current_step == 5 || current_step == 6 {
                let gain_idx = (current_step - 5) as usize;
                let noise_level = mult(scale, NOISE_GAINS[gain_idx]);
                let neg_noise = negate(noise_level);

                let mut prng_val = noise_prng(&mut self.prng_state);
                for k in 0..10 {
                    let pos = out_base + k;
                    if output[pos] == 0 {
                        output[pos] = if (prng_val as u16 & 1) != 0 {
                            noise_level
                        } else {
                            neg_noise
                        };
                        prng_val = shr(prng_val, 1);
                    }
                }
                prng_val = noise_prng(&mut self.prng_state);
                for k in 10..20 {
                    let pos = out_base + k;
                    if output[pos] == 0 {
                        output[pos] = if (prng_val as u16 & 1) != 0 {
                            noise_level
                        } else {
                            neg_noise
                        };
                        prng_val = shr(prng_val, 1);
                    }
                }
            }

            // Noise fill for step 7 (unconditional: all samples)
            if current_step == 7 {
                let gain_idx = (current_step - 5) as usize; // = 2
                let noise_level = mult(scale, NOISE_GAINS[gain_idx]);
                let neg_noise = negate(noise_level);

                let mut prng_val = noise_prng(&mut self.prng_state);
                for k in 0..10 {
                    let pos = out_base + k;
                    output[pos] = if (prng_val as u16 & 1) != 0 {
                        noise_level
                    } else {
                        neg_noise
                    };
                    prng_val = shr(prng_val, 1);
                }
                prng_val = noise_prng(&mut self.prng_state);
                for k in 10..20 {
                    let pos = out_base + k;
                    output[pos] = if (prng_val as u16 & 1) != 0 {
                        noise_level
                    } else {
                        neg_noise
                    };
                    prng_val = shr(prng_val, 1);
                }
            }
        }

        // Post-error adjustment
        if error {
            bs.total_bits_remaining = sub(bs.total_bits_remaining, 1);
        }
    }

    /// Set error state: mark remaining subbands as step 7.
    fn set_error_state(&self, current_sb: usize, num_subbands: usize, alloc: &mut [i16; MAX_SUBBANDS]) {
        let next_sb = current_sb + 1;
        if next_sb < num_subbands {
            for i in next_sb..num_subbands {
                alloc[i] = 7;
            }
        }
        alloc[current_sb] = 7;
    }
}

/// 4-tap PRNG for noise fill.
/// Matches `noise_prng` at 0x10003870.
fn noise_prng(state: &mut [i16; 4]) -> i16 {
    let sum = l_add(state[0] as i32, state[3] as i32);
    let mut val = extract_l(sum);
    if (val as u16) & 0x8000 != 0 {
        val = add(val, 1);
    }
    state[3] = state[2];
    state[2] = state[1];
    state[1] = state[0];
    state[0] = val;
    val
}

/// Decompose a Huffman symbol into quantizer digits.
/// Returns the count of nonzero digits.
/// Matches `inverse_quantize` at 0x10003760.
fn inverse_quantize(symbol: i16, digits: &mut [i16], step: i16) -> i16 {
    let si = step as usize;
    let mut nonzero: i16 = 0;
    let divisor = add(QUANT_INV_STEP[si], 1);
    let step_size = QUANT_STEP_SIZE[si];
    let num_digits = sub(QUANT_LEVELS_M1[si], 1);

    if num_digits >= 0 {
        let count = (num_digits + 1) as usize;
        let mut val = symbol;
        for j in (0..count).rev() {
            let quotient = mult(val, step_size);
            let product = l_mult0(quotient, divisor);
            let prod_lo = extract_l(product);
            let remainder = sub(val, prod_lo);
            digits[j] = remainder;
            if remainder != 0 {
                nonzero = add(nonzero, 1);
            }
            val = quotient;
        }
        return nonzero;
    }
    0
}

/// Select codebook tree for the given quantizer step (0-6).
fn codebook_tree(step: i16) -> &'static [i16] {
    match step {
        0 => &CODEBOOK_TREE_0,
        1 => &CODEBOOK_TREE_1,
        2 => &CODEBOOK_TREE_2,
        3 => &CODEBOOK_TREE_3,
        4 => &CODEBOOK_TREE_4,
        5 => &CODEBOOK_TREE_5,
        6 => &CODEBOOK_TREE_6,
        _ => &CODEBOOK_TREE_0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decoder_init() {
        let dec = DecoderState::new(16000).unwrap();
        assert_eq!(dec.bits_per_frame, 320);
        assert_eq!(dec.encoded_frame_size, 20);
        assert_eq!(dec.num_subbands, 14);
    }

    #[test]
    fn test_decoder_init_snap() {
        let result = DecoderState::new(16400);
        assert!(result.is_err());
    }

    #[test]
    fn test_decoder_init_subbands() {
        assert_eq!(DecoderState::new(8000).unwrap().num_subbands, 8);
        assert_eq!(DecoderState::new(9600).unwrap().num_subbands, 10);
        assert_eq!(DecoderState::new(12000).unwrap().num_subbands, 12);
        assert_eq!(DecoderState::new(16000).unwrap().num_subbands, 14);
    }

    #[test]
    fn test_noise_prng() {
        let mut state: [i16; 4] = [1, 1, 1, 1];
        let v1 = noise_prng(&mut state);
        assert_eq!(v1, 2);
        assert_eq!(state, [2, 1, 1, 1]);

        let v2 = noise_prng(&mut state);
        assert_eq!(v2, 3);
        assert_eq!(state, [3, 2, 1, 1]);
    }

    #[test]
    fn test_inverse_quantize_step0() {
        let mut digits = [0i16; 6];
        let nz = inverse_quantize(5, &mut digits, 0);
        // Step 0: QUANT_LEVELS_M1[0]=2 -> 2 digits
        // QUANT_INV_STEP[0]=13, divisor=14
        // QUANT_STEP_SIZE[0]=2341
        // digit[1] = 5 - mult(5, 2341)*14
        // mult(5, 2341) = (5*2341)>>15 = 11705>>15 = 0
        // So digit[1] = 5 - 0 = 5, digit[0] = 0
        assert_eq!(digits[1], 5);
        assert_eq!(digits[0], 0);
        assert_eq!(nz, 1);
    }

    #[test]
    fn test_compute_allocation() {
        let gains = [10i16, 8, 6, 4, 2, 0, -2, -4];
        let mut alloc = [0i16; 8];
        DecoderState::compute_allocation(&mut alloc, &gains, 8, 10);
        assert_eq!(alloc[0], 0); // (10-10)/2 = 0
        assert_eq!(alloc[7], 7); // (10-(-4))/2 = 7
    }
}
