/// ITU-T G.729-style fixed-point basic operations.
///
/// These match the original A1800.DLL implementation exactly for bit-exact decoding.
/// All operations use i16 (Word16) and i32 (Word32) with saturation semantics.

const MAX_16: i32 = 0x7FFF;
const MIN_16: i32 = -0x8000;
const MAX_32: i32 = 0x7FFF_FFFF;
const MIN_32: i32 = -0x8000_0000i32;

/// Clamp a 32-bit value to the i16 range [-32768, 32767].
#[inline(always)]
pub fn saturate(val: i32) -> i16 {
    if val > MAX_16 {
        MAX_16 as i16
    } else if val < MIN_16 {
        MIN_16 as i16
    } else {
        val as i16
    }
}

/// Saturating 16-bit addition.
#[inline(always)]
pub fn add(a: i16, b: i16) -> i16 {
    saturate(a as i32 + b as i32)
}

/// Saturating 16-bit subtraction.
#[inline(always)]
pub fn sub(a: i16, b: i16) -> i16 {
    saturate(a as i32 - b as i32)
}

/// Absolute value with saturation (abs(-32768) = 32767).
#[inline(always)]
pub fn abs_s(val: i16) -> i16 {
    if val == MIN_16 as i16 {
        MAX_16 as i16
    } else if val < 0 {
        -val
    } else {
        val
    }
}

/// Negate with saturation (negate(-32768) = 32767).
#[inline(always)]
pub fn negate(val: i16) -> i16 {
    if val == MIN_16 as i16 {
        MAX_16 as i16
    } else {
        -val
    }
}

/// 16-bit arithmetic right shift. Negative shift calls shl.
#[inline(always)]
pub fn shr(val: i16, shift: i16) -> i16 {
    if shift < 0 {
        if shift < -16 {
            return shl(val, 16);
        }
        return shl(val, -shift);
    }
    if shift > 14 {
        return if val < 0 { -1 } else { 0 };
    }
    if val < 0 {
        return !((!val as i16) >> (shift as u32 & 0x1F)) as i16;
    }
    (val >> (shift as u32 & 0x1F)) as i16
}

/// 16-bit left shift with overflow saturation. Negative shift calls shr.
#[inline(always)]
pub fn shl(val: i16, shift: i16) -> i16 {
    if shift < 0 {
        if shift < -16 {
            return shr(val, 16);
        }
        return shr(val, -shift);
    }
    let result = (1i32 << (shift as u32 & 0x1F)) * (val as i32);
    if (shift < 16 || val == 0) && result - (result as i16 as i32) == 0 {
        return result as i16;
    }
    // Overflow
    if val < 1 {
        (MAX_16 + 1) as i16 // 0x8000
    } else {
        MAX_16 as i16 // 0x7FFF
    }
}

/// Q15 multiply: (a * b) >> 15, with saturation.
#[inline(always)]
pub fn mult(a: i16, b: i16) -> i16 {
    let result = ((a as i32) * (b as i32)) >> 15;
    let sign_extended = if (result & 0x10000) != 0 {
        result | !0xFFFF
    } else {
        result
    };
    saturate(sign_extended)
}

/// 32-bit multiply: a * b * 2, with saturation for 0x4000_0000 case.
#[inline(always)]
pub fn l_mult(a: i16, b: i16) -> i32 {
    let result = (a as i32) * (b as i32);
    if result != 0x4000_0000 {
        result * 2
    } else {
        MAX_32
    }
}

/// 32-bit multiply-accumulate: acc + a * b * 2.
#[inline(always)]
pub fn l_mac(acc: i32, a: i16, b: i16) -> i32 {
    l_add(acc, l_mult(a, b))
}

/// 32-bit saturating addition.
#[inline(always)]
pub fn l_add(a: i32, b: i32) -> i32 {
    let result = a.wrapping_add(b);
    // Overflow check: same signs in, different sign out
    if ((a ^ b) & MIN_32) == 0 && ((result ^ a) & MIN_32) != 0 {
        if a < 0 {
            MIN_32
        } else {
            MAX_32
        }
    } else {
        result
    }
}

/// 32-bit saturating subtraction.
#[inline(always)]
pub fn l_sub(a: i32, b: i32) -> i32 {
    let result = a.wrapping_sub(b);
    // Overflow check: different signs in, different sign out
    if ((a ^ b) & MIN_32) != 0 && ((result ^ a) & MIN_32) != 0 {
        if a < 0 {
            MIN_32
        } else {
            MAX_32
        }
    } else {
        result
    }
}

/// 32-bit left shift with saturation. Negative shift calls l_shr.
#[inline(always)]
pub fn l_shl(val: i32, shift: i16) -> i32 {
    if shift <= 0 {
        if shift < -32 {
            return l_shr(val, 32);
        }
        return l_shr(val, -shift);
    }
    let mut v = val;
    let mut s = shift;
    loop {
        if v > 0x3FFF_FFFF {
            return MAX_32;
        }
        if v < -0x4000_0000 {
            return MIN_32;
        }
        v *= 2;
        s -= 1;
        if s <= 0 {
            return v;
        }
    }
}

/// 32-bit arithmetic right shift. Negative shift calls l_shl.
#[inline(always)]
pub fn l_shr(val: i32, shift: i16) -> i32 {
    if shift < 0 {
        if shift < -32 {
            return l_shl(val, 32);
        }
        return l_shl(val, -shift);
    }
    if shift > 30 {
        return if val < 0 { -1 } else { 0 };
    }
    if val < 0 {
        !((!val) >> (shift as u32 & 0x1F))
    } else {
        val >> (shift as u32 & 0x1F)
    }
}

/// Extract high 16 bits of a 32-bit value.
#[inline(always)]
pub fn extract_h(val: i32) -> i16 {
    (val >> 16) as i16
}

/// Extract low 16 bits of a 32-bit value (identity cast).
#[inline(always)]
pub fn extract_l(val: i32) -> i16 {
    val as i16
}

/// Sign-extend 16-bit to 32-bit.
#[inline(always)]
pub fn l_deposit_l(val: i16) -> i32 {
    val as i32
}

/// Count leading redundant sign bits of a 16-bit value.
/// Returns 0 for 0 and -1, 15 for 0xFFFF.
#[inline(always)]
pub fn norm_s(val: i16) -> i16 {
    if val == 0 {
        return 0;
    }
    if val == -1i16 {
        return 15;
    }
    let mut v = if val < 0 { !val } else { val } as u16;
    let mut count: i16 = 0;
    while v < 0x4000 {
        v <<= 1;
        count += 1;
    }
    count
}

/// 32-bit multiply without the *2: a * b.
#[inline(always)]
pub fn l_mult0(a: i16, b: i16) -> i32 {
    (a as i32) * (b as i32)
}

/// 32-bit multiply-accumulate without the *2: acc + a * b.
#[inline(always)]
pub fn l_mac0(acc: i32, a: i16, b: i16) -> i32 {
    l_add(acc, l_mult0(a, b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_saturate() {
        assert_eq!(saturate(0), 0);
        assert_eq!(saturate(32767), 32767);
        assert_eq!(saturate(32768), 32767);
        assert_eq!(saturate(-32768), -32768);
        assert_eq!(saturate(-32769), -32768);
    }

    #[test]
    fn test_add_sub() {
        assert_eq!(add(100, 200), 300);
        assert_eq!(add(32000, 1000), 32767);
        assert_eq!(add(-32000, -1000), -32768);
        assert_eq!(sub(100, 200), -100);
        assert_eq!(sub(-32000, 1000), -32768);
    }

    #[test]
    fn test_negate_abs() {
        assert_eq!(negate(100), -100);
        assert_eq!(negate(-100), 100);
        assert_eq!(negate(-32768), 32767);
        assert_eq!(abs_s(100), 100);
        assert_eq!(abs_s(-100), 100);
        assert_eq!(abs_s(-32768), 32767);
    }

    #[test]
    fn test_shl_shr() {
        assert_eq!(shl(1, 3), 8);
        assert_eq!(shr(8, 3), 1);
        assert_eq!(shr(-8, 3), -1);
        assert_eq!(shl(0x4000, 1), 32767); // overflow saturates
    }

    #[test]
    fn test_mult() {
        assert_eq!(mult(16384, 16384), 8192); // 0.5 * 0.5 = 0.25 in Q15
    }

    #[test]
    fn test_l_mult() {
        assert_eq!(l_mult(1, 1), 2);
        assert_eq!(l_mult(16384, 16384), 536870912); // not the overflow case
    }

    #[test]
    fn test_l_add_sub() {
        assert_eq!(l_add(100, 200), 300);
        assert_eq!(l_add(MAX_32, 1), MAX_32);
        assert_eq!(l_add(MIN_32, -1), MIN_32);
        assert_eq!(l_sub(100, 200), -100);
    }

    #[test]
    fn test_extract() {
        assert_eq!(extract_h(0x12340000u32 as i32), 0x1234);
        assert_eq!(extract_l(0x00001234), 0x1234);
    }

    #[test]
    fn test_norm_s() {
        assert_eq!(norm_s(0), 0);
        assert_eq!(norm_s(1), 14);
        assert_eq!(norm_s(-1), 15);
        assert_eq!(norm_s(0x4000), 0);
        assert_eq!(norm_s(0x2000), 1);
    }
}
