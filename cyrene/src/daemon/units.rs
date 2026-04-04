use std::fmt;
use std::ops::{Add, Sub, Neg};

const UNITS: &[(i128, &str)] = &[
    (1024_i128.pow(4), "T"),
    (1024_i128.pow(3), "G"),
    (1024_i128.pow(2), "M"),
    (1024_i128.pow(1), "K"),
];

/// A byte count. Internally `i128` to allow signed arithmetic on deltas
/// while supporting pools up to 2^127 bytes (~170 undecibytes).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Size(pub i128);

impl Size {
    pub fn from_u64(n: u64) -> Self { Self(n as i128) }
}

impl fmt::Display for Size {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let amt = self.0;
        let abs = amt.unsigned_abs();

        if amt < 0 { f.write_str("-")?; }

        for &(scale, unit) in UNITS {
            if abs >= scale as u128 {
                return write!(f, "{:.2}{}", abs as f64 / scale as f64, unit);
            }
        }

        write!(f, "{}B", abs)
    }
}

impl Add for Size {
    type Output = Self;
    fn add(self, rhs: Self) -> Self { Self(self.0 + rhs.0) }
}

impl Sub for Size {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self { Self(self.0 - rhs.0) }
}

impl Neg for Size {
    type Output = Self;
    fn neg(self) -> Self { Self(-self.0) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display() {
        assert_eq!(Size(0).to_string(),                        "0B");
        assert_eq!(Size(1023).to_string(),                     "1023B");
        assert_eq!(Size(1024).to_string(),                     "1.00K");
        assert_eq!(Size(1536).to_string(),                     "1.50K");
        assert_eq!(Size(1024_i128.pow(2)).to_string(),         "1.00M");
        assert_eq!(Size(1024_i128.pow(3)).to_string(),         "1.00G");
        assert_eq!(Size(1024_i128.pow(4)).to_string(),         "1.00T");
        assert_eq!(Size(1024_i128.pow(4) * 2).to_string(),     "2.00T");
    }

    #[test]
    fn test_negative_display() {
        assert_eq!(Size(-1024).to_string(),                    "-1.00K");
        assert_eq!(Size(-1024_i128.pow(3)).to_string(),        "-1.00G");
    }

    #[test]
    fn test_arithmetic() {
        let a = Size(1024_i128.pow(3));     // 1G
        let b = Size(512 * 1024 * 1024);   // 512M
        assert_eq!((a - b).to_string(),     "512.00M");
        assert_eq!((a + b).to_string(),     "1.50G");
        assert_eq!((-a).to_string(),        "-1.00G");
    }

    #[test]
    fn test_from_u64() {
        assert_eq!(Size::from_u64(u64::MAX), Size(u64::MAX as i128));
    }
}
