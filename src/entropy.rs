pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    // 1. Count how many times each of the 256 possible byte values appears.
    let mut counts = [0usize; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    // 2. Sum -p*log2(p) over every value that actually occurred.
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in counts.iter() {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::shannon_entropy;

    // An empty buffer carries no information.
    #[test]
    fn empty_is_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    // One repeated value is perfectly predictable -> 0 bits.
    #[test]
    fn uniform_is_zero() {
        assert_eq!(shannon_entropy(&[0xAA; 1000]), 0.0);
    }

    // Two values, equally likely -> exactly 1 bit per byte.
    #[test]
    fn two_equal_values_is_one_bit() {
        let data: Vec<u8> = (0..1000).map(|i| (i % 2) as u8).collect();
        assert!((shannon_entropy(&data) - 1.0).abs() < 1e-9);
    }

    // All 256 values, each once -> the maximum, 8 bits per byte.
    #[test]
    fn all_256_values_is_eight_bits() {
        let data: Vec<u8> = (0..=255).collect();
        assert!((shannon_entropy(&data) - 8.0).abs() < 1e-9);
    }
}
