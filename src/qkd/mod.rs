use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors for BB84-inspired QKD simulation.
#[derive(Debug, Error, PartialEq)]
pub enum QkdError {
    #[error("qubit_count must be greater than zero")]
    EmptyTransmission,
    #[error("sample_size must be greater than zero")]
    InvalidSampleSize,
    #[error("bit_flip_probability must be in [0.0, 1.0]")]
    InvalidNoiseProbability,
    #[error("max_qber must be in [0.0, 1.0]")]
    InvalidMaxQber,
    #[error("not enough sifted bits for requested sample size")]
    InsufficientSiftedBits,
    #[error("entropy source exhausted")]
    EntropyExhausted,
}

/// Entropy source abstraction for deterministic testing and pluggable randomness.
pub trait EntropySource {
    /// Return the next 64 random bits.
    fn next_u64(&mut self) -> Result<u64, QkdError>;

    /// Return the next random bit (0 or 1).
    fn next_bit(&mut self) -> Result<u8, QkdError> {
        Ok((self.next_u64()? & 1) as u8)
    }

    /// Return a random floating point value in [0.0, 1.0).
    fn next_unit_f64(&mut self) -> Result<f64, QkdError> {
        let x = self.next_u64()?;
        Ok((x as f64) / ((u64::MAX as f64) + 1.0))
    }
}

/// Simple deterministic entropy source for simulation and tests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    pub fn from_seed(seed: u64) -> Self {
        // Avoid the all-zero absorbing state.
        let state = if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        };
        Self { state }
    }
}

impl EntropySource for XorShift64 {
    fn next_u64(&mut self) -> Result<u64, QkdError> {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        Ok(x)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Basis {
    Rectilinear,
    Diagonal,
}

impl Basis {
    fn random(entropy: &mut impl EntropySource) -> Result<Self, QkdError> {
        Ok(if entropy.next_bit()? == 0 {
            Basis::Rectilinear
        } else {
            Basis::Diagonal
        })
    }
}

/// Quantum channel model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumChannel {
    /// Probability that a measured bit flips due to channel noise.
    pub bit_flip_probability: f64,
}

impl QuantumChannel {
    pub fn new(bit_flip_probability: f64) -> Result<Self, QkdError> {
        if !(0.0..=1.0).contains(&bit_flip_probability) {
            return Err(QkdError::InvalidNoiseProbability);
        }
        Ok(Self {
            bit_flip_probability,
        })
    }

    fn maybe_flip(
        &self,
        bit: u8,
        entropy: &mut impl EntropySource,
    ) -> Result<u8, QkdError> {
        let draw = entropy.next_unit_f64()?;
        if draw < self.bit_flip_probability {
            Ok(bit ^ 1)
        } else {
            Ok(bit)
        }
    }
}

/// Parameters for BB84-style QKD simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QkdParameters {
    /// Number of transmitted qubits.
    pub qubit_count: usize,
    /// Number of sifted bits publicly compared to estimate QBER.
    pub sample_size: usize,
    /// Maximum accepted quantum bit error rate.
    pub max_qber: f64,
}

impl Default for QkdParameters {
    fn default() -> Self {
        Self {
            qubit_count: 256,
            sample_size: 32,
            max_qber: 0.11,
        }
    }
}

/// Result of one BB84 simulation run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QkdSessionReport {
    pub raw_bits: usize,
    pub sifted_bits: usize,
    pub sampled_bits: usize,
    pub mismatches: usize,
    pub qber: f64,
    pub accepted: bool,
    /// Final shared key bits after discarding sampled bits.
    pub final_key_bits: Vec<u8>,
}

/// BB84-inspired key distribution simulator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bb84Simulator {
    pub params: QkdParameters,
    pub channel: QuantumChannel,
}

impl Bb84Simulator {
    pub fn new(params: QkdParameters, channel: QuantumChannel) -> Result<Self, QkdError> {
        if params.qubit_count == 0 {
            return Err(QkdError::EmptyTransmission);
        }
        if params.sample_size == 0 {
            return Err(QkdError::InvalidSampleSize);
        }
        if !(0.0..=1.0).contains(&params.max_qber) {
            return Err(QkdError::InvalidMaxQber);
        }
        Ok(Self { params, channel })
    }

    /// Execute one BB84 session.
    pub fn run(&self, entropy: &mut impl EntropySource) -> Result<QkdSessionReport, QkdError> {
        let n = self.params.qubit_count;

        let mut sifted_alice = Vec::new();
        let mut sifted_bob = Vec::new();

        for _ in 0..n {
            let alice_bit = entropy.next_bit()?;
            let alice_basis = Basis::random(entropy)?;
            let bob_basis = Basis::random(entropy)?;

            // If bases differ, Bob's measurement is information-theoretically random.
            let ideal_bob_bit = if alice_basis == bob_basis {
                alice_bit
            } else {
                entropy.next_bit()?
            };
            let bob_bit = self.channel.maybe_flip(ideal_bob_bit, entropy)?;

            if alice_basis == bob_basis {
                sifted_alice.push(alice_bit);
                sifted_bob.push(bob_bit);
            }
        }

        if sifted_alice.len() < self.params.sample_size {
            return Err(QkdError::InsufficientSiftedBits);
        }

        let sample_indices = random_unique_indices(
            sifted_alice.len(),
            self.params.sample_size,
            entropy,
        )?;
        let mut is_sample = vec![false; sifted_alice.len()];
        for &idx in &sample_indices {
            is_sample[idx] = true;
        }

        let mismatches = sample_indices
            .iter()
            .filter(|&&i| sifted_alice[i] != sifted_bob[i])
            .count();
        let qber = (mismatches as f64) / (self.params.sample_size as f64);
        let accepted = qber <= self.params.max_qber;

        let final_key_bits = sifted_alice
            .iter()
            .enumerate()
            .filter_map(|(i, &bit)| if is_sample[i] { None } else { Some(bit) })
            .collect::<Vec<_>>();

        Ok(QkdSessionReport {
            raw_bits: n,
            sifted_bits: sifted_alice.len(),
            sampled_bits: self.params.sample_size,
            mismatches,
            qber,
            accepted,
            final_key_bits,
        })
    }
}

fn random_unique_indices(
    len: usize,
    sample_size: usize,
    entropy: &mut impl EntropySource,
) -> Result<Vec<usize>, QkdError> {
    let mut idx = (0..len).collect::<Vec<_>>();

    // Fisher-Yates shuffle for uniform sampling without replacement.
    for i in (1..len).rev() {
        let r = entropy.next_u64()? as usize;
        let j = r % (i + 1);
        idx.swap(i, j);
    }

    idx.truncate(sample_size);
    Ok(idx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone)]
    struct FixedEntropy {
        values: Vec<u64>,
        pos: usize,
    }

    impl FixedEntropy {
        fn new(values: Vec<u64>) -> Self {
            Self { values, pos: 0 }
        }
    }

    impl EntropySource for FixedEntropy {
        fn next_u64(&mut self) -> Result<u64, QkdError> {
            let out = self
                .values
                .get(self.pos)
                .copied()
                .ok_or(QkdError::EntropyExhausted)?;
            self.pos += 1;
            Ok(out)
        }
    }

    #[test]
    fn test_simulation_accepts_zero_noise() {
        let params = QkdParameters {
            qubit_count: 512,
            sample_size: 40,
            max_qber: 0.11,
        };
        let channel = QuantumChannel::new(0.0).unwrap();
        let sim = Bb84Simulator::new(params, channel).unwrap();
        let mut entropy = XorShift64::from_seed(12345);

        let report = sim.run(&mut entropy).unwrap();
        assert!(report.accepted);
        assert_eq!(report.qber, 0.0);
        assert_eq!(report.raw_bits, 512);
        assert!(report.sifted_bits >= 40);
        assert_eq!(report.final_key_bits.len(), report.sifted_bits - report.sampled_bits);
    }

    #[test]
    fn test_simulation_rejects_high_noise() {
        let params = QkdParameters {
            qubit_count: 512,
            sample_size: 40,
            max_qber: 0.11,
        };
        let channel = QuantumChannel::new(1.0).unwrap();
        let sim = Bb84Simulator::new(params, channel).unwrap();
        let mut entropy = XorShift64::from_seed(77);

        let report = sim.run(&mut entropy).unwrap();
        assert!(!report.accepted);
        assert!(report.qber > 0.5);
    }

    #[test]
    fn test_same_seed_is_deterministic() {
        let params = QkdParameters {
            qubit_count: 300,
            sample_size: 20,
            max_qber: 0.2,
        };
        let channel = QuantumChannel::new(0.05).unwrap();
        let sim = Bb84Simulator::new(params, channel).unwrap();

        let mut e1 = XorShift64::from_seed(999);
        let mut e2 = XorShift64::from_seed(999);

        let r1 = sim.run(&mut e1).unwrap();
        let r2 = sim.run(&mut e2).unwrap();

        assert_eq!(r1.sifted_bits, r2.sifted_bits);
        assert_eq!(r1.mismatches, r2.mismatches);
        assert_eq!(r1.qber, r2.qber);
        assert_eq!(r1.final_key_bits, r2.final_key_bits);
    }

    #[test]
    fn test_invalid_noise_probability_rejected() {
        let err = QuantumChannel::new(1.5).expect_err("invalid noise");
        assert_eq!(err, QkdError::InvalidNoiseProbability);
    }

    #[test]
    fn test_empty_transmission_rejected() {
        let params = QkdParameters {
            qubit_count: 0,
            sample_size: 4,
            max_qber: 0.1,
        };
        let channel = QuantumChannel::new(0.0).unwrap();
        let err = Bb84Simulator::new(params, channel).expect_err("empty transmission");
        assert_eq!(err, QkdError::EmptyTransmission);
    }

    #[test]
    fn test_invalid_sample_size_rejected() {
        let params = QkdParameters {
            qubit_count: 8,
            sample_size: 0,
            max_qber: 0.1,
        };
        let channel = QuantumChannel::new(0.0).unwrap();
        let err = Bb84Simulator::new(params, channel).expect_err("invalid sample");
        assert_eq!(err, QkdError::InvalidSampleSize);
    }

    #[test]
    fn test_invalid_max_qber_rejected() {
        let params = QkdParameters {
            qubit_count: 8,
            sample_size: 2,
            max_qber: 2.0,
        };
        let channel = QuantumChannel::new(0.0).unwrap();
        let err = Bb84Simulator::new(params, channel).expect_err("invalid qber");
        assert_eq!(err, QkdError::InvalidMaxQber);
    }

    #[test]
    fn test_insufficient_sifted_bits_error() {
        let params = QkdParameters {
            qubit_count: 4,
            sample_size: 5,
            max_qber: 0.2,
        };
        let channel = QuantumChannel::new(0.0).unwrap();
        let sim = Bb84Simulator::new(params, channel).unwrap();
        let mut entropy = XorShift64::from_seed(5);

        let err = sim.run(&mut entropy).expect_err("not enough sifted bits");
        assert_eq!(err, QkdError::InsufficientSiftedBits);
    }

    #[test]
    fn test_entropy_exhaustion_propagates() {
        let params = QkdParameters {
            qubit_count: 64,
            sample_size: 4,
            max_qber: 0.2,
        };
        let channel = QuantumChannel::new(0.0).unwrap();
        let sim = Bb84Simulator::new(params, channel).unwrap();
        let mut entropy = FixedEntropy::new(vec![0, 1, 2]);

        let err = sim.run(&mut entropy).expect_err("entropy exhausted");
        assert_eq!(err, QkdError::EntropyExhausted);
    }

    #[test]
    fn test_report_serialization_roundtrip() {
        let params = QkdParameters {
            qubit_count: 128,
            sample_size: 16,
            max_qber: 0.15,
        };
        let channel = QuantumChannel::new(0.02).unwrap();
        let sim = Bb84Simulator::new(params, channel).unwrap();
        let mut entropy = XorShift64::from_seed(4242);

        let report = sim.run(&mut entropy).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let decoded: QkdSessionReport = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.raw_bits, report.raw_bits);
        assert_eq!(decoded.sifted_bits, report.sifted_bits);
        assert_eq!(decoded.mismatches, report.mismatches);
        assert_eq!(decoded.final_key_bits, report.final_key_bits);
    }
}
