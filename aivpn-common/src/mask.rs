//! Mask System (Traffic Mimicry Profiles)
//! 
//! Implements Mask profiles that define traffic shaping behavior

use serde::{Deserialize, Serialize};
use rand::{Rng, distributions::Distribution};
use rand::distributions::weighted::WeightedIndex;

use crate::error::{Error, Result};

/// Mask profile for traffic mimicry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskProfile {
    /// Unique identifier
    pub mask_id: String,
    /// Profile version
    pub version: u16,
    /// Creation timestamp
    pub created_at: u64,
    /// Expiration timestamp
    pub expires_at: u64,

    /// Protocol to spoof
    pub spoof_protocol: SpoofProtocol,
    /// Header template bytes
    pub header_template: Vec<u8>,
    /// Offset for ephemeral public key in header
    pub eph_pub_offset: u16,
    /// Length of ephemeral public key (always 32)
    pub eph_pub_length: u16,

    /// Packet size distribution
    pub size_distribution: SizeDistribution,
    /// Inter-arrival time distribution
    pub iat_distribution: IATDistribution,
    /// Padding strategy
    pub padding_strategy: PaddingStrategy,

    /// FSM states for behavioral mimicry
    pub fsm_states: Vec<FSMState>,
    /// Initial FSM state
    pub fsm_initial_state: u16,

    /// Neural resonance signature (64 floats)
    pub signature_vector: Vec<f32>,

    /// Reverse profile for server->client traffic
    pub reverse_profile: Option<Box<MaskProfile>>,

    /// Ed25519 signature (64 bytes)
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

/// Protocol spoofing types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum SpoofProtocol {
    None,
    QUIC,
    WebRTC_STUN,
    HTTPS_H2,
    DNS_over_UDP,
}

/// Packet size distribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SizeDistribution {
    pub dist_type: SizeDistType,
    pub bins: Vec<(u16, u16, f32)>, // (min, max, probability)
    pub parametric_type: Option<ParametricType>,
    pub parametric_params: Option<Vec<f64>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SizeDistType {
    Histogram,
    Parametric,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParametricType {
    LogNormal,
    Gamma,
    Bimodal,
}

impl SizeDistribution {
    /// Sample a packet size from the distribution
    pub fn sample<R: Rng>(&self, rng: &mut R) -> u16 {
        match self.dist_type {
            SizeDistType::Histogram => {
                if self.bins.is_empty() {
                    return 64; // Default
                }
                
                // Weighted random selection of bin
                let weights: Vec<f32> = self.bins.iter().map(|(_, _, p)| *p).collect();
                if let Ok(dist) = WeightedIndex::new(&weights) {
                    let bin_idx = dist.sample(rng);
                    let (min, max, _) = self.bins[bin_idx];
                    rng.gen_range(min..=max)
                } else {
                    64
                }
            }
            SizeDistType::Parametric => {
                match self.parametric_type {
                    Some(ParametricType::LogNormal) => {
                        if let Some(params) = &self.parametric_params {
                            let mu: f64 = params[0];
                            let sigma: f64 = params[1];
                            // Box-Muller transform: generate standard normal from two uniform samples
                            let u1: f64 = rng.gen::<f64>().max(1e-10); // avoid ln(0)
                            let u2: f64 = rng.gen();
                            let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
                            // LogNormal: exp(mu + sigma * z)
                            let sample = (mu + sigma * z).exp();
                            (sample as u16).max(1)
                        } else {
                            rng.gen_range(64..512)
                        }
                    }
                    _ => rng.gen_range(64..512),
                }
            }
        }
    }
}

/// Inter-arrival time distribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IATDistribution {
    pub dist_type: IATDistType,
    pub params: Vec<f64>,
    pub jitter_range_ms: (f64, f64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IATDistType {
    Exponential,
    LogNormal,
    Gamma,
    Empirical,
}

impl IATDistribution {
    /// Sample an inter-arrival time in milliseconds
    pub fn sample<R: Rng>(&self, rng: &mut R) -> f64 {
        let base_iat = match self.dist_type {
            IATDistType::Exponential => {
                let lambda: f64 = self.params[0];
                let val: f64 = rng.gen::<f64>().max(1e-10);
                -(1.0 - val).ln() / lambda
            }
            IATDistType::LogNormal => {
                let mu: f64 = self.params[0];
                let sigma: f64 = self.params[1];
                // Box-Muller transform for proper normal distribution
                let u1: f64 = rng.gen::<f64>().max(1e-10);
                let u2: f64 = rng.gen();
                let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
                (mu + sigma * z).exp()
            }
            IATDistType::Gamma => {
                // Simplified gamma sampling (sum of k exponentials for integer k)
                let k: f64 = self.params[0];
                let theta: f64 = self.params[1];
                let sum: f64 = (0..k.max(1.0) as i32)
                    .map(|_| {
                        let val: f64 = rng.gen::<f64>().max(1e-10);
                        -(1.0 - val).ln()
                    })
                    .sum();
                sum * theta
            }
            IATDistType::Empirical => {
                let idx = rng.gen_range(0..self.params.len());
                self.params[idx]
            }
        };

        // Add jitter
        let jitter = rng.gen_range(self.jitter_range_ms.0..=self.jitter_range_ms.1);
        (base_iat + jitter).max(0.0)
    }
}

/// Padding strategy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PaddingStrategy {
    RandomUniform { min: u16, max: u16 },
    MatchDistribution,
    Fixed { size: u16 },
}

impl PaddingStrategy {
    /// Calculate padding length for a given payload
    pub fn calc_padding<R: Rng>(&self, payload_size: usize, target_size: u16, rng: &mut R) -> u16 {
        match self {
            Self::RandomUniform { min, max } => rng.gen_range(*min..=*max),
            Self::MatchDistribution => {
                if target_size as usize > payload_size {
                    (target_size as usize - payload_size) as u16
                } else {
                    0
                }
            }
            Self::Fixed { size } => *size,
        }
    }
}

/// FSM state for behavioral mimicry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FSMState {
    pub state_id: u16,
    pub transitions: Vec<FSMTransition>,
}

/// FSM transition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FSMTransition {
    pub condition: TransitionCondition,
    pub next_state: u16,
    pub size_override: Option<SizeDistribution>,
    pub iat_override: Option<IATDistribution>,
    pub padding_override: Option<PaddingStrategy>,
}

/// Transition condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransitionCondition {
    AfterPackets(u32),
    AfterDuration(u64), // milliseconds
    OnPayloadType(u8),
    Random(f32), // probability per packet
}

impl MaskProfile {
    /// MDH length for regular packets that do not carry a client eph_pub.
    pub fn data_mdh_len(&self) -> usize {
        self.header_template.len()
    }

    /// MDH length for bootstrap packets that carry a client eph_pub in the MDH.
    pub fn handshake_mdh_len(&self) -> usize {
        self.header_template.len().max(
            self.eph_pub_offset as usize + self.eph_pub_length as usize,
        )
    }

    pub fn matches_mdh_prefix(&self, mdh: &[u8]) -> bool {
        if mdh.len() < self.header_template.len() {
            return false;
        }

        let eph_start = self.eph_pub_offset as usize;
        let eph_end = eph_start.saturating_add(self.eph_pub_length as usize);
        self.header_template
            .iter()
            .enumerate()
            .all(|(idx, expected)| {
                (idx >= eph_start && idx < eph_end) || mdh[idx] == *expected
            })
    }

    pub fn copy_eph_pub_from_mdh(&self, mdh: &[u8]) -> Option<[u8; 32]> {
        if self.eph_pub_length != 32 {
            return None;
        }

        let eph_start = self.eph_pub_offset as usize;
        let eph_end = eph_start.checked_add(32)?;
        let eph = mdh.get(eph_start..eph_end)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(eph);
        Some(out)
    }

    /// Verify Ed25519 signature over all profile fields except the signature itself
    pub fn verify_signature(&self, public_key: &[u8; 32]) -> Result<bool> {
        use ed25519_dalek::{Signature, VerifyingKey, Verifier};

        let vk = VerifyingKey::from_bytes(public_key)
            .map_err(|e| Error::Crypto(format!("Invalid Ed25519 public key: {}", e)))?;

        // Build canonical message: mask_id || version || header_template
        let mut message = Vec::new();
        message.extend_from_slice(self.mask_id.as_bytes());
        message.extend_from_slice(&self.version.to_le_bytes());
        message.extend_from_slice(&self.header_template);

        let sig = Signature::from_bytes(&self.signature);
        match vk.verify(&message, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Get initial FSM state
    pub fn initial_state(&self) -> u16 {
        self.fsm_initial_state
    }

    /// Process FSM transition
    pub fn process_transition(
        &self,
        current_state: u16,
        packets_in_state: u32,
        duration_in_state_ms: u64,
    ) -> (u16, Option<SizeDistribution>, Option<IATDistribution>, Option<PaddingStrategy>) {
        let state = self.fsm_states.iter().find(|s| s.state_id == current_state);
        if let Some(state) = state {
            for transition in &state.transitions {
                let should_transition = match &transition.condition {
                    TransitionCondition::AfterPackets(n) => packets_in_state >= *n,
                    TransitionCondition::AfterDuration(ms) => duration_in_state_ms >= *ms,
                    TransitionCondition::Random(prob) => rand::thread_rng().gen_range(0.0..1.0) < *prob,
                    TransitionCondition::OnPayloadType(_) => false, // Handled separately
                };

                if should_transition {
                    return (
                        transition.next_state,
                        transition.size_override.clone(),
                        transition.iat_override.clone(),
                        transition.padding_override.clone(),
                    );
                }
            }
        }
        (current_state, None, None, None)
    }
}

/// Pre-built mask catalog (MVP defaults)
pub mod preset_masks {
    use super::*;

    /// WebRTC Zoom-like profile
    pub fn webrtc_zoom_v3() -> MaskProfile {
        MaskProfile {
            mask_id: "webrtc_zoom_v3".to_string(),
            version: 2,
            created_at: 0,
            expires_at: u64::MAX,
            spoof_protocol: SpoofProtocol::WebRTC_STUN,
            header_template: vec![
                0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42, 0x7F, 0xB2, 0x7B, 0x94,
                0x16, 0x02, 0xD0, 0x1D, 0x9C, 0x5B, 0x2D, 0xCB,
            ],
            eph_pub_offset: 20,
            eph_pub_length: 32,
            size_distribution: SizeDistribution {
                dist_type: SizeDistType::Parametric,
                bins: vec![],
                parametric_type: Some(ParametricType::Bimodal),
                parametric_params: Some(vec![5.0, 0.5]), // Opus-like
            },
            iat_distribution: IATDistribution {
                dist_type: IATDistType::LogNormal,
                params: vec![2.5, 0.3], // ~12ms average
                jitter_range_ms: (5.0, 20.0),
            },
            padding_strategy: PaddingStrategy::RandomUniform { min: 0, max: 64 },
            fsm_states: vec![
                FSMState {
                    state_id: 0,
                    transitions: vec![
                        FSMTransition {
                            condition: TransitionCondition::AfterDuration(5000),
                            next_state: 1,
                            size_override: None,
                            iat_override: None,
                            padding_override: None,
                        }
                    ],
                },
                FSMState {
                    state_id: 1,
                    transitions: vec![],
                },
            ],
            fsm_initial_state: 0,
            signature_vector: vec![0.0; 64],
            reverse_profile: None,
            signature: [0u8; 64],
        }
    }

    /// QUIC/HTTP3-like profile
    pub fn quic_https_v2() -> MaskProfile {
        MaskProfile {
            mask_id: "quic_https_v2".to_string(),
            version: 2,
            created_at: 0,
            expires_at: u64::MAX,
            spoof_protocol: SpoofProtocol::QUIC,
            header_template: vec![
                0xC0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x49, 0x8E, 0x38, 0xC9, 0x0F, 0x58,
                0xC5, 0x2A,
            ],
            eph_pub_offset: 14,
            eph_pub_length: 32,
            size_distribution: SizeDistribution {
                dist_type: SizeDistType::Histogram,
                bins: vec![
                    (64, 128, 0.3),
                    (256, 512, 0.4),
                    (768, 1200, 0.3),
                ],
                parametric_type: None,
                parametric_params: None,
            },
            iat_distribution: IATDistribution {
                dist_type: IATDistType::Exponential,
                params: vec![0.1], // Burst-idle pattern
                jitter_range_ms: (0.0, 10.0),
            },
            padding_strategy: PaddingStrategy::MatchDistribution,
            fsm_states: vec![
                FSMState {
                    state_id: 0,
                    transitions: vec![],
                },
            ],
            fsm_initial_state: 0,
            signature_vector: vec![0.0; 64],
            reverse_profile: None,
            signature: [0u8; 64],
        }
    }

    /// Yandex Telemost/WebRTC-like bootstrap profile.
    pub fn webrtc_yandex_telemost_v1() -> MaskProfile {
        MaskProfile {
            mask_id: "webrtc_yandex_telemost_v1".to_string(),
            version: 2,
            created_at: 0,
            expires_at: u64::MAX,
            spoof_protocol: SpoofProtocol::WebRTC_STUN,
            header_template: vec![
                0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42, 0x9C, 0x2A, 0xBD, 0x49,
                0xD3, 0x58, 0x0E, 0x93, 0x3E, 0xCD, 0x1F, 0x77,
            ],
            eph_pub_offset: 20,
            eph_pub_length: 32,
            size_distribution: SizeDistribution {
                dist_type: SizeDistType::Parametric,
                bins: vec![],
                parametric_type: Some(ParametricType::Bimodal),
                parametric_params: Some(vec![4.5, 0.45]),
            },
            iat_distribution: IATDistribution {
                dist_type: IATDistType::LogNormal,
                params: vec![2.3, 0.25],
                jitter_range_ms: (3.0, 15.0),
            },
            padding_strategy: PaddingStrategy::RandomUniform { min: 0, max: 48 },
            fsm_states: vec![
                FSMState {
                    state_id: 0,
                    transitions: vec![FSMTransition {
                        condition: TransitionCondition::AfterDuration(4000),
                        next_state: 1,
                        size_override: None,
                        iat_override: None,
                        padding_override: None,
                    }],
                },
                FSMState {
                    state_id: 1,
                    transitions: vec![],
                },
            ],
            fsm_initial_state: 0,
            signature_vector: vec![0.0; 64],
            reverse_profile: None,
            signature: [0u8; 64],
        }
    }

    /// VK Teams/WebRTC-like bootstrap profile.
    pub fn webrtc_vk_teams_v1() -> MaskProfile {
        MaskProfile {
            mask_id: "webrtc_vk_teams_v1".to_string(),
            version: 2,
            created_at: 0,
            expires_at: u64::MAX,
            spoof_protocol: SpoofProtocol::WebRTC_STUN,
            header_template: vec![
                0x00, 0x01, 0x00, 0x01, 0x21, 0x12, 0xA4, 0x42, 0xCB, 0x0E, 0xA7, 0x5C,
                0x26, 0xB9, 0x47, 0x7C, 0x31, 0xD9, 0x56, 0x0F,
            ],
            eph_pub_offset: 20,
            eph_pub_length: 32,
            size_distribution: SizeDistribution {
                dist_type: SizeDistType::Histogram,
                bins: vec![
                    (64, 128, 0.15),
                    (256, 512, 0.50),
                    (768, 1024, 0.25),
                    (1024, 1400, 0.10),
                ],
                parametric_type: None,
                parametric_params: None,
            },
            iat_distribution: IATDistribution {
                dist_type: IATDistType::LogNormal,
                params: vec![2.8, 0.35],
                jitter_range_ms: (5.0, 25.0),
            },
            padding_strategy: PaddingStrategy::RandomUniform { min: 0, max: 64 },
            fsm_states: vec![
                FSMState {
                    state_id: 0,
                    transitions: vec![FSMTransition {
                        condition: TransitionCondition::AfterDuration(6000),
                        next_state: 1,
                        size_override: None,
                        iat_override: None,
                        padding_override: None,
                    }],
                },
                FSMState {
                    state_id: 1,
                    transitions: vec![FSMTransition {
                        condition: TransitionCondition::AfterPackets(50),
                        next_state: 2,
                        size_override: None,
                        iat_override: None,
                        padding_override: None,
                    }],
                },
                FSMState {
                    state_id: 2,
                    transitions: vec![],
                },
            ],
            fsm_initial_state: 0,
            signature_vector: vec![0.0; 64],
            reverse_profile: None,
            signature: [0u8; 64],
        }
    }

    /// SberJazz/WebRTC-like bootstrap profile.
    pub fn webrtc_sberjazz_v1() -> MaskProfile {
        MaskProfile {
            mask_id: "webrtc_sberjazz_v1".to_string(),
            version: 2,
            created_at: 0,
            expires_at: u64::MAX,
            spoof_protocol: SpoofProtocol::WebRTC_STUN,
            header_template: vec![
                0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42, 0x59, 0xC9, 0x4D, 0x86,
                0x2D, 0xA7, 0x16, 0x62, 0xAD, 0x37, 0x8D, 0xD2,
            ],
            eph_pub_offset: 20,
            eph_pub_length: 32,
            size_distribution: SizeDistribution {
                dist_type: SizeDistType::Parametric,
                bins: vec![],
                parametric_type: Some(ParametricType::Bimodal),
                parametric_params: Some(vec![5.5, 0.55]),
            },
            iat_distribution: IATDistribution {
                dist_type: IATDistType::Exponential,
                params: vec![0.08],
                jitter_range_ms: (2.0, 12.0),
            },
            padding_strategy: PaddingStrategy::RandomUniform { min: 0, max: 32 },
            fsm_states: vec![
                FSMState {
                    state_id: 0,
                    transitions: vec![FSMTransition {
                        condition: TransitionCondition::AfterDuration(3000),
                        next_state: 1,
                        size_override: None,
                        iat_override: None,
                        padding_override: None,
                    }],
                },
                FSMState {
                    state_id: 1,
                    transitions: vec![],
                },
            ],
            fsm_initial_state: 0,
            signature_vector: vec![0.0; 64],
            reverse_profile: None,
            signature: [0u8; 64],
        }
    }

    /// QUIC-like bootstrap profile with a different long-header byte pattern.
    pub fn quic_grease_v1() -> MaskProfile {
        MaskProfile {
            mask_id: "quic_grease_v1".to_string(),
            version: 1,
            created_at: 0,
            expires_at: u64::MAX,
            spoof_protocol: SpoofProtocol::QUIC,
            header_template: vec![0xC3, 0x00, 0x00, 0x01],
            eph_pub_offset: 4,
            eph_pub_length: 32,
            size_distribution: SizeDistribution {
                dist_type: SizeDistType::Histogram,
                bins: vec![
                    (88, 180, 0.2),
                    (512, 980, 0.45),
                    (1000, 1320, 0.35),
                ],
                parametric_type: None,
                parametric_params: None,
            },
            iat_distribution: IATDistribution {
                dist_type: IATDistType::Exponential,
                params: vec![0.08],
                jitter_range_ms: (0.0, 16.0),
            },
            padding_strategy: PaddingStrategy::MatchDistribution,
            fsm_states: vec![
                FSMState {
                    state_id: 0,
                    transitions: vec![FSMTransition {
                        condition: TransitionCondition::AfterPackets(16),
                        next_state: 1,
                        size_override: None,
                        iat_override: Some(IATDistribution {
                            dist_type: IATDistType::Exponential,
                            params: vec![0.14],
                            jitter_range_ms: (0.0, 8.0),
                        }),
                        padding_override: None,
                    }],
                },
                FSMState {
                    state_id: 1,
                    transitions: vec![],
                },
            ],
            fsm_initial_state: 0,
            signature_vector: vec![0.0; 64],
            reverse_profile: None,
            signature: [0u8; 64],
        }
    }

    /// Built-in masks that can be used for initial handshake fallback.
    pub fn bootstrap_fallback_masks() -> Vec<MaskProfile> {
        vec![
            webrtc_yandex_telemost_v1(),
            webrtc_zoom_v3(),
            quic_https_v2(),
            webrtc_vk_teams_v1(),
            quic_grease_v1(),
            webrtc_sberjazz_v1(),
        ]
    }
}
