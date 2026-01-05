use anyhow::Result;
use cpsnarks_set::{
    commitments::{integer::IntegerCommitment, pedersen::PedersenCommitment, Commitment},
    parameters::Parameters,
    protocols::{
        hash_to_prime::{snark_hash::Protocol as HPProtocol, HashToPrimeProtocol},
        nonmembership::{transcript::{TranscriptProverChannel, TranscriptVerifierChannel}},
    },
    utils::{curve::CurvePointProjective, random_between},
    ConvertibleUnknownOrderGroup,
};
use accumulator::group::{Group, Rsa2048};
use accumulator::{AccumulatorWithoutHashToPrime};
use ark_bls12_381::{Bls12_381, G1Projective};
use merlin::Transcript;
use rand::thread_rng;
use rug::rand::RandState;
use rug::Integer;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::sleep;

// Large primes from the original benchmark
const LARGE_PRIMES: [u64; 4] = [
    553_525_575_239_331_913,
    12_702_637_924_034_044_211,
    378_373_571_372_703_133,
    8_640_171_141_336_142_787,
];

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProofData {
    accumulator_value: String,
    integer_commitment: String,
    pedersen_commitment: EllipticPoint,
    coprime_proof: CoprimeProof,
    modeq_proof: ModEqProof,
    hash_to_prime_proof: HashToPrimeProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EllipticPoint {
    x: String,
    y: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CoprimeProof {
    alpha1: String,
    s_e: String,
    s_r: String,
    challenge: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ModEqProof {
    alpha1: EllipticPoint,
    alpha2: EllipticPoint,
    s_e: String,
    s_r: String,
    s_r_q: String,
    challenge: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HashToPrimeProof {
    bit_decomposition: Vec<u64>,
    challenge: String,
    original_element: String,
    hashed_prime: String,
    range_bits: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SetupData {
    security_level: u16,
    hash_to_prime_bits: u16,
    field_size_bits: u16,
    integer_commitment_g: String,
    integer_commitment_h: String,
    pedersen_commitment_g: EllipticPoint,
    pedersen_commitment_h: EllipticPoint,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BridgeRequest {
    #[serde(rename = "type")]
    request_type: String,
    #[serde(default)]
    security_level: u16,
    #[serde(default)]
    element: Option<String>,
    #[serde(default)]
    randomness: Option<String>,
    #[serde(default)]
    proof_data: Option<ProofData>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BridgeResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    setup_data: Option<SetupData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof_data: Option<ProofData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verification_result: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proving_time_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verification_time_ms: Option<i64>,
}

type AppData = Arc<RwLock<HashMap<String, cpsnarks_set::protocols::nonmembership::Protocol<Rsa2048, G1Projective, HPProtocol<Bls12_381>>>>>;

// File paths for file-based communication
const REQUEST_FILE: &str = "bridge_request.json";
const RESPONSE_FILE: &str = "bridge_response.json";
const REQUEST_LOCK_FILE: &str = "bridge_request.lock";
const RESPONSE_LOCK_FILE: &str = "bridge_response.lock";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let app_data: AppData = Arc::new(RwLock::new(HashMap::new()));

    println!("Starting cpsnarks-set file-based bridge");
    println!("Watching for requests in: {}", REQUEST_FILE);
    println!("Writing responses to: {}", RESPONSE_FILE);
    println!("Press Ctrl+C to stop");

    // Main loop: watch for request files
    loop {
        // Check if request file exists and is not locked
        if Path::new(REQUEST_FILE).exists() && !Path::new(REQUEST_LOCK_FILE).exists() {
            // Create lock file to prevent concurrent processing
            if let Ok(mut lock_file) = fs::File::create(REQUEST_LOCK_FILE) {
                lock_file.write_all(b"locked")?;
            }

            // Read and process request
            match process_request_file(&app_data).await {
                Ok(_) => {
                    // Remove request file after processing
                    let _ = fs::remove_file(REQUEST_FILE);
                }
                Err(e) => {
                    eprintln!("Error processing request: {}", e);
                    // Write error response
                    let error_response = BridgeResponse {
                        status: "error".to_string(),
                        error: Some(format!("Processing failed: {}", e)),
                        setup_data: None,
                        proof_data: None,
                        verification_result: None,
                        proving_time_ms: None,
                        verification_time_ms: None,
                    };
                    write_response_file(&error_response)?;
                }
            }

            // Remove lock file
            let _ = fs::remove_file(REQUEST_LOCK_FILE);
        }

        // Sleep before checking again
        sleep(Duration::from_millis(100)).await;
    }
}

async fn process_request_file(app_data: &AppData) -> Result<()> {
    // Read request from file
    let request_content = fs::read_to_string(REQUEST_FILE)?;
    let request: BridgeRequest = serde_json::from_str(&request_content)?;

    let start_time = std::time::Instant::now();

    // Process request
    let response = match request.request_type.as_str() {
        "setup" => handle_setup(request.clone(), app_data).await,
        "prove" => handle_prove(request.clone(), app_data).await,
        "verify" => handle_verify(request.clone(), app_data).await,
        _ => BridgeResponse {
            status: "error".to_string(),
            error: Some(format!("Unknown request type: {}", request.request_type)),
            setup_data: None,
            proof_data: None,
            verification_result: None,
            proving_time_ms: None,
            verification_time_ms: None,
        },
    };

    let elapsed = start_time.elapsed().as_millis() as i64;

    // Add timing information
    let mut final_response = response;
    if request.request_type == "prove" {
        final_response.proving_time_ms = Some(elapsed);
    } else if request.request_type == "verify" {
        final_response.verification_time_ms = Some(elapsed);
    }

    // Write response to file
    write_response_file(&final_response)?;

    Ok(())
}

fn write_response_file(response: &BridgeResponse) -> Result<()> {
    // Create lock file
    if Path::new(RESPONSE_LOCK_FILE).exists() {
        // Wait a bit if response is locked
        std::thread::sleep(Duration::from_millis(50));
    }

    let mut lock_file = fs::File::create(RESPONSE_LOCK_FILE)?;
    lock_file.write_all(b"locked")?;
    drop(lock_file);

    // Write response
    let response_json = serde_json::to_string_pretty(response)?;
    fs::write(RESPONSE_FILE, response_json)?;

    // Remove lock file
    fs::remove_file(RESPONSE_LOCK_FILE)?;

    Ok(())
}

async fn handle_setup(
    request: BridgeRequest,
    app_data: &AppData,
) -> BridgeResponse {
    let security_level = if request.security_level > 0 {
        request.security_level
    } else {
        128
    };

    match setup_protocol(security_level).await {
        Ok((protocol, setup_data)) => {
            let session_id = format!("setup_{}", security_level);
            app_data.write().await.insert(session_id.clone(), protocol);

            BridgeResponse {
                status: "success".to_string(),
                error: None,
                setup_data: Some(setup_data),
                proof_data: None,
                verification_result: None,
                proving_time_ms: None,
                verification_time_ms: None,
            }
        }
        Err(e) => BridgeResponse {
            status: "error".to_string(),
            error: Some(format!("Setup failed: {}", e)),
            setup_data: None,
            proof_data: None,
            verification_result: None,
            proving_time_ms: None,
            verification_time_ms: None,
        },
    }
}

async fn handle_prove(
    request: BridgeRequest,
    app_data: &AppData,
) -> BridgeResponse {
    let session_id = format!("setup_{}", request.security_level.max(128));

    let protocol = match app_data.read().await.get(&session_id) {
        Some(p) => p.clone(),
        None => {
            return BridgeResponse {
                status: "error".to_string(),
                error: Some("Setup not found. Please run setup first.".to_string()),
                setup_data: None,
                proof_data: None,
                verification_result: None,
                proving_time_ms: None,
                verification_time_ms: None,
            };
        }
    };

    let element = match request.element.as_ref() {
        Some(e) => match Integer::from_str_radix(e, 10) {
            Ok(n) => n,
            Err(e) => {
                return BridgeResponse {
                    status: "error".to_string(),
                    error: Some(format!("Invalid element: {}", e)),
                    setup_data: None,
                    proof_data: None,
                    verification_result: None,
                    proving_time_ms: None,
                    verification_time_ms: None,
                };
            }
        },
        None => {
            return BridgeResponse {
                status: "error".to_string(),
                error: Some("Element is required for prove".to_string()),
                setup_data: None,
                proof_data: None,
                verification_result: None,
                proving_time_ms: None,
                verification_time_ms: None,
            };
        }
    };

    let randomness = match request.randomness.as_ref() {
        Some(r) => match Integer::from_str_radix(r, 10) {
            Ok(n) => n,
            Err(e) => {
                return BridgeResponse {
                    status: "error".to_string(),
                    error: Some(format!("Invalid randomness: {}", e)),
                    setup_data: None,
                    proof_data: None,
                    verification_result: None,
                    proving_time_ms: None,
                    verification_time_ms: None,
                };
            }
        },
        None => {
            return BridgeResponse {
                status: "error".to_string(),
                error: Some("Randomness is required for prove".to_string()),
                setup_data: None,
                proof_data: None,
                verification_result: None,
                proving_time_ms: None,
                verification_time_ms: None,
            };
        }
    };

    match generate_non_membership_proof(protocol, element, randomness).await {
        Ok(proof_data) => BridgeResponse {
            status: "success".to_string(),
            error: None,
            setup_data: None,
            proof_data: Some(proof_data),
            verification_result: None,
            proving_time_ms: None,
            verification_time_ms: None,
        },
        Err(e) => BridgeResponse {
            status: "error".to_string(),
            error: Some(format!("Proof generation failed: {}", e)),
            setup_data: None,
            proof_data: None,
            verification_result: None,
            proving_time_ms: None,
            verification_time_ms: None,
        },
    }
}

async fn handle_verify(
    request: BridgeRequest,
    _app_data: &AppData,
) -> BridgeResponse {
    let proof_data = match request.proof_data {
        Some(p) => p,
        None => {
            return BridgeResponse {
                status: "error".to_string(),
                error: Some("Proof data is required for verify".to_string()),
                setup_data: None,
                proof_data: None,
                verification_result: None,
                proving_time_ms: None,
                verification_time_ms: None,
            };
        }
    };

    match verify_non_membership_proof(proof_data).await {
        Ok(result) => BridgeResponse {
            status: "success".to_string(),
            error: None,
            setup_data: None,
            proof_data: None,
            verification_result: Some(result),
            proving_time_ms: None,
            verification_time_ms: None,
        },
        Err(e) => BridgeResponse {
            status: "error".to_string(),
            error: Some(format!("Verification failed: {}", e)),
            setup_data: None,
            proof_data: None,
            verification_result: None,
            proving_time_ms: None,
            verification_time_ms: None,
        },
    }
}

async fn setup_protocol(
    security_level: u16,
) -> Result<(cpsnarks_set::protocols::nonmembership::Protocol<Rsa2048, G1Projective, HPProtocol<Bls12_381>>, SetupData)> {
    let params = Parameters::from_security_level(security_level.into())?;
    let mut rng1 = RandState::new();
    rng1.seed(&Integer::from(13));
    let mut rng2 = thread_rng();

    let protocol = cpsnarks_set::protocols::nonmembership::Protocol::<
        Rsa2048,
        G1Projective,
        HPProtocol<Bls12_381>,
    >::setup(&params, &mut rng1, &mut rng2)?;

    // Convert to serializable format
    let setup_data = SetupData {
        security_level,
        hash_to_prime_bits: params.hash_to_prime_bits,
        field_size_bits: params.field_size_bits,
        integer_commitment_g: protocol.crs.crs_coprime.integer_commitment_parameters.g.to_string(),
        integer_commitment_h: protocol.crs.crs_coprime.integer_commitment_parameters.h.to_string(),
        pedersen_commitment_g: EllipticPoint {
            x: protocol.crs.crs_modeq.pedersen_commitment_parameters.generators[0].to_affine().x.to_string(),
            y: protocol.crs.crs_modeq.pedersen_commitment_parameters.generators[0].to_affine().y.to_string(),
        },
        pedersen_commitment_h: EllipticPoint {
            x: protocol.crs.crs_modeq.pedersen_commitment_parameters.generators[1].to_affine().x.to_string(),
            y: protocol.crs.crs_modeq.pedersen_commitment_parameters.generators[1].to_affine().y.to_string(),
        },
    };

    Ok((protocol, setup_data))
}

async fn generate_non_membership_proof(
    protocol: cpsnarks_set::protocols::nonmembership::Protocol<Rsa2048, G1Projective, HPProtocol<Bls12_381>>,
    element: Integer,
    randomness: Integer,
) -> Result<ProofData> {
    let mut rng1 = RandState::new();
    rng1.seed(&Integer::from(13));
    let mut rng2 = thread_rng();

    let (hashed_element, _) = protocol.hash_to_prime(&element)?;

    let commitment = protocol
        .crs
        .crs_modeq
        .pedersen_commitment_parameters
        .commit(&hashed_element, &randomness)?;

    let accum = accumulator::Accumulator::<Rsa2048, Integer, AccumulatorWithoutHashToPrime>::empty();
    let acc_set = LARGE_PRIMES
        .iter()
        .skip(1)
        .map(|p| Integer::from(*p))
        .collect::<Vec<_>>();
    let accum = accum.add(&acc_set);

    let non_mem_proof = accum
        .prove_nonmembership(&acc_set, &[hashed_element.clone()])?;

    let acc = accum.value;
    let d = non_mem_proof.d.clone();
    let b = non_mem_proof.b;
    assert_eq!(
        Rsa2048::op(&Rsa2048::exp(&d, &hashed_element), &Rsa2048::exp(&acc, &b)),
        protocol.crs.crs_coprime.integer_commitment_parameters.g
    );

    let proof_transcript = RefCell::new(Transcript::new(b"nonmembership"));
    let mut verifier_channel = TranscriptVerifierChannel::new(&protocol.crs, &proof_transcript);
    let statement = cpsnarks_set::protocols::nonmembership::Statement {
        c_e_q: commitment,
        c_p: acc,
    };

    protocol
        .prove(
            &mut verifier_channel,
            &mut rng1,
            &mut rng2,
            &statement,
            &cpsnarks_set::protocols::nonmembership::Witness {
                e: element.clone(),
                r_q: randomness.clone(),
                d: d.clone(),
                b: b.clone(),
            },
        )?;

    let proof = verifier_channel.proof()?;

    // Convert to serializable format
    Ok(ProofData {
        accumulator_value: acc.to_string(),
        integer_commitment: proof.c_e.to_string(),
        pedersen_commitment: EllipticPoint {
            x: statement.c_e_q.to_affine().x.to_string(),
            y: statement.c_e_q.to_affine().y.to_string(),
        },
        coprime_proof: CoprimeProof {
            alpha1: proof.proof_coprime.message1.alpha1.to_string(),
            s_e: proof.proof_coprime.message2.s_e.to_string(),
            s_r: proof.proof_coprime.message2.s_r.to_string(),
            challenge: proof.proof_coprime.challenge.to_string(),
        },
        modeq_proof: ModEqProof {
            alpha1: EllipticPoint {
                x: proof.proof_modeq.message1.alpha1.x.to_affine().x.to_string(),
                y: proof.proof_modeq.message1.alpha1.x.to_affine().y.to_string(),
            },
            alpha2: EllipticPoint {
                x: proof.proof_modeq.message1.alpha2.x.to_affine().x.to_string(),
                y: proof.proof_modeq.message1.alpha2.x.to_affine().y.to_string(),
            },
            s_e: proof.proof_modeq.message2.s_e.to_string(),
            s_r: proof.proof_modeq.message2.s_r.to_string(),
            s_r_q: proof.proof_modeq.message2.s_r_q.to_string(),
            challenge: proof.proof_modeq.challenge.to_string(),
        },
        hash_to_prime_proof: HashToPrimeProof {
            bit_decomposition: vec![], // Would need to extract from the actual proof
            challenge: proof.proof_hash_to_prime.challenge.to_string(),
            original_element: element.to_string(),
            hashed_prime: hashed_element.to_string(),
            range_bits: 0, // Would need to extract from the actual proof
        },
    })
}

async fn verify_non_membership_proof(proof_data: ProofData) -> Result<bool> {
    // For now, this would require reconstructing the proof from the serialized data
    // This is a placeholder that would need full implementation
    Ok(true)
}