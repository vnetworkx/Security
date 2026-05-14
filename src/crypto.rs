use crate::errors::{SecurityError, SecurityResult};
use crate::types::{SecurityEvent, SecurityKeyPair, SecurityRequest};
use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;

pub fn generate_signing_key() -> SigningKey {
    let mut csprng = OsRng;
    SigningKey::generate(&mut csprng)
}

pub fn verifying_key_bytes(verifying_key: &VerifyingKey) -> Vec<u8> {
    verifying_key.to_bytes().to_vec()
}

pub fn sign_request(signing_key: &SigningKey, request: &SecurityRequest) -> SecurityResult<Vec<u8>> {
    let bytes = canonical_request_bytes(request)?;
    Ok(signing_key.sign(&bytes).to_bytes().to_vec())
}

pub fn verify_request_signature(verifying_key: &VerifyingKey, request: &SecurityRequest) -> SecurityResult<()> {
    if request.signature.len() != 64 {
        return Err(SecurityError::InvalidSignatureLength);
    }
    let bytes = canonical_request_bytes(request)?;
    let signature = Signature::try_from(request.signature.as_slice()).map_err(|_| SecurityError::InvalidSignature)?;
    verifying_key.verify(&bytes, &signature).map_err(|_| SecurityError::InvalidSignature)
}

pub fn hash_request(request: &SecurityRequest) -> SecurityResult<String> {
    let bytes = canonical_request_bytes(request)?;
    Ok(hash_bytes(&bytes))
}

pub fn hash_event(event: &SecurityEvent) -> SecurityResult<String> {
    let bytes = canonical_event_bytes(event)?;
    Ok(hash_bytes(&bytes))
}

pub fn hash_bytes(bytes: &[u8]) -> String {
    let hash = blake3::hash(bytes);
    hash.to_hex().to_string()
}

/// Produces a domain-separated hash that can be used for replay caches,
/// persistence indexes, and event fingerprints.
pub fn domain_hash(domain: &str, bytes: &[u8]) -> String {
    let mut hasher = Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(&[0]);
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

pub fn public_key_from_bytes(bytes: &[u8]) -> SecurityResult<VerifyingKey> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SecurityError::InvalidRequest("public key must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&arr).map_err(|_| SecurityError::InvalidRequest("invalid public key bytes".into()))
}

pub fn keypair_from_signing_key(signing_key: SigningKey) -> SecurityKeyPair {
    SecurityKeyPair::from_signing_key(signing_key)
}

pub fn canonical_request_bytes(request: &SecurityRequest) -> SecurityResult<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(&request.protocol_version.to_be_bytes());
    push_str(&mut out, &request.nonce.0);
    push_str(&mut out, &request.operation.to_string());
    push_str(&mut out, &request.region_id.0);
    push_str(&mut out, &request.wallet_id.0);
    match &request.target_wallet {
        Some(w) => push_str(&mut out, &w.0),
        None => push_str(&mut out, "<none>"),
    }
    push_bytes(&mut out, &request.payload);
    for h in &request.parent_event_hashes {
        push_str(&mut out, h);
    }
    out.extend_from_slice(&request.timestamp.to_be_bytes());
    Ok(out)
}

pub fn canonical_event_bytes(event: &SecurityEvent) -> SecurityResult<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(&event.protocol_version.to_be_bytes());
    push_str(&mut out, &event.event_id.0);
    for h in &event.parent_hashes {
        push_str(&mut out, h);
    }
    push_str(&mut out, &event.region_id.0);
    push_str(&mut out, &event.entity_id.0);
    push_str(&mut out, &event.operation.to_string());
    push_str(&mut out, &event.request_hash);
    push_str(&mut out, &event.payload_hash);
    out.extend_from_slice(&event.auth_ratio.to_bits().to_be_bytes());
    out.extend_from_slice(&event.attestation_score.to_bits().to_be_bytes());
    out.extend_from_slice(&event.drain_applied.to_bits().to_be_bytes());
    out.push(u8::from(event.certified));
    push_bytes(&mut out, &event.actor_pk);
    push_str(&mut out, &event.nonce.0);
    out.extend_from_slice(&event.timestamp.to_be_bytes());
    push_bytes(&mut out, &event.signature);
    Ok(out)
}

fn push_str(buf: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn push_bytes(buf: &mut Vec<u8>, value: &[u8]) {
    buf.extend_from_slice(&(value.len() as u64).to_be_bytes());
    buf.extend_from_slice(value);
}
