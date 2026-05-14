use vector_security_layer::{
    generate_signing_key, sign_request, verifying_key_bytes, Attestation, OperationKind, PolicyEngine,
    SecurityContext, SecurityEnvelope, SecurityEngine, SecurityRequest, Nonce, RegionId, WalletId,
};

fn build_request() -> (ed25519_dalek::SigningKey, SecurityRequest) {
    let signing_key = generate_signing_key();
    let mut request = SecurityRequest {
        protocol_version: 1,
        nonce: Nonce("nonce-test-1".into()),
        operation: OperationKind::Create,
        region_id: RegionId("region-a".into()),
        wallet_id: WalletId("wallet-a".into()),
        target_wallet: None,
        payload: br#"{"kind":"create"}"#.to_vec(),
        parent_event_hashes: vec![],
        signature: Vec::new(),
        timestamp: 1_710_000_123,
    };
    request.signature = sign_request(&signing_key, &request).expect("signed");
    (signing_key, request)
}

#[tokio::test]
async fn accepts_valid_request() {
    let (signing_key, request) = build_request();
    let ctx = SecurityContext::now(
        "wallet-a",
        "region-a",
        verifying_key_bytes(&signing_key.verifying_key()),
        0.88,
        0.70,
    );
    let engine = SecurityEngine::new(PolicyEngine::default());
    let envelope = SecurityEnvelope { request, context: ctx, attestations: vec![] };
    let decision = engine.validate_async(envelope).await.expect("valid");
    assert!(decision.accepted);
    assert!(decision.event.is_some());
}

#[tokio::test]
async fn rejects_replay() {
    let (signing_key, request) = build_request();
    let ctx = SecurityContext::now(
        "wallet-a",
        "region-a",
        verifying_key_bytes(&signing_key.verifying_key()),
        0.88,
        0.70,
    );
    let engine = SecurityEngine::new(PolicyEngine::default());
    let envelope = SecurityEnvelope { request: request.clone(), context: ctx.clone(), attestations: vec![] };
    let _ = engine.validate_async(envelope).await.expect("first request accepted");

    let envelope2 = SecurityEnvelope { request, context: ctx, attestations: vec![] };
    let err = engine.validate_async(envelope2).await.expect_err("replay should fail");
    assert!(format!("{err}").contains("replay"));
}

#[tokio::test]
async fn rejects_low_auth_ratio() {
    let (signing_key, request) = build_request();
    let ctx = SecurityContext::now(
        "wallet-a",
        "region-a",
        verifying_key_bytes(&signing_key.verifying_key()),
        0.10,
        0.70,
    );
    let engine = SecurityEngine::new(PolicyEngine::default());
    let envelope = SecurityEnvelope { request, context: ctx, attestations: vec![] };
    let err = engine.validate_async(envelope).await.expect_err("low auth should fail");
    assert!(format!("{err}").contains("auth ratio"));
}

#[tokio::test]
async fn accepts_supported_attestations() {
    let (signing_key, request) = build_request();
    let ctx = SecurityContext::now(
        "wallet-a",
        "region-a",
        verifying_key_bytes(&signing_key.verifying_key()),
        0.92,
        0.80,
    );
    let engine = SecurityEngine::new(PolicyEngine::default()).with_attestation_threshold(0.50);
    let envelope = SecurityEnvelope {
        request,
        context: ctx,
        attestations: vec![
            Attestation {
                issuer: "validator-1".into(),
                subject_wallet: WalletId("wallet-a".into()),
                score: 0.80,
                note: "healthy reputation".into(),
                issued_at: 1_710_000_100,
            },
            Attestation {
                issuer: "validator-2".into(),
                subject_wallet: WalletId("wallet-a".into()),
                score: 0.60,
                note: "secondary confirmation".into(),
                issued_at: 1_710_000_101,
            },
        ],
    };
    let decision = engine.validate_async(envelope).await.expect("attested");
    assert!(decision.accepted);
}

#[tokio::test]
async fn rejects_wallet_mismatch() {
    let (signing_key, request) = build_request();
    let ctx = SecurityContext::now(
        "wallet-b",
        "region-a",
        verifying_key_bytes(&signing_key.verifying_key()),
        0.88,
        0.70,
    );
    let engine = SecurityEngine::new(PolicyEngine::default());
    let envelope = SecurityEnvelope { request, context: ctx, attestations: vec![] };
    let err = engine.validate_async(envelope).await.expect_err("wallet mismatch should fail");
    assert!(format!("{err}").contains("wallet mismatch"));
}
