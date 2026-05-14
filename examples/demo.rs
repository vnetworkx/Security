use vector_security_layer::{
    generate_signing_key, sign_request, verifying_key_bytes, Attestation, OperationKind, PolicyEngine,
    SecurityContext, SecurityEnvelope, SecurityEngine, SecurityRequest, Nonce, RegionId, WalletId,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let signing_key = generate_signing_key();
    let verifying_key = signing_key.verifying_key();

    let mut request = SecurityRequest {
        protocol_version: 1,
        nonce: Nonce("nonce-0001".into()),
        operation: OperationKind::Transfer,
        region_id: RegionId("region-alpha".into()),
        wallet_id: WalletId("wallet-001".into()),
        target_wallet: Some(WalletId("wallet-002".into())),
        payload: br#"{"amount":125,"token":"vUSD","purpose":"settlement"}"#.to_vec(),
        parent_event_hashes: vec!["parent-hash-a".into(), "parent-hash-b".into()],
        signature: Vec::new(),
        timestamp: 1_710_000_000,
    };

    request.signature = sign_request(&signing_key, &request)?;

    let ctx = SecurityContext::now(
        "wallet-001",
        "region-alpha",
        verifying_key_bytes(&verifying_key),
        0.91,
        0.75,
    );

    let engine = SecurityEngine::new(PolicyEngine::default()).with_attestation_threshold(0.50);

    let attestations = vec![
        Attestation {
            issuer: "validator-a".into(),
            subject_wallet: WalletId("wallet-001".into()),
            score: 0.88,
            note: "request matches prior network reputation".into(),
            issued_at: 1_710_000_000,
        },
        Attestation {
            issuer: "validator-b".into(),
            subject_wallet: WalletId("wallet-001".into()),
            score: 0.84,
            note: "wallet binding and signature trail look consistent".into(),
            issued_at: 1_710_000_000,
        },
    ];

    let envelope = SecurityEnvelope { request, context: ctx, attestations };
    let decision = engine.validate_async(envelope).await?;

    println!("accepted={}", decision.accepted);
    if let Some(event) = decision.event {
        println!("event_hash={}", event.event_hash);
        println!("event_id={}", event.event_id.0);
        println!("certified={}", event.certified);
        println!("attestation_score={}", event.attestation_score);
        println!("drain_applied={}", event.drain_applied);
    }

    Ok(())
}
