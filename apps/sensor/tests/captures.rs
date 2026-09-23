use mailent_domain::{EmailProtocol, KeyExchange, StartTlsState, TlsVersion};
use mailent_sensor::analyze::analyze;
use std::path::{Path, PathBuf};

fn zeek_binary() -> PathBuf {
    if Path::new("../../scripts/zeek-container").exists() {
        PathBuf::from("../../scripts/zeek-container")
    } else if Path::new("scripts/zeek-container").exists() {
        PathBuf::from("scripts/zeek-container")
    } else {
        PathBuf::from("zeek")
    }
}

fn fixture(name: &str) -> PathBuf {
    let direct = Path::new("../../fixtures/pcap").join(name);
    if direct.exists() {
        direct
    } else {
        Path::new("fixtures/pcap").join(name)
    }
}

#[tokio::test]
async fn test_smtp_starttls_pcap_and_pcapng() {
    let zeek = zeek_binary();

    for ext in ["pcap", "pcapng"] {
        let pcap = fixture(&format!("smtp_starttls.{ext}"));
        if !pcap.exists() {
            continue;
        }

        let result = analyze(&pcap, &zeek, "sensor-test", true)
            .await
            .expect("Should analyze successfully");

        assert_eq!(result.observations.len(), 1);
        let obs = &result.observations[0];

        assert_eq!(obs.protocol, EmailProtocol::Smtp);
        assert_eq!(obs.starttls_state, Some(StartTlsState::TlsEstablished));
        assert_eq!(obs.tls_version, Some(TlsVersion::Tls12));
        assert_eq!(obs.key_exchange, Some(KeyExchange::Ecdhe));

        let cipher = obs.cipher_suite.as_ref().expect("Cipher suite present");
        assert_eq!(cipher.name, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
        assert_eq!(cipher.id, Some(49199));

        let cert = obs.certificate.as_ref().expect("Certificate present");
        assert_eq!(
            cert.reference.sha256_fingerprint,
            "e714bc098be8370c1c82fa7d2cdaf60ca8534368198de0527ce887f5a84f99c6"
        );
        assert_eq!(cert.reference.subject, "CN=mail.mailent.test");
        assert_eq!(cert.reference.issuer, "CN=mail.mailent.test");

        let capture = obs.capture.as_ref().expect("Capture evidence present");
        assert_eq!(capture.tls_established, Some(true));

        let kinds: Vec<&str> = capture.timeline.iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(
            kinds,
            vec![
                "tcp_connected",
                "smtp_greeting",
                "protocol_identified",
                "ehlo",
                "starttls_advertised",
                "protocol_identified",
                "starttls_requested",
                "starttls_accepted",
                "tls_client_hello",
                "tls_server_hello",
                "certificate_observed",
                "key_exchange_ecdhe",
                "tls_established",
            ]
        );
    }
}

#[tokio::test]
async fn test_smtp_legacy_pcap_policy_findings() {
    let zeek = zeek_binary();
    let pcap = fixture("smtp_legacy.pcap");
    if !pcap.exists() {
        return;
    }

    let result = analyze(&pcap, &zeek, "sensor-test", true)
        .await
        .expect("Should analyze legacy pcap");

    assert_eq!(result.observations.len(), 1);
    let obs = &result.observations[0];

    assert_eq!(obs.protocol, EmailProtocol::Smtp);
    assert_eq!(obs.starttls_state, Some(StartTlsState::TlsEstablished));
    assert_eq!(obs.tls_version, Some(TlsVersion::Tls10));
    assert_eq!(obs.key_exchange, Some(KeyExchange::RsaStatic));

    // Evaluate policy on the parsed session
    let session = mailent_domain::EmailSession::from(obs);
    let pack_str = include_str!("../../../policies/modern/policy.yaml");
    let pack = mailent_policy::PolicyPack::from_yaml(pack_str).expect("Valid modern policy");

    let candidates = mailent_policy::evaluate(&session, &pack);
    let rule_ids: Vec<&str> = candidates.iter().map(|c| c.rule_id.as_str()).collect();

    assert!(rule_ids.contains(&"TLS_LEGACY_VERSION"));
    assert!(rule_ids.contains(&"NO_FORWARD_SECRECY"));
    assert!(rule_ids.contains(&"CERTIFICATE_EXPIRED"));
}

#[tokio::test]
async fn test_smtp_unused_pcap() {
    let zeek = zeek_binary();
    let pcap = fixture("smtp_unused.pcap");
    if !pcap.exists() {
        return;
    }

    let result = analyze(&pcap, &zeek, "sensor-test", true)
        .await
        .expect("Should analyze unused starttls pcap");

    assert_eq!(result.observations.len(), 1);
    let obs = &result.observations[0];

    assert_eq!(obs.protocol, EmailProtocol::Smtp);
    assert_eq!(obs.starttls_state, Some(StartTlsState::AdvertisedNotUsed));
    assert_eq!(obs.tls_version, None);
    assert_eq!(obs.cipher_suite, None);
    assert_eq!(obs.certificate, None);

    let capture = obs.capture.as_ref().unwrap();
    assert!(
        capture
            .gaps
            .iter()
            .any(|g| g.contains("TLS negotiation unavailable"))
    );
}

#[tokio::test]
async fn test_imap_and_pop3_starttls() {
    let zeek = zeek_binary();

    // IMAP
    let imap_pcap = fixture("imap_starttls.pcap");
    if imap_pcap.exists() {
        let res = analyze(&imap_pcap, &zeek, "sensor-test", true)
            .await
            .expect("IMAP analysis");
        assert_eq!(res.observations.len(), 1);
        let obs = &res.observations[0];
        assert_eq!(obs.protocol, EmailProtocol::Imap);
        assert_eq!(obs.starttls_state, Some(StartTlsState::TlsEstablished));
        assert_eq!(obs.tls_version, Some(TlsVersion::Tls12));
        assert_eq!(obs.key_exchange, Some(KeyExchange::Ecdhe));
    }

    // POP3
    let pop3_pcap = fixture("pop3_stls.pcap");
    if pop3_pcap.exists() {
        let res = analyze(&pop3_pcap, &zeek, "sensor-test", true)
            .await
            .expect("POP3 analysis");
        assert_eq!(res.observations.len(), 1);
        let obs = &res.observations[0];
        assert_eq!(obs.protocol, EmailProtocol::Pop3);
        assert_eq!(obs.starttls_state, Some(StartTlsState::TlsEstablished));
        assert_eq!(obs.tls_version, Some(TlsVersion::Tls12));
        assert_eq!(obs.key_exchange, Some(KeyExchange::Ecdhe));
    }
}

#[tokio::test]
async fn test_truncated_and_midstream_captures() {
    let zeek = zeek_binary();

    // Truncated capture
    let trunc_pcap = fixture("smtp_truncated.pcap");
    if trunc_pcap.exists() {
        let res = analyze(&trunc_pcap, &zeek, "sensor-test", true)
            .await
            .expect("Truncated capture analysis");
        assert_eq!(res.observations.len(), 1);
        let obs = &res.observations[0];
        assert_eq!(obs.starttls_state, Some(StartTlsState::Accepted));
        let capture = obs.capture.as_ref().unwrap();
        assert!(
            capture
                .gaps
                .iter()
                .any(|g| g.contains("capture may be truncated"))
        );
    }

    // Midstream capture (starts mid-stream missing TCP SYN and initial EHLO banner)
    let mid_pcap = fixture("smtp_midstream.pcap");
    if mid_pcap.exists() {
        let res = analyze(&mid_pcap, &zeek, "sensor-test", true)
            .await
            .expect("Midstream capture analysis");
        // Zeek cannot reconstruct SMTP stream when initial protocol greeting is absent midstream
        assert_eq!(res.observations.len(), 0);
        assert!(
            res.warnings
                .iter()
                .any(|w| w.contains("No email sessions found"))
        );
    }
}

#[tokio::test]
async fn test_empty_pcap() {
    let zeek = zeek_binary();
    let pcap = fixture("empty.pcap");
    if !pcap.exists() {
        return;
    }

    let res = analyze(&pcap, &zeek, "sensor-test", true)
        .await
        .expect("Empty pcap analysis");
    assert_eq!(res.observations.len(), 0);
    assert!(
        res.warnings
            .iter()
            .any(|w| w.contains("No email sessions found"))
    );
}

#[tokio::test]
async fn test_failure_cases() {
    let zeek = zeek_binary();

    // 1. Nonexistent capture
    let err = analyze(
        Path::new("fixtures/pcap/nonexistent.pcap"),
        &zeek,
        "sensor-test",
        true,
    )
    .await;
    assert!(err.is_err());

    // 2. 0-byte capture
    let temp = tempfile::NamedTempFile::new().unwrap();
    let err = analyze(temp.path(), &zeek, "sensor-test", true).await;
    assert!(err.is_err());
    let msg = err.unwrap_err().to_string();
    assert!(msg.contains("capture file is empty"));

    // 3. Nonexistent Zeek binary
    let valid_pcap = fixture("empty.pcap");
    if valid_pcap.exists() {
        let err = analyze(
            &valid_pcap,
            Path::new("/nonexistent/zeek/bin/zeek"),
            "sensor-test",
            true,
        )
        .await;
        assert!(err.is_err());
    }
}
