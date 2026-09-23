use mailent_domain::{EmailProtocol, StartTlsState};
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

fn edge_fixture(name: &str) -> PathBuf {
    let direct = Path::new("../../fixtures/pcap_edge").join(name);
    if direct.exists() {
        direct
    } else {
        Path::new("fixtures/pcap_edge").join(name)
    }
}

#[tokio::test]
async fn test_corrupted_and_truncated_edge_pcaps() {
    let zeek = zeek_binary();

    // 1. Truncated header (< 24 bytes) - rejected immediately before invoking Zeek
    let trunc = edge_fixture("truncated_header.pcap");
    if trunc.exists() {
        // analyze creates a copy and checks size == 0, but input file is 14 bytes
        // Zeek will fail to read header or sensor rejects
        let res = analyze(&trunc, &zeek, "sensor-test", true).await;
        // Should either error or produce 0 observations
        if let Ok(analysis) = res {
            assert_eq!(analysis.observations.len(), 0);
        }
    }

    // 2. Corrupted packet length (packet header claims 50,000 bytes, file has 32 bytes)
    let corrupted = edge_fixture("corrupted_packet_len.pcap");
    if corrupted.exists() {
        let res = analyze(&corrupted, &zeek, "sensor-test", true).await;
        assert!(res.is_err(), "Zeek must detect truncated dump file");
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains("truncated dump") || err_msg.contains("failed to read a packet"));
    }
}

#[tokio::test]
async fn test_endian_and_timestamp_variants() {
    let zeek = zeek_binary();

    for name in [
        "nanosecond_le.pcap",
        "nanosecond_be.pcap",
        "microsecond_be.pcap",
        "zero_snaplen.pcap",
    ] {
        let pcap = edge_fixture(name);
        if !pcap.exists() {
            continue;
        }
        let res = analyze(&pcap, &zeek, "sensor-test", true).await;
        assert!(res.is_ok(), "Header variant {} should parse cleanly", name);
        let analysis = res.unwrap();
        assert_eq!(
            analysis.observations.len(),
            0,
            "Empty variant should have 0 observations"
        );
    }
}

#[tokio::test]
async fn test_smtp_huge_greeting_and_dos_resilience() {
    let zeek = zeek_binary();
    let pcap = edge_fixture("smtp_huge_greeting.pcap");
    if !pcap.exists() {
        return;
    }

    let res = analyze(&pcap, &zeek, "sensor-test", true)
        .await
        .expect("Should survive 32KB greeting without crashing");

    assert_eq!(res.observations.len(), 1);
    let obs = &res.observations[0];
    assert_eq!(obs.protocol, EmailProtocol::Smtp);
    assert_eq!(obs.flow.dst_port, 25);
}

#[tokio::test]
async fn test_smtp_downgrade_and_auth_exposed_pcap() {
    let zeek = zeek_binary();
    let pcap = edge_fixture("smtp_downgrade_auth_exposed.pcap");
    if !pcap.exists() {
        return;
    }

    let res = analyze(&pcap, &zeek, "sensor-test", true)
        .await
        .expect("Should analyze downgrade pcap");

    assert_eq!(res.observations.len(), 1);
    let obs = &res.observations[0];
    assert_eq!(obs.protocol, EmailProtocol::Smtp);
    // Client sent plaintext AUTH LOGIN after STARTTLS 454 error -> PlaintextContinuation!
    assert_eq!(
        obs.starttls_state,
        Some(StartTlsState::PlaintextContinuation)
    );

    // Policy evaluation must flag this plaintext continuation as STARTTLS_MISSING
    let session = mailent_domain::EmailSession::from(obs);
    let pack = mailent_policy::PolicyPack::modern();
    let findings = mailent_policy::evaluate(&session, &pack);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "STARTTLS_MISSING");
    assert!(
        findings[0]
            .description
            .contains("continued in plaintext without securing transport")
    );
}

#[tokio::test]
async fn test_smtp_nonstandard_port_2525() {
    let zeek = zeek_binary();
    let pcap = edge_fixture("smtp_port_2525.pcap");
    if !pcap.exists() {
        return;
    }

    let res = analyze(&pcap, &zeek, "sensor-test", true)
        .await
        .expect("Should analyze non-standard port pcap");

    assert_eq!(res.observations.len(), 1);
    let obs = &res.observations[0];
    assert_eq!(obs.protocol, EmailProtocol::Smtp);
    assert_eq!(obs.flow.dst_port, 2525);
    assert_eq!(obs.starttls_state, Some(StartTlsState::Advertised));
}

#[tokio::test]
async fn test_pop3_stls_rejected() {
    let zeek = zeek_binary();
    let pcap = edge_fixture("pop3_stls_rejected.pcap");
    if !pcap.exists() {
        return;
    }

    let res = analyze(&pcap, &zeek, "sensor-test", true)
        .await
        .expect("Should analyze POP3 rejected pcap");

    assert_eq!(res.observations.len(), 1);
    let obs = &res.observations[0];
    assert_eq!(obs.protocol, EmailProtocol::Pop3);
    assert_eq!(obs.flow.dst_port, 110);
    // Client sent USER and PASS in plaintext after -ERR TLS -> PlaintextContinuation!
    assert_eq!(
        obs.starttls_state,
        Some(StartTlsState::PlaintextContinuation)
    );
}

#[tokio::test]
async fn test_multi_protocol_mixed_traffic() {
    let zeek = zeek_binary();
    let pcap = edge_fixture("multi_protocol_mixed.pcap");
    if !pcap.exists() {
        return;
    }

    let res = analyze(&pcap, &zeek, "sensor-test", true)
        .await
        .expect("Should handle mixed protocols");

    // Both SMTP and POP3 sessions in the same capture should be reconstructed
    assert!(!res.observations.is_empty());
}

#[tokio::test]
async fn test_ipv6_smtp_session() {
    let zeek = zeek_binary();
    let pcap = edge_fixture("ipv6_smtp.pcap");
    if !pcap.exists() {
        return;
    }

    let res = analyze(&pcap, &zeek, "sensor-test", true)
        .await
        .expect("Should parse IPv6 SMTP stream");

    assert_eq!(res.observations.len(), 1);
    let obs = &res.observations[0];
    assert_eq!(obs.protocol, EmailProtocol::Smtp);
    assert_eq!(obs.flow.src_ip, "2001:db8::1");
    assert_eq!(obs.flow.dst_ip, "2001:db8::2");
    assert_eq!(obs.flow.dst_port, 25);
    assert_eq!(
        obs.flow.to_string(),
        "[2001:db8::1]:51234 -> [2001:db8::2]:25"
    );
}

#[tokio::test]
async fn test_vlan_tagged_smtp_session() {
    let zeek = zeek_binary();
    let pcap = edge_fixture("vlan_tagged_smtp.pcap");
    if !pcap.exists() {
        return;
    }

    let res = analyze(&pcap, &zeek, "sensor-test", true)
        .await
        .expect("Should parse 802.1Q VLAN tagged SMTP stream");

    assert_eq!(res.observations.len(), 1);
    let obs = &res.observations[0];
    assert_eq!(obs.protocol, EmailProtocol::Smtp);
    assert_eq!(obs.flow.dst_port, 25);
}

#[tokio::test]
async fn test_tcp_out_of_order_stream() {
    let zeek = zeek_binary();
    let pcap = edge_fixture("tcp_out_of_order.pcap");
    if !pcap.exists() {
        return;
    }

    let res = analyze(&pcap, &zeek, "sensor-test", true)
        .await
        .expect("Should reassemble out-of-order TCP stream");

    // Zeek should reassemble the out-of-order greeting: "220 mail.test ESMTP\r\n"
    assert_eq!(res.observations.len(), 1);
    let obs = &res.observations[0];
    assert_eq!(obs.protocol, EmailProtocol::Smtp);
}

#[tokio::test]
async fn test_non_mail_traffic_rejection() {
    let zeek = zeek_binary();

    for name in [
        "non_mail_http_on_port_25.pcap",
        "non_mail_ssh_on_port_25.pcap",
    ] {
        let pcap = edge_fixture(name);
        if !pcap.exists() {
            continue;
        }

        let res = analyze(&pcap, &zeek, "sensor-test", true)
            .await
            .expect("Should safely analyze non-mail capture without panic");

        assert_eq!(
            res.observations.len(),
            0,
            "Capture {} with HTTP/SSH should yield 0 email observations",
            name
        );
        assert!(
            res.warnings
                .iter()
                .any(|w| w.contains("No email sessions found")),
            "Capture {} should produce a warning indicating no email sessions",
            name
        );
    }
}

#[tokio::test]
async fn test_imap_unencrypted_plaintext() {
    let zeek = zeek_binary();
    let pcap = edge_fixture("imap_unencrypted_login.pcap");
    if !pcap.exists() {
        return;
    }

    let res = analyze(&pcap, &zeek, "sensor-test", true)
        .await
        .expect("Should analyze IMAP unencrypted traffic");

    assert_eq!(res.observations.len(), 1);
    let obs = &res.observations[0];
    assert_eq!(obs.protocol, EmailProtocol::Imap);
    assert_eq!(obs.flow.dst_port, 143);
    assert_eq!(obs.starttls_state, Some(StartTlsState::NotAdvertised));
}

#[tokio::test]
async fn test_smtp_mid_handshake_rst() {
    let zeek = zeek_binary();
    let pcap = edge_fixture("smtp_mid_handshake_rst.pcap");
    if !pcap.exists() {
        return;
    }

    let res = analyze(&pcap, &zeek, "sensor-test", true)
        .await
        .expect("Should analyze mid-handshake RST capture");

    assert_eq!(res.observations.len(), 1);
    let obs = &res.observations[0];
    assert_eq!(obs.protocol, EmailProtocol::Smtp);
    // Since RST occurred right after 220 Ready to start TLS, TLS was not established
    assert_ne!(obs.starttls_state, Some(StartTlsState::TlsEstablished));
}
