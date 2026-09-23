use mailent_domain::{
    CertificateCryptoDetails, CertificateExtensions, ChainValidation, PublicKeyDetails,
};
/// Conventional names for common EC curve OIDs used in public-key parameters.
/// Unknown OIDs map to `None` (reported as unavailable rather than guessed).
fn curve_name_for_oid(oid: x509_parser::der_parser::oid::Oid<'_>) -> Option<String> {
    const SECP256R1: &str = "1.2.840.10045.3.1.7";
    const SECP384R1: &str = "1.3.132.0.34";
    const SECP521R1: &str = "1.3.132.0.35";
    const SECP256K1: &str = "1.3.132.0.10";
    match oid.to_id_string().as_str() {
        SECP256R1 => Some("secp256r1 (P-256)".to_string()),
        SECP384R1 => Some("secp384r1 (P-384)".to_string()),
        SECP521R1 => Some("secp521r1 (P-521)".to_string()),
        SECP256K1 => Some("secp256k1".to_string()),
        _ => None,
    }
}

/// Extract details from the certificate already parsed by the transport probe.
/// Unknown algorithms or extensions remain unavailable.
pub fn crypto_details(
    cert: &x509_parser::prelude::X509Certificate<'_>,
) -> CertificateCryptoDetails {
    use x509_parser::prelude::*;

    let signature_algorithm = Some(cert.signature_algorithm.algorithm.to_string());

    let subject_pki = &cert.tbs_certificate.subject_pki;
    // EC curve names are not exposed by x509-parser's ECPoint; we derive a
    // conventional name from the algorithm OID parameters when present.
    let ec_curve_from_params = || -> Option<String> {
        let params = subject_pki.algorithm.parameters()?;
        let oid = params.as_oid().ok()?;
        curve_name_for_oid(oid)
    };
    let (algorithm, rsa_bits, ec_curve) = match subject_pki.parsed() {
        Ok(x509_parser::public_key::PublicKey::RSA(rsa)) => {
            (Some("RSA".to_string()), Some(rsa.key_size() as u16), None)
        }
        Ok(x509_parser::public_key::PublicKey::EC(_)) => {
            (Some("EC".to_string()), None, ec_curve_from_params())
        }
        _ => (None, None, None),
    };

    let mut basic_constraints = None;
    let mut key_usage = Vec::new();
    let mut extended_key_usage = Vec::new();
    for ext in cert.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::BasicConstraints(bc) => {
                basic_constraints = Some(if bc.ca {
                    "CA:TRUE".to_string()
                } else {
                    "CA:FALSE".to_string()
                });
            }
            ParsedExtension::KeyUsage(ku) => {
                if ku.digital_signature() {
                    key_usage.push("digitalSignature".to_string());
                }
                if ku.key_encipherment() {
                    key_usage.push("keyEncipherment".to_string());
                }
                if ku.key_agreement() {
                    key_usage.push("keyAgreement".to_string());
                }
                if ku.key_cert_sign() {
                    key_usage.push("keyCertSign".to_string());
                }
            }
            ParsedExtension::ExtendedKeyUsage(eku) => {
                if eku.any {
                    extended_key_usage.push("anyExtendedKeyUsage".to_string());
                }
                if eku.server_auth {
                    extended_key_usage.push("serverAuth".to_string());
                }
                if eku.client_auth {
                    extended_key_usage.push("clientAuth".to_string());
                }
                if eku.email_protection {
                    extended_key_usage.push("emailProtection".to_string());
                }
            }
            _ => {}
        }
    }

    CertificateCryptoDetails {
        signature_algorithm,
        public_key: PublicKeyDetails {
            algorithm,
            rsa_bits,
            ec_curve,
            spki_sha256: None,
        },
        chain_validation: ChainValidation::NotVerified,
        chain_length: None,
        extensions: CertificateExtensions {
            basic_constraints,
            key_usage,
            extended_key_usage,
        },
    }
}
