use native_tls::{HandshakeError, TlsConnector};
use std::net::TcpStream;
use x509_parser::prelude::*;

pub fn probe_tls_certificate(stream: TcpStream, domain: &str) -> Option<String> {
    let connector = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .ok()?;

    let tls_stream = match connector.connect(domain, stream) {
        Ok(s) => s,
        Err(HandshakeError::WouldBlock(mid)) => mid.handshake().ok()?,
        Err(_) => return None,
    };

    let cert = tls_stream.peer_certificate().ok()??;
    let der = cert.to_der().ok()?;
    let (_, parsed_cert) = parse_x509_certificate(&der).ok()?;

    let subject = parsed_cert.subject();
    let mut cn = None;
    let mut org = None;

    for rdn in subject.iter() {
        for attr in rdn.iter() {
            if attr.attr_type() == &oid_registry::OID_X509_COMMON_NAME {
                if let Ok(val) = attr.as_str() {
                    cn = Some(val.to_string());
                }
            } else if attr.attr_type() == &oid_registry::OID_X509_ORGANIZATION_NAME {
                if let Ok(val) = attr.as_str() {
                    org = Some(val.to_string());
                }
            }
        }
    }

    match (cn, org) {
        (Some(c), Some(o)) => Some(format!("SSL: CN={}, O={}", c, o)),
        (Some(c), None) => Some(format!("SSL: CN={}", c)),
        (None, Some(o)) => Some(format!("SSL: O={}", o)),
        (None, None) => Some("SSL: Certificado detectado".to_string()),
    }
}
