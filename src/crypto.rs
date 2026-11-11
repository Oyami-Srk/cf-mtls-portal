use crate::error::{AppError, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x509_parser::{
    certification_request::X509CertificationRequest, prelude::*, public_key::PublicKey,
};

pub fn random() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
pub fn hash(bytes: impl AsRef<[u8]>) -> String {
    format!("{:x}", Sha256::digest(bytes.as_ref()))
}
pub fn equal(a: &str, b: &str) -> bool {
    Sha256::digest(a.as_bytes())
        .ct_eq(&Sha256::digest(b.as_bytes()))
        .into()
}

fn pem(input: &str, label: &str) -> Result<Vec<u8>> {
    if input.len() > 8192 || input.contains("PRIVATE KEY") {
        return Err(AppError::bad("invalid_pem", "只接受公开 CSR 或公开证书。"));
    }
    let (rest, pem) = x509_parser::pem::parse_x509_pem(input.as_bytes())
        .map_err(|_| AppError::bad("invalid_pem", "PEM 格式无效。"))?;
    if pem.label != label || rest.iter().any(|b| !b.is_ascii_whitespace()) {
        return Err(AppError::bad("invalid_pem", "PEM 类型或内容无效。"));
    }
    Ok(pem.contents)
}
pub fn check_csr(input: &str, cn: &str) -> Result<String> {
    let der = pem(input, "CERTIFICATE REQUEST")?;
    let (rest, csr) = X509CertificationRequest::from_der(&der)
        .map_err(|_| AppError::bad("invalid_csr", "CSR 无效。"))?;
    let info = &csr.certification_request_info;
    let names = info.subject.iter_attributes().collect::<Vec<_>>();
    let valid_name = names.len() == 1
        && names[0].attr_type().to_id_string() == "2.5.4.3"
        && names[0].as_str().is_ok_and(|v| v == cn);
    let key = info
        .subject_pki
        .parsed()
        .map_err(|_| AppError::bad("invalid_csr", "CSR 公钥无效。"))?;
    let valid_key = match key {
        PublicKey::RSA(key) => key.key_size() == 2048 && key.exponent == [1, 0, 1],
        _ => false,
    };
    if !rest.is_empty()
        || info.version.0 != 0
        || !info.attributes().is_empty()
        || !valid_name
        || !valid_key
        || csr.signature_algorithm.algorithm.to_id_string() != "1.2.840.113549.1.1.11"
        || csr.verify_signature().is_err()
    {
        return Err(AppError::bad(
            "invalid_csr",
            "CSR 的签名、算法、主题或公钥不符合要求。",
        ));
    }
    Ok(hash(info.subject_pki.raw))
}
pub struct Certificate {
    pub fingerprint: String,
    pub expires_at: String,
}
pub fn check_certificate(input: &str, cn: &str, spki: &str, max_days: u16) -> Result<Certificate> {
    let der = pem(input, "CERTIFICATE")?;
    let (rest, cert) = X509Certificate::from_der(&der).map_err(|_| AppError::remote())?;
    let names = cert.subject().iter_attributes().collect::<Vec<_>>();
    let now = chrono::Utc::now().timestamp();
    if !rest.is_empty()
        || names.len() != 1
        || names[0].attr_type().to_id_string() != "2.5.4.3"
        || names[0].as_str().ok() != Some(cn)
        || !equal(&hash(cert.public_key().raw), spki)
        || cert.validity().not_after.timestamp() <= now
        || cert.validity().not_before.timestamp() > now + 300
        || cert.validity().not_after.timestamp() > now + i64::from(max_days) * 86400 + 600
        || cert.is_ca()
        || !cert
            .extended_key_usage()
            .ok()
            .flatten()
            .is_some_and(|e| e.value.client_auth)
        || !cert
            .key_usage()
            .ok()
            .flatten()
            .is_some_and(|e| e.value.digital_signature())
    {
        return Err(AppError::conflict(
            "certificate_mismatch",
            "签发结果与设备请求不匹配，已停止开通。",
        ));
    }
    let expires = chrono::DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0)
        .ok_or_else(AppError::remote)?;
    Ok(Certificate {
        fingerprint: hash(der),
        expires_at: expires.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    })
}
