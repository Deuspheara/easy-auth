//! Explicit leaf-certificate pinning. This is configuration, never an identity
//! proof, PKI chain validation, XML signature validation or activation approval.

use crate::{Error, Result};
use openssl::{asn1::Asn1Time, pkey::Id, x509::X509};
use sha2::{Digest, Sha256};
use std::{cmp::Ordering, fmt};

const MAX_CERTIFICATE_DER_BYTES: usize = 16 * 1024;
const MIN_RSA_BITS: u32 = 2048;

/// An operator-approved exact DER certificate and half-open Unix-second window.
/// Self-signed certificates are supported by explicit leaf pinning. Issuer names,
/// system roots, remote metadata and callback KeyInfo do not establish trust.
#[derive(Clone)]
pub struct SamlPinnedCertificate {
    der: Vec<u8>,
    fingerprint: [u8; 32],
    approved_from: i64,
    approved_until: i64,
}

impl SamlPinnedCertificate {
    /// Parse with OpenSSL, require a canonical single DER RSA certificate with
    /// at least 2048 bits and constrain operator approval to X.509 validity.
    /// No private key, certificate-chain discovery or signature is processed.
    pub fn from_der(der: &[u8], approved_from: i64, approved_until: i64) -> Result<Self> {
        if der.is_empty()
            || der.len() > MAX_CERTIFICATE_DER_BYTES
            || approved_from < 0
            || approved_from >= approved_until
        {
            return Err(Error::InvalidInput);
        }
        let cert = X509::from_der(der).map_err(|_| Error::InvalidInput)?;
        let canonical = cert.to_der().map_err(|_| Error::InvalidInput)?;
        let key = cert.public_key().map_err(|_| Error::InvalidInput)?;
        if canonical != der || key.id() != Id::RSA || key.bits() < MIN_RSA_BITS {
            return Err(Error::InvalidInput);
        }
        let from = Asn1Time::from_unix(approved_from).map_err(|_| Error::InvalidInput)?;
        let until = Asn1Time::from_unix(approved_until).map_err(|_| Error::InvalidInput)?;
        if cert
            .not_before()
            .compare(&from)
            .map_err(|_| Error::InvalidInput)?
            == Ordering::Greater
            || cert
                .not_after()
                .compare(&until)
                .map_err(|_| Error::InvalidInput)?
                == Ordering::Less
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            fingerprint: Sha256::digest(&canonical).into(),
            der: canonical,
            approved_from,
            approved_until,
        })
    }

    pub fn der(&self) -> &[u8] {
        &self.der
    }
    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }
    pub fn approved_from(&self) -> i64 {
        self.approved_from
    }
    pub fn approved_until(&self) -> i64 {
        self.approved_until
    }
    /// Call with the operation's trusted database time; no implicit clock skew.
    pub fn is_active_at(&self, unix_seconds: i64) -> bool {
        self.approved_from <= unix_seconds && unix_seconds < self.approved_until
    }
}

impl fmt::Debug for SamlPinnedCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SamlPinnedCertificate([configured certificate])")
    }
}
