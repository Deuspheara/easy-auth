use super::configuration;
use crate::{Postgres, unavailable};
use auth_core::{Error, Result, SamlCertificateTrust, SamlPinnedCertificate, SamlRegistration};
use sqlx::{FromRow, Postgres as Pg, Transaction};

impl Postgres {
    /// Trusted administration only. Replace exact registration and pins in one
    /// transaction; allocate a fresh revision and cancel every pending request.
    /// Existing operator disable is retained. This does not activate a provider.
    pub async fn configure_saml_pinned_registration(
        &self,
        input: &SamlRegistration,
        trust: &SamlCertificateTrust,
    ) -> Result<SamlRegistration> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        let registration = replace_registration(&mut tx, input, trust).await?;
        tx.commit().await.map_err(unavailable)?;
        Ok(registration)
    }

    /// Read configured pins only under exact current enabled registration.
    /// Callers must select active certificates at trusted operation time. This
    /// getter creates no verification result, user or session.
    pub async fn saml_certificate_trust(
        &self,
        registration: &SamlRegistration,
    ) -> Result<SamlCertificateTrust> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        configuration::lock(&mut tx, registration).await?;
        let rows: Vec<CertificateRow> = sqlx::query_as(r#"
            SELECT certificate_der,fingerprint,approved_from,approved_until FROM auth_saml_certificates
            WHERE realm_id=$1 AND connection_id=$2 AND client_id=$3 AND revision=$4 ORDER BY slot
        "#)
        .bind(registration.realm())
        .bind(registration.connection())
        .bind(registration.client())
        .bind(registration.revision())
        .fetch_all(&mut *tx)
        .await
        .map_err(unavailable)?;
        if rows.is_empty() {
            return Err(Error::Unauthorized);
        }
        // Copy the exact snapshot, then release storage locks before X.509 work.
        tx.commit().await.map_err(unavailable)?;
        let pins: Result<Vec<_>> = rows.into_iter().map(CertificateRow::parse).collect();
        SamlCertificateTrust::pinned_leaf(pins?).map_err(|_| Error::Unavailable)
    }
}

/// Allocate registration revision, invalidate old state and replace explicit pins
/// under the caller's transaction. Commit and any additional policy stay visible
/// in that caller; no transaction or trust inference is hidden here.
pub(super) async fn replace_registration(
    tx: &mut Transaction<'_, Pg>,
    input: &SamlRegistration,
    trust: &SamlCertificateTrust,
) -> Result<SamlRegistration> {
    let registration = configuration::replace_registration(tx, input).await?;
    for (slot, pin) in trust.certificates().iter().enumerate() {
        let slot = i16::try_from(slot).map_err(|_| Error::InvalidInput)?;
        sqlx::query(
            r#"
            INSERT INTO auth_saml_certificates(realm_id,connection_id,client_id,revision,slot,
              certificate_der,fingerprint,approved_from,approved_until)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
        "#,
        )
        .bind(registration.realm())
        .bind(registration.connection())
        .bind(registration.client())
        .bind(registration.revision())
        .bind(slot)
        .bind(pin.der())
        .bind(pin.fingerprint().as_slice())
        .bind(pin.approved_from())
        .bind(pin.approved_until())
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    }
    Ok(registration)
}

#[derive(FromRow)]
struct CertificateRow {
    certificate_der: Vec<u8>,
    fingerprint: Vec<u8>,
    approved_from: i64,
    approved_until: i64,
}

impl CertificateRow {
    fn parse(self) -> Result<SamlPinnedCertificate> {
        let pin = SamlPinnedCertificate::from_der(
            &self.certificate_der,
            self.approved_from,
            self.approved_until,
        )
        .map_err(|_| Error::Unavailable)?;
        if self.fingerprint != pin.fingerprint() {
            return Err(Error::Unavailable);
        }
        Ok(pin)
    }
}
