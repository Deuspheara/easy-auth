use auth_core::*;
use serde_json::{Value, json};
use zeroize::Zeroizing;

pub(super) struct Pending {
    pub(super) browser: Secret,
    pub(super) start: OAuthStart,
}
pub(super) struct Replay {
    browser: Secret,
    state: Secret,
    nonce: Zeroizing<String>,
    pkce: Zeroizing<String>,
}

impl Pending {
    pub(super) async fn consume(
        self,
        transactions: &OAuthTransactions,
        connection: &OAuthConnection,
        callback: &str,
    ) -> Result<(OAuthExchange, Replay, Result<String>)> {
        let Self { browser, start } = self;
        let url = url::Url::parse(callback).map_err(|_| Error::Unauthorized)?;
        let mut base = url.clone();
        base.set_query(None);
        if base.as_str() != connection.redirect() {
            return Err(Error::Unauthorized);
        }
        let pairs: Vec<_> = url.query_pairs().collect();
        let value = |name: &str| -> Result<&str> {
            let values: Vec<_> = pairs.iter().filter(|(key, _)| key == name).collect();
            if values.len() != 1 {
                return Err(Error::Unauthorized);
            }
            Ok(values[0].1.as_ref())
        };
        let state = Secret::parse(value("state")?.to_owned())?;
        let proof = OAuthBrowserProof::parse(
            start.proof.nonce().expose().to_owned(),
            start.proof.pkce_verifier().expose().to_owned(),
        )?;
        let intent = OAuthIntent {
            browser: &browser,
            source: "owned-keycloak",
            purpose: OAuthPurpose::SignIn,
        };
        let context = transactions
            .consume(
                &intent,
                &state,
                proof,
                OAuthCallback {
                    redirect: connection.redirect(),
                    issuer: Some(value("iss")?),
                },
            )
            .await?;
        // Original protected material only for exact consumed-state replay. This
        // tuple and code stay in private fixture memory/IPC and are never logged.
        let replay = Replay {
            browser,
            state: start.state,
            nonce: Zeroizing::new(start.proof.nonce().expose().to_owned()),
            pkce: Zeroizing::new(start.proof.pkce_verifier().expose().to_owned()),
        };
        Ok((context, replay, value("code").map(str::to_owned)))
    }
}
impl Replay {
    pub(super) async fn check(
        &self,
        transactions: &OAuthTransactions,
        connection: &OAuthConnection,
    ) -> Result<Value> {
        let intent = OAuthIntent {
            browser: &self.browser,
            source: "owned-keycloak",
            purpose: OAuthPurpose::SignIn,
        };
        transactions
            .consume(
                &intent,
                &self.state,
                OAuthBrowserProof::parse(self.nonce.to_string(), self.pkce.to_string())?,
                OAuthCallback {
                    redirect: connection.redirect(),
                    issuer: Some(connection.issuer()),
                },
            )
            .await?;
        Ok(json!({"result":"unexpected-state-reuse"}))
    }
}
