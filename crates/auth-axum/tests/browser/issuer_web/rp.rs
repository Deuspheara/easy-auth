use super::{rp_transport::OwnedTransport, *};

async fn connection(f: &mut Fixture, client: Uuid) -> OAuthConnection {
    // The existing inbound RP admits a narrower callback profile without fixed
    // query parameters. Keep issuer query-preservation coverage in lifecycle.rs.
    f.redirect = format!("https://client.example/cb/{}", Uuid::new_v4());
    let registration = match &f.secret {
        Some(secret) => IssuerClientRegistration::confidential(
            f.realm,
            f.client.client(),
            &[&f.redirect],
            secret,
        ),
        None => IssuerClientRegistration::public(f.realm, f.client.client(), &[&f.redirect]),
    }
    .unwrap();
    f.client = f
        .store
        .configure_issuer_client(&registration)
        .await
        .unwrap();
    let realm = Uuid::new_v4();
    f.store.ensure_realm(realm).await.unwrap();
    f.store
        .configure_oauth_connection(
            &OAuthConnection::new(
                realm,
                Uuid::new_v4(),
                Uuid::new_v4(),
                ORIGIN,
                &client.to_string(),
                &f.redirect,
                OAuthMixupDefense::RequireIssuer,
            )
            .unwrap(),
        )
        .await
        .unwrap()
}
fn documents(f: &Fixture, connection: OAuthConnection) -> Arc<OidcDocuments> {
    Arc::new(
        OidcDocuments::new(
            connection,
            &[ORIGIN],
            f.store.clone(),
            Arc::new(OwnedTransport(f.app.clone())),
        )
        .unwrap(),
    )
}
fn policy(algorithm: OidcSigningAlgorithm) -> OidcVerificationPolicy {
    OidcVerificationPolicy::new(&[algorithm], &[]).unwrap()
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn real_rp_transactions_discovery_authorization_callback_post_and_verifier_accept_public_and_basic_clients(
    pool: PgPool,
) {
    for profile in [Profile::Public, Profile::Confidential] {
        let mut f = Fixture::new(pool.clone(), profile).await;
        let client = f.client.client();
        let connection = connection(&mut f, client).await;
        let transactions = OAuthTransactions::new(connection.clone(), f.store.clone());
        let browser = Secret::generate().unwrap();
        let intent = OAuthIntent {
            browser: &browser,
            source: "owned-rp-wire",
            purpose: OAuthPurpose::SignIn,
        };
        let start = transactions.begin(&intent).await.unwrap();
        let authentication = match &f.secret {
            Some(secret) => OidcClientAuthentication::ClientSecretBasic(
                OidcClientSecret::parse(secret.expose().to_owned()).unwrap(),
            ),
            None => OidcClientAuthentication::Public,
        };
        let rp = OidcCodeExchange::new(
            documents(&f, connection.clone()),
            f.store.clone(),
            policy(OidcSigningAlgorithm::RS256),
            authentication,
            Arc::new(OwnedTransport(f.app.clone())),
        );
        let authorization = rp.authorization_url(&start, &[]).await.unwrap();
        let parsed = url::Url::parse(authorization.expose()).unwrap();
        assert_eq!(parsed.path(), "/oidc/authorize");
        let input = Value::Object(
            parsed
                .query_pairs()
                .map(|(key, value)| (key.into_owned(), Value::String(value.into_owned())))
                .collect(),
        );
        let returned = f.approve(&input).await;
        let parameters: std::collections::HashMap<_, _> = returned.query_pairs().collect();
        assert!(parameters["state"] == start.state.expose());
        assert_eq!(parameters["iss"], ORIGIN);
        let code = OidcAuthorizationCode::parse(parameters["code"].to_string()).unwrap();
        let exchange = transactions
            .consume(
                &intent,
                &start.state,
                start.proof,
                OAuthCallback {
                    redirect: &f.redirect,
                    issuer: Some(ORIGIN),
                },
            )
            .await
            .unwrap();
        let identity = rp.exchange(exchange, code).await.unwrap();
        assert_eq!(identity.configuration(), &connection);
        assert_eq!(identity.email(), None);
        assert!(!identity.email_verified());
        assert!(identity.authenticated_at().is_some());
        let subject: String = sqlx::query_scalar(
            "SELECT subject::text FROM auth_issuer_access_tokens WHERE realm_id=$1",
        )
        .bind(f.realm)
        .fetch_one(&f.pool)
        .await
        .unwrap();
        assert_eq!(identity.subject(), subject);
        // The RP is in another realm; a verified identity is no local session.
        let rp_users: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_users WHERE realm_id=$1")
            .bind(connection.realm())
            .fetch_one(&f.pool)
            .await
            .unwrap();
        assert_eq!(rp_users, 0);
        assert_eq!(f.facts().await, (1, 1, 1));
    }
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn ordinary_unaltered_issuer_tokens_cannot_satisfy_a_foreign_audience_nonce_or_algorithm_policy(
    pool: PgPool,
) {
    let mut f = Fixture::new(pool, Profile::Public).await;
    // Each token is an unchanged ordinary issuer output. Exactly one RP
    // expectation differs; no crafted claims, altered signature or test signer.
    for (client, algorithm, wrong_nonce) in [
        (Uuid::new_v4(), OidcSigningAlgorithm::RS256, false),
        (f.client.client(), OidcSigningAlgorithm::RS256, true),
        (f.client.client(), OidcSigningAlgorithm::PS256, false),
    ] {
        let connection = connection(&mut f, client).await;
        let transactions = OAuthTransactions::new(connection.clone(), f.store.clone());
        let browser = Secret::generate().unwrap();
        let intent = OAuthIntent {
            browser: &browser,
            source: "owned-rp-policy",
            purpose: OAuthPurpose::SignIn,
        };
        let start = transactions.begin(&intent).await.unwrap();
        let other_nonce = Secret::generate().unwrap();
        let nonce = if wrong_nonce {
            other_nonce.expose()
        } else {
            start.proof.nonce().expose()
        };
        let returned = f.approve(&json!({"client_id":f.client.client(),"response_type":"code","redirect_uri":f.redirect,"scope":"openid","state":start.state.expose(),"nonce":nonce,"code_challenge":f.pkce.challenge(),"code_challenge_method":"S256"})).await;
        let code = Secret::parse(
            returned
                .query_pairs()
                .find(|(key, _)| key == "code")
                .unwrap()
                .1
                .into_owned(),
        )
        .unwrap();
        let response = f.send(f.body(&code), None).await;
        assert_eq!(response.status(), 200);
        let token = read(response).await;
        let exchange = transactions
            .consume(
                &intent,
                &start.state,
                start.proof,
                OAuthCallback {
                    redirect: &f.redirect,
                    issuer: Some(ORIGIN),
                },
            )
            .await
            .unwrap();
        let verifier = OidcTokenVerifier::new(
            documents(&f, connection),
            f.store.clone(),
            policy(algorithm),
        );
        assert!(matches!(
            verifier
                .verify(
                    exchange,
                    OidcIdToken::parse(token["id_token"].as_str().unwrap().to_owned()).unwrap()
                )
                .await,
            Err(Error::Unauthorized)
        ));
    }
    assert_eq!(f.facts().await, (1, 1, 3));
}
