use super::setup::*;

fn response(state: &Secret, error: Option<&str>) -> AppleAuthorizationResponse {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.append_pair("state", state.expose());
    if let Some(error) = error {
        form.append_pair("error", error);
    } else {
        form.append_pair("code", "owned-apple-authorization-code");
    }
    AppleAuthorizationResponse::parse(&form.finish()).unwrap()
}

#[tokio::test]
async fn shared_web_and_native_start_finish_preserve_private_state_and_return_verified_proof_only()
{
    for kind in [
        AppleClientType::Web,
        AppleClientType::Native(AppleNonceEncoding::Sha256Hex),
    ] {
        let f = fixture();
        let tokens = TokenHttp::new();
        let component = Arc::new(client(&f, tokens.clone(), kind));
        let flow = AppleAuthorization::new(
            Arc::new(OAuthTransactions::new(
                f.store.connection.clone(),
                f.store.clone(),
            )),
            component,
        )
        .unwrap();
        let browser = Secret::generate().unwrap();
        let intent = OAuthIntent {
            browser: &browser,
            source: "owned-apple",
            purpose: OAuthPurpose::SignIn,
        };
        let start = flow.begin(&intent).await.unwrap();
        assert_eq!(
            start.request.client_id(),
            f.store.connection.provider_client()
        );
        assert!(start.request.state() == start.transaction.state.expose());
        assert!(
            !format!("{:?}", start.request)
                .contains(start.transaction.proof.pkce_verifier().expose())
        );
        if kind == AppleClientType::Web {
            let url = url::Url::parse(start.request.web_url().unwrap()).unwrap();
            let fields: std::collections::HashMap<_, _> = url.query_pairs().collect();
            assert_eq!(fields["response_type"], "code");
            assert_eq!(fields["response_mode"], "form_post");
            assert_eq!(fields["scope"], "email name");
            assert_eq!(fields["redirect_uri"], f.store.connection.redirect());
            assert!(!fields.contains_key("code_challenge"));
        } else {
            assert!(start.request.web_url().is_none());
        }
        let claims = json!({"iss":"https://appleid.apple.com","sub":"owned-subject","aud":start.request.client_id(),"nonce":start.request.nonce(),"iat":NOW_US/1_000_000,"exp":NOW_US/1_000_000+60});
        tokens.success(&f, &claims);
        let wrong = Secret::generate().unwrap();
        let proof = OAuthBrowserProof::parse(
            start.transaction.proof.nonce().expose().to_owned(),
            start.transaction.proof.pkce_verifier().expose().to_owned(),
        )
        .unwrap();
        assert!(matches!(
            flow.finish(
                &intent,
                &wrong,
                proof,
                f.store.connection.redirect(),
                response(&start.transaction.state, None)
            )
            .await,
            Err(Error::Unauthorized)
        ));
        assert_eq!(tokens.posts(), 0);
        let result = flow
            .finish(
                &intent,
                &start.transaction.state,
                start.transaction.proof,
                f.store.connection.redirect(),
                response(&start.transaction.state, None),
            )
            .await
            .unwrap();
        let AppleAuthorizationCompletion::Verified {
            identity,
            initial_profile,
        } = result
        else {
            panic!("expected verified backend result");
        };
        assert_eq!(identity.subject(), "owned-subject");
        assert!(initial_profile.is_none());
        assert_eq!(tokens.posts(), 1);
    }
}

#[tokio::test]
async fn bound_denial_cancels_without_token_io_or_grant_and_other_purposes_are_rejected() {
    let f = fixture();
    let tokens = TokenHttp::new();
    let flow = AppleAuthorization::new(
        Arc::new(OAuthTransactions::new(
            f.store.connection.clone(),
            f.store.clone(),
        )),
        Arc::new(client(&f, tokens.clone(), AppleClientType::Web)),
    )
    .unwrap();
    let browser = Secret::generate().unwrap();
    let intent = OAuthIntent {
        browser: &browser,
        source: "owned-apple",
        purpose: OAuthPurpose::SignIn,
    };
    let start = flow.begin(&intent).await.unwrap();
    let result = flow
        .finish(
            &intent,
            &start.transaction.state,
            start.transaction.proof,
            f.store.connection.redirect(),
            response(&start.transaction.state, Some("user_cancelled_authorize")),
        )
        .await
        .unwrap();
    assert!(matches!(result, AppleAuthorizationCompletion::Denied));
    assert_eq!(tokens.posts(), 0);
    let linking = OAuthIntent {
        purpose: OAuthPurpose::Link {
            user: uuid::Uuid::new_v4(),
            session: Secret::generate().unwrap().verifier(),
        },
        ..intent
    };
    assert!(matches!(
        flow.begin(&linking).await,
        Err(Error::Unauthorized)
    ));
}
