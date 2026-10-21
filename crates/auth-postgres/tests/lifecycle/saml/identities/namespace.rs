use super::super::signed_idp;
use super::setup::{allow_jit, facts, fixture, verify};
use auth_core::{
    Repository, SamlIdentityPolicy, SamlJitPolicy, SamlRegistration, SamlSignIn, SamlTransactions,
};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn changing_either_entity_namespace_cannot_select_the_previous_subject_owner(pool: PgPool) {
    let (mut f, policy) = fixture(pool).await;
    let mut policy = allow_jit(&mut f, &policy).await;
    let service = SamlSignIn::new(f.store.clone());
    let (a, _) = service
        .finish(policy.map(verify(&f, "same-subject").await).unwrap())
        .await
        .unwrap();
    let mut owners = vec![a.id];
    for (idp, sp) in [
        ("urn:example:idp", "urn:example:other-sp"),
        ("urn:example:other-idp", "urn:example:other-sp"),
    ] {
        let r = &f.registration;
        let reg = SamlRegistration::unsigned_redirect(
            r.realm(),
            r.connection(),
            r.client(),
            sp,
            idp,
            r.sso(),
            r.acs(),
        )
        .unwrap();
        policy = f
            .store
            .configure_saml_identity_policy(
                &SamlIdentityPolicy::new(reg).with_jit(SamlJitPolicy::Allow),
                &signed_idp::trust(),
            )
            .await
            .unwrap();
        f.registration = policy.registration().clone();
        f.flow = SamlTransactions::new(f.registration.clone(), f.store.clone());
        let (user, bearer) = service
            .finish(policy.map(verify(&f, "same-subject").await).unwrap())
            .await
            .unwrap();
        assert!(!owners.contains(&user.id));
        assert!(
            f.store
                .authenticate(user.realm_id, bearer.verifier())
                .await
                .is_ok()
        );
        owners.push(user.id);
    }
    assert_eq!(facts(&f).await, (3, 3, 3, 6, 3));
}

#[sqlx::test(migrations = "./migrations")]
async fn maximum_legal_namespace_resolves_an_existing_owner_without_presentation_or_wide_index(
    pool: PgPool,
) {
    let (mut f, _) = fixture(pool).await;
    let r = &f.registration;
    let idp = format!("urn:idp:{}", "i".repeat(1016));
    let sp = format!("urn:sp:{}", "s".repeat(1017));
    assert_eq!((idp.len(), sp.len()), (1024, 1024));
    let reg = SamlRegistration::unsigned_redirect(
        r.realm(),
        r.connection(),
        r.client(),
        &sp,
        &idp,
        r.sso(),
        r.acs(),
    )
    .unwrap();
    let policy = f
        .store
        .configure_saml_identity_policy(&SamlIdentityPolicy::new(reg), &signed_idp::trust())
        .await
        .unwrap();
    f.registration = policy.registration().clone();
    f.flow = SamlTransactions::new(f.registration.clone(), f.store.clone());
    let subject = "💡".repeat(256);
    let owner = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO auth_users(realm_id,id,email,email_verified_at,display_name,authentication_policy) VALUES($1,$2,NULL,NULL,'Stored presentation','provider_required')")
        .bind(f.registration.realm()).bind(owner).execute(&f.pool).await.unwrap();
    let r = &f.registration;
    sqlx::query("INSERT INTO auth_saml_identities(realm_id,id,connection_id,client_id,idp_entity,sp_entity,subject,user_id,subject_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,auth_saml_subject_key($1,$3,$4,$5,$6,$7))")
        .bind(r.realm()).bind(uuid::Uuid::new_v4()).bind(r.connection()).bind(r.client()).bind(&idp).bind(&sp).bind(&subject).bind(owner)
        .execute(&f.pool).await.unwrap();
    let mapped = policy.map(verify(&f, &subject).await).unwrap();
    assert_eq!(mapped.display_name(), None);
    let (user, bearer) = SamlSignIn::new(f.store.clone())
        .finish(mapped)
        .await
        .unwrap();
    assert_eq!(user.id, owner);
    assert_eq!(user.display_name.as_deref(), Some("Stored presentation"));
    assert!(
        f.store
            .authenticate(user.realm_id, bearer.verifier())
            .await
            .is_ok()
    );
    assert_eq!(facts(&f).await, (1, 1, 1, 2, 1));
}

#[sqlx::test(migrations = "./migrations")]
async fn identical_ids_across_realms_and_subject_case_never_merge_owners_or_bearers(pool: PgPool) {
    let (mut f, policy) = fixture(pool).await;
    let policy = allow_jit(&mut f, &policy).await;
    let other_realm = uuid::Uuid::new_v4();
    f.store.ensure_realm(other_realm).await.unwrap();
    let r = &f.registration;
    let reg = SamlRegistration::unsigned_redirect(
        other_realm,
        r.connection(),
        r.client(),
        r.sp_entity(),
        r.idp_entity(),
        r.sso(),
        r.acs(),
    )
    .unwrap();
    let other_policy = f
        .store
        .configure_saml_identity_policy(
            &SamlIdentityPolicy::new(reg).with_jit(SamlJitPolicy::Allow),
            &signed_idp::trust(),
        )
        .await
        .unwrap();
    let other = super::super::setup::Fixture {
        pool: f.pool.clone(),
        store: f.store.clone(),
        registration: other_policy.registration().clone(),
        flow: SamlTransactions::new(other_policy.registration().clone(), f.store.clone()),
    };
    let service = SamlSignIn::new(f.store.clone());
    let (a, a_token) = service
        .finish(policy.map(verify(&f, "Case-Sensitive").await).unwrap())
        .await
        .unwrap();
    let (b, b_token) = service
        .finish(
            other_policy
                .map(verify(&other, "Case-Sensitive").await)
                .unwrap(),
        )
        .await
        .unwrap();
    let (c, _) = service
        .finish(policy.map(verify(&f, "case-sensitive").await).unwrap())
        .await
        .unwrap();
    assert_ne!(a.id, b.id);
    assert_ne!(a.id, c.id);
    for (realm, token) in [(a.realm_id, &b_token), (b.realm_id, &a_token)] {
        assert!(matches!(
            f.store.authenticate(realm, token.verifier()).await,
            Err(auth_core::Error::Unauthorized)
        ));
        assert!(matches!(
            f.store.list_sessions(realm, token.verifier(), None).await,
            Err(auth_core::Error::Unauthorized)
        ));
    }
    assert_eq!(facts(&f).await, (3, 3, 3, 6, 3));
}
