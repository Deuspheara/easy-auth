use super::{binding, key, payload, vault};
use crate::{
    Error,
    oidc::apple::grants::{
        AppleGrantBinding, AppleGrantEnvelope, AppleGrantKey, AppleGrantVault, protection,
    },
};
use uuid::Uuid;

#[test]
fn operator_keys_reject_missing_default_duplicate_and_unbounded_configuration() {
    assert!(AppleGrantKey::new(Uuid::nil(), vec![17; 32]).is_err());
    for bytes in [vec![], vec![17; 31], vec![17; 33], vec![0; 32]] {
        assert!(AppleGrantKey::new(Uuid::new_v4(), bytes).is_err());
    }
    let id = Uuid::new_v4();
    assert!(AppleGrantVault::new(key(id, 17), vec![key(id, 31)]).is_err());
    assert!(
        AppleGrantVault::new(
            key(Uuid::new_v4(), 17),
            (0..8).map(|_| key(Uuid::new_v4(), 31)).collect()
        )
        .is_err()
    );
    assert!(
        AppleGrantVault::new(
            key(Uuid::new_v4(), 17),
            (0..7).map(|_| key(Uuid::new_v4(), 31)).collect()
        )
        .is_ok()
    );
    assert_eq!(format!("{:?}", key(id, 17)), "AppleGrantKey([REDACTED])");
    let b = binding();
    assert!(
        AppleGrantBinding::new(
            Uuid::nil(),
            b.connection(),
            b.client(),
            b.identity(),
            b.grant()
        )
        .is_err()
    );
}

#[tokio::test]
async fn missing_and_wrong_keys_never_select_a_fallback_by_trial() {
    let vault = vault();
    let sealed = protection::seal(&vault.keys, binding(), payload()).unwrap();
    let missing = AppleGrantEnvelope::restore(
        sealed.binding(),
        Uuid::new_v4(),
        sealed.ciphertext().to_owned(),
    )
    .unwrap();
    assert!(matches!(
        vault.rewrap(&missing).await,
        Err(Error::Unavailable)
    ));
    let wrong = AppleGrantVault::new(key(sealed.key_id(), 31), vec![]).unwrap();
    assert!(matches!(
        wrong.rewrap(&sealed).await,
        Err(Error::Unauthorized)
    ));
}
