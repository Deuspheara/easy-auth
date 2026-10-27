use super::{binding, key, payload};
use crate::{
    Error,
    oidc::apple::grants::{AppleGrantVault, protection},
};
use uuid::Uuid;

#[tokio::test]
async fn explicit_rotation_preserves_binding_and_payload_with_fresh_ciphertext() {
    let old = Uuid::new_v4();
    let new = Uuid::new_v4();
    let before = AppleGrantVault::new(key(old, 17), vec![]).unwrap();
    let b = binding();
    let sealed = protection::seal(&before.keys, b, payload()).unwrap();
    let rotation = AppleGrantVault::new(key(new, 31), vec![key(old, 17)]).unwrap();
    let updated = rotation.rewrap(&sealed).await.unwrap();
    assert!(updated.binding() == b);
    assert_eq!(updated.key_id(), new);
    assert!(updated.ciphertext() != sealed.ciphertext());
    let after = AppleGrantVault::new(key(new, 31), vec![]).unwrap();
    let payload = protection::open(&after.keys, &updated).unwrap();
    assert!(payload.token == "owned-refresh-material");
    assert!(matches!(
        after.rewrap(&sealed).await,
        Err(Error::Unavailable)
    ));
    assert!(matches!(
        before.rewrap(&updated).await,
        Err(Error::Unavailable)
    ));
}
