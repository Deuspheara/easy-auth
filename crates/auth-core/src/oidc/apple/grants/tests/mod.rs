mod binding;
mod keys;
mod rotation;
use super::{
    AppleGrantBinding, AppleGrantKey, AppleGrantVault,
    payload::{GrantTokenKind, StoredGrant},
};
use uuid::Uuid;

pub(super) fn binding() -> AppleGrantBinding {
    AppleGrantBinding::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    )
    .unwrap()
}
pub(super) fn payload() -> StoredGrant {
    StoredGrant {
        version: 1,
        kind: GrantTokenKind::Refresh,
        token: "owned-refresh-material".to_owned(),
        provider_client: "com.example.owned".to_owned(),
        access_expires_us: None,
    }
}
pub(super) fn key(id: Uuid, byte: u8) -> AppleGrantKey {
    AppleGrantKey::new(id, vec![byte; 32]).unwrap()
}
pub(super) fn vault() -> AppleGrantVault {
    AppleGrantVault::new(key(Uuid::new_v4(), 17), vec![]).unwrap()
}
