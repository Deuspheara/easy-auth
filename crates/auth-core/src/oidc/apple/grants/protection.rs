use super::{
    AppleGrantBinding, AppleGrantEnvelope,
    keys::KeySet,
    payload::{MAX_PAYLOAD_BYTES, StoredGrant},
};
use crate::{Error, Result};
use josekit::{
    Value,
    jwe::{self, Dir, JweDecrypter, JweHeader},
};
use uuid::Uuid;
use zeroize::Zeroizing;

const STORAGE_ENVELOPE_TYPE: &str = "easy-auth/apple-grant+v1";
fn header(binding: AppleGrantBinding, key: Uuid) -> Result<JweHeader> {
    let mut header = JweHeader::new();
    header.set_algorithm("dir");
    header.set_content_encryption("A256GCM");
    header.set_token_type(STORAGE_ENVELOPE_TYPE);
    header.set_key_id(key.to_string());
    for (name, value) in [
        ("realm", binding.realm),
        ("connection", binding.connection),
        ("client", binding.client),
        ("identity", binding.identity),
        ("grant", binding.grant),
    ] {
        header
            .set_claim(name, Some(Value::String(value.to_string())))
            .map_err(|_| Error::Unavailable)?;
    }
    Ok(header)
}
pub(super) fn seal(
    keys: &KeySet,
    binding: AppleGrantBinding,
    payload: StoredGrant,
) -> Result<AppleGrantEnvelope> {
    payload.validate()?;
    let bytes = Zeroizing::new(serde_json::to_vec(&payload).map_err(|_| Error::Unavailable)?);
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(Error::Unavailable);
    }
    let key = keys.key(keys.current)?;
    let encrypter = Dir
        .encrypter_from_bytes(key.bytes.as_slice())
        .map_err(|_| Error::Unavailable)?;
    let ciphertext = jwe::serialize_compact(&bytes, &header(binding, key.id)?, &encrypter)
        .map_err(|_| Error::Unavailable)?;
    AppleGrantEnvelope::restore(binding, key.id, ciphertext)
}
pub(super) fn open(keys: &KeySet, envelope: &AppleGrantEnvelope) -> Result<StoredGrant> {
    let key = keys.key(envelope.key)?;
    let expected = header(envelope.binding, key.id)?;
    let decrypter = Dir
        .decrypter_from_bytes(key.bytes.as_slice())
        .map_err(|_| Error::Unavailable)?;
    // Selector runs before decrypt/decompress. Even a correctly authenticated
    // envelope with extra claims, zip or another algorithm is not our format.
    let (bytes, _) = jwe::deserialize_compact_with_selector(&envelope.ciphertext, |header| {
        Ok(if header == &expected {
            Some(&decrypter as &dyn JweDecrypter)
        } else {
            None
        })
    })
    .map_err(|_| Error::Unauthorized)?;
    let bytes = Zeroizing::new(bytes);
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(Error::Unauthorized);
    }
    let payload: StoredGrant = serde_json::from_slice(&bytes).map_err(|_| Error::Unauthorized)?;
    payload.validate()?;
    Ok(payload)
}
