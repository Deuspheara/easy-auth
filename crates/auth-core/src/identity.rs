use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct User {
    pub id: Uuid,
    pub realm_id: Uuid,
    pub email: String,
}
