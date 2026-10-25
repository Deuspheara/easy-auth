use uuid::Uuid;

/// Maximum public linked-provider metadata returned in one owner-scoped page.
pub const LINKED_PROVIDER_PAGE_SIZE: usize = 50;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderKind {
    Oidc,
    Saml,
}

/// Public inventory position only; neither field authenticates a provider or owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkedProviderCursor {
    pub kind: ProviderKind,
    pub id: Uuid,
}

/// Public issuer metadata. Subjects, provider claims and credentials are excluded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkedProvider {
    pub id: Uuid,
    pub kind: ProviderKind,
    pub issuer: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkedProviderPage {
    pub providers: Vec<LinkedProvider>,
    pub next: Option<LinkedProviderCursor>,
}
