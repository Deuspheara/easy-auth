use crate::{
    browser::read_cookie,
    error::{ApiError, ErrorResponse},
    router::AppState,
};
use auth_core::{Error, LinkedProviderCursor, ProviderKind};
use axum::{
    Json,
    extract::{Query, State, rejection::QueryRejection},
    http::HeaderMap,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

#[derive(Clone, Copy, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProviderProtocol {
    Oidc,
    Saml,
}

impl From<ProviderProtocol> for ProviderKind {
    fn from(kind: ProviderProtocol) -> Self {
        match kind {
            ProviderProtocol::Oidc => Self::Oidc,
            ProviderProtocol::Saml => Self::Saml,
        }
    }
}

impl From<ProviderKind> for ProviderProtocol {
    fn from(kind: ProviderKind) -> Self {
        match kind {
            ProviderKind::Oidc => Self::Oidc,
            ProviderKind::Saml => Self::Saml,
        }
    }
}

#[derive(Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub(crate) struct ProviderQuery {
    /// Supply both cursor fields from the preceding page, or neither.
    after_kind: Option<ProviderProtocol>,
    after_id: Option<Uuid>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct LinkedProviderResponse {
    id: Uuid,
    kind: ProviderProtocol,
    /// Immutable linked issuer; this is not current trust or activation status.
    issuer: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ProviderCursorResponse {
    kind: ProviderProtocol,
    id: Uuid,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct LinkedProvidersResponse {
    #[schema(max_items = 50)]
    providers: Vec<LinkedProviderResponse>,
    next: Option<ProviderCursorResponse>,
}

#[utoipa::path(get, path="/v1/account/providers", params(ProviderQuery, ("Cookie"=String,Header)),
    responses((status=200,body=LinkedProvidersResponse,description="Owner-scoped public linked issuers, ordered by protocol then UUID; no subjects, claims or credentials"),
    (status=400,body=ErrorResponse),(status=401,body=ErrorResponse),(status=503,body=ErrorResponse),(status=504,body=ErrorResponse)))]
pub(crate) async fn linked_providers(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<ProviderQuery>, QueryRejection>,
) -> Result<Json<LinkedProvidersResponse>, ApiError> {
    let Query(query) = query.map_err(|_| Error::InvalidInput)?;
    let after = match (query.after_kind, query.after_id) {
        (None, None) => None,
        (Some(kind), Some(id)) => Some(LinkedProviderCursor {
            kind: kind.into(),
            id,
        }),
        _ => return Err(Error::InvalidInput.into()),
    };
    let current = read_cookie(&headers, state.browser.session_name())?;
    let page = state.auth.linked_providers(&current, after).await?;
    Ok(Json(LinkedProvidersResponse {
        providers: page
            .providers
            .into_iter()
            .map(|provider| LinkedProviderResponse {
                id: provider.id,
                kind: provider.kind.into(),
                issuer: provider.issuer,
            })
            .collect(),
        next: page.next.map(|cursor| ProviderCursorResponse {
            kind: cursor.kind.into(),
            id: cursor.id,
        }),
    }))
}
