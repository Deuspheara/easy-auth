use crate::{Postgres, unavailable};
use auth_core::{
    Error, LINKED_PROVIDER_PAGE_SIZE, LinkedProvider, LinkedProviderCursor, LinkedProviderPage,
    ProviderKind, Result, Verifier,
};
use sqlx::{Row, Transaction, postgres::PgRow};
use uuid::Uuid;

impl Postgres {
    pub(crate) async fn linked_providers(
        &self,
        realm: Uuid,
        current: Verifier,
        after: Option<LinkedProviderCursor>,
    ) -> Result<LinkedProviderPage> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        let (owner, _, deadline) =
            super::validation::active_caller(&mut tx, realm, current).await?;
        let rows = linked_rows(&mut tx, realm, owner.id, after).await?;
        let more = rows.len() > LINKED_PROVIDER_PAGE_SIZE;
        let providers: Vec<_> = rows
            .into_iter()
            .take(LINKED_PROVIDER_PAGE_SIZE)
            .map(provider_from_row)
            .collect::<Result<_>>()?;
        let next = if more {
            providers.last().map(|provider| LinkedProviderCursor {
                kind: provider.kind,
                id: provider.id,
            })
        } else {
            None
        };
        deadline.check(&mut tx).await?;
        tx.commit().await.map_err(unavailable)?;
        Ok(LinkedProviderPage { providers, next })
    }
}

async fn linked_rows(
    tx: &mut Transaction<'_, sqlx::Postgres>,
    realm: Uuid,
    owner: Uuid,
    after: Option<LinkedProviderCursor>,
) -> Result<Vec<PgRow>> {
    // Owner locking serializes erasure. The immutable identity issuer is
    // inventory, never evidence that a source is currently enabled or trusted.
    sqlx::query(
        r#"
        SELECT id,kind,issuer FROM (
            SELECT id,'oidc'::text AS kind,issuer FROM auth_oidc_identities
              WHERE realm_id=$1 AND user_id=$2
            UNION ALL
            SELECT id,'saml'::text AS kind,idp_entity AS issuer FROM auth_saml_identities
              WHERE realm_id=$1 AND user_id=$2
        ) identities
        WHERE ($3::text IS NULL OR (kind,id)>($3,$4::uuid))
        ORDER BY kind,id LIMIT $5
        "#,
    )
    .bind(realm)
    .bind(owner)
    .bind(after.map(|cursor| match cursor.kind {
        ProviderKind::Oidc => "oidc",
        ProviderKind::Saml => "saml",
    }))
    .bind(after.map(|cursor| cursor.id))
    .bind((LINKED_PROVIDER_PAGE_SIZE + 1) as i64)
    .fetch_all(&mut **tx)
    .await
    .map_err(unavailable)
}

fn provider_from_row(row: PgRow) -> Result<LinkedProvider> {
    Ok(LinkedProvider {
        id: row.get("id"),
        kind: match row.get::<&str, _>("kind") {
            "oidc" => ProviderKind::Oidc,
            "saml" => ProviderKind::Saml,
            _ => return Err(Error::Unavailable),
        },
        issuer: row.get("issuer"),
    })
}
