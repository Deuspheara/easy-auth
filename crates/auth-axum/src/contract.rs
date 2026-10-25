// Import generated path descriptors locally so Rust module paths do not become API tags.
use crate::error::ErrorResponse;
use crate::handlers::account::{
    __path_confirm_email_change, __path_finish_account_deletion, __path_start_account_deletion,
    __path_start_email_change,
};
use crate::handlers::account::{DeleteFinishInput, DeleteInput};
use crate::handlers::email::{__path_finish, __path_start};
use crate::handlers::health::{__path_health, __path_ready};
use crate::handlers::passwords::{__path_enroll_password, __path_password_login};
use crate::handlers::passwords::{PasswordEnrollmentInput, PasswordLoginInput};
use crate::handlers::providers::{
    __path_linked_providers, LinkedProviderResponse, LinkedProvidersResponse,
    ProviderCursorResponse, ProviderProtocol,
};
use crate::handlers::recovery::PasswordResetInput;
use crate::handlers::recovery::{__path_finish_password_reset, __path_start_password_reset};
use crate::handlers::sessions::listing::{
    __path_list_sessions, SessionListResponse, SessionResponse,
};
use crate::handlers::sessions::revocation::{
    __path_revoke_all_sessions, __path_revoke_session, RevokeAllInput, RevokeSessionInput,
};
use crate::handlers::sessions::{__path_logout, __path_session};
use crate::handlers::{Accepted, EmailInput, FinishInput, UserResponse};
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "easy-auth",
        description = "Experimental same-origin browser API; not an OIDC issuer. POST requests require the exact configured Origin. HTTPS production cookies use __Host- prefix, Secure, HttpOnly, SameSite=Lax, Path=/ and no Domain. Development loopback cookies omit the prefix and Secure. Auth responses are no-store."
    ),
    paths(
        health,
        ready,
        start,
        finish,
        enroll_password,
        password_login,
        start_email_change,
        confirm_email_change,
        start_account_deletion,
        finish_account_deletion,
        start_password_reset,
        finish_password_reset,
        session,
        logout,
        list_sessions,
        linked_providers,
        revoke_session,
        revoke_all_sessions
    ),
    components(schemas(
        EmailInput,
        FinishInput,
        PasswordEnrollmentInput,
        PasswordLoginInput,
        PasswordResetInput,
        DeleteInput,
        DeleteFinishInput,
        ErrorResponse,
        Accepted,
        UserResponse,
        SessionResponse,
        SessionListResponse,
        LinkedProviderResponse,
        LinkedProvidersResponse,
        ProviderCursorResponse,
        ProviderProtocol,
        RevokeSessionInput,
        RevokeAllInput
    ))
)]
struct ApiDoc;
/// Generated from the implemented HTTP handlers and transport DTOs.
pub fn openapi() -> utoipa::openapi::OpenApi {
    ApiDoc::openapi()
}
