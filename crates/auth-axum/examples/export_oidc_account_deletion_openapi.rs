fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&easy_auth_axum::oidc_account_deletion_openapi()).unwrap()
    );
}
