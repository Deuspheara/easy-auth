fn main() {
    println!(
        "{}",
        easy_auth_axum::saml_account_deletion_web_openapi()
            .to_pretty_json()
            .unwrap()
    );
}
