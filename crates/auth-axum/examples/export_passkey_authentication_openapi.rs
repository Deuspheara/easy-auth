fn main() {
    println!(
        "{}",
        easy_auth_axum::passkey_authentication_openapi()
            .to_pretty_json()
            .expect("serializable protocol schema")
    );
}
