fn main() {
    println!(
        "{}",
        easy_auth_axum::passkey_signup_openapi()
            .to_pretty_json()
            .expect("serializable protocol schema")
    );
}
