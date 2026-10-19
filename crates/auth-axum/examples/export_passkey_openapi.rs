fn main() {
    println!(
        "{}",
        easy_auth_axum::passkey_enrollment_openapi()
            .to_pretty_json()
            .expect("serializable protocol schema")
    );
}
