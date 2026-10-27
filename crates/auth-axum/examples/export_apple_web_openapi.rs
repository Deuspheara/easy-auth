fn main() {
    println!(
        "{}",
        easy_auth_axum::apple_web_openapi()
            .to_pretty_json()
            .unwrap()
    );
}
