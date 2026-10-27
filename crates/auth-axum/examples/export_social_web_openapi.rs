fn main() {
    println!(
        "{}",
        easy_auth_axum::social_web_openapi()
            .to_pretty_json()
            .unwrap()
    );
}
