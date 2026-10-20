fn main() {
    println!(
        "{}",
        easy_auth_axum::google_web_openapi()
            .to_pretty_json()
            .unwrap()
    );
}
