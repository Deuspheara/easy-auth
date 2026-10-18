fn main() {
    println!(
        "{}",
        easy_auth_axum::openapi()
            .to_pretty_json()
            .expect("serializable schema")
    );
}
