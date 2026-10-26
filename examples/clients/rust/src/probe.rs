use reqwest::{Client, StatusCode, Url, redirect};
use std::{error::Error, time::Duration};

fn origin() -> Result<Url, Box<dyn Error>> {
    parse_origin(&std::env::var("EASY_AUTH_CLIENT_ORIGIN")?)
}

fn parse_origin(value: &str) -> Result<Url, Box<dyn Error>> {
    let url = Url::parse(value)?;
    let local = url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "[::1]"));
    if (url.scheme() != "https" && !local)
        || url.host_str().is_none()
        || url.port_or_known_default() == Some(0)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("expected an HTTPS origin or literal-loopback HTTP origin".into());
    }
    Ok(url)
}

#[cfg(test)]
mod tests;

pub(super) async fn run() -> Result<(), Box<dyn Error>> {
    let origin = origin()?;
    let client = Client::builder()
        .no_proxy()
        .redirect(redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10))
        .build()?;
    for (path, expected) in [
        ("healthz", StatusCode::OK),
        ("readyz", StatusCode::OK),
        ("v1/session", StatusCode::UNAUTHORIZED),
    ] {
        if client.get(origin.join(path)?).send().await?.status() != expected {
            return Err("unexpected public HTTP result".into());
        }
    }
    println!("{{\"health\":200,\"ready\":200,\"anonymous_session\":401}}");
    Ok(())
}
