//! Cookie-free SDK operations over the existing owned TLS transport.
use super::{
    FixtureResult,
    database::Database,
    ipc::{read_command, send},
    provision::Provision,
    server::Server,
    transport,
};
use auth_core::{OidcClient, OidcClientAuthentication, OidcClientConfiguration, OidcClientError};
use std::{io::BufRead, net::SocketAddr, path::Path, sync::atomic::Ordering};

pub(super) async fn run(
    config: &serde_json::Value,
    database: &Database,
    input: &mut impl BufRead,
) -> FixtureResult<()> {
    let origin = config["issuer"].as_str().ok_or("owned issuer required")?;
    let parsed = url::Url::parse(origin)?;
    if parsed.scheme() != "https"
        || parsed.host_str() != Some("fixture.invalid")
        || parsed.port().is_none()
    {
        return Err("exact owned TLS issuer required".into());
    }
    let directory = Path::new(
        config["directory"]
            .as_str()
            .ok_or("owned directory required")?,
    );
    send(serde_json::json!({"phase":"provision"}))?;
    let provision = Provision::new(&database.pool, origin, directory).await?;
    send(serde_json::json!({"phase":"server-startup"}))?;
    let (server, address) = Server::start(config, &database.name, &provision).await?;
    let certificate: Vec<u8> = serde_json::from_value(config["certificate_der"].clone())?;
    let target: SocketAddr = config["address"]
        .as_str()
        .ok_or("owned TLS address required")?
        .parse()?;
    let http = transport::Http::new(origin, target, certificate)?;
    let client = OidcClient::new(
        OidcClientConfiguration::web(
            origin,
            provision.client,
            "https://client.example/callback",
            OidcClientAuthentication::Public,
        )?,
        http.clone(),
        http.clone(),
    )?;
    send(
        serde_json::json!({"ready":true,"application_address":address.to_string(),"client_id":provision.client}),
    )?;
    let result=async {
        let mut pending=None;
        while let Some(command)=read_command(input)? {
            let id=command["id"].clone();
            match command["command"].as_str() {
                Some("close")=>break,
                Some("authorize")=>{
                    if pending.is_some() {return Err("owned operation already retained".into());}
                    let operation=client.authorize().await?;
                    send(serde_json::json!({"id":id,"authorization_url":operation.authorization_url()}))?;
                    pending=Some(operation);
                }
                Some("complete")=>{
                    let actual=command["callback"].as_str().ok_or("actual callback required")?;
                    let operation=pending.take().ok_or("owned pending operation required")?;
                    let before=http.posts.load(Ordering::SeqCst);
                    match client.complete(operation,actual).await {
                        Ok(tokens)=>{
                            let identity=tokens.identity();
                            if identity.issuer()!=origin || identity.client()!=provision.client || identity.authenticated_at().is_none() || tokens.refresh_token().is_some() {
                                return Err("owned SDK projection mismatch".into());
                            }
                            send(serde_json::json!({"id":id,"verified":true,"posts":http.posts.load(Ordering::SeqCst)-before,"subject_pairwise":uuid::Uuid::parse_str(identity.subject()).is_ok()}))?;
                        }
                        Err(OidcClientError::Denied)=>send(serde_json::json!({"id":id,"denied":true,"posts":http.posts.load(Ordering::SeqCst)-before}))?,
                        Err(_)=>return Err("owned SDK operation failed".into()),
                    }
                }
                _=>return Err("unsupported owned command".into()),
            }
        }
        Ok(())
    }.await;
    server.stop()?;
    result
}
