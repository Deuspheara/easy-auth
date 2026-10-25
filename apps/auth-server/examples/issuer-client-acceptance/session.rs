//! Owned process/TLS lifetime and private command dispatch.
use super::{
    FixtureResult,
    database::Database,
    ipc::{read_command, send},
    operations::Clients,
    provision::Provision,
    server::Server,
    transport,
};
use std::{io::BufRead, net::SocketAddr, path::Path};

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
    let mut provision = Provision::new(&database.pool, origin, directory).await?;
    send(serde_json::json!({"phase":"server-startup"}))?;
    let (server, address) = Server::start(config, &database.name, &provision).await?;
    let mut server = Some(server);
    let certificate: Vec<u8> = serde_json::from_value(config["certificate_der"].clone())?;
    let target: SocketAddr = config["address"]
        .as_str()
        .ok_or("owned TLS address required")?
        .parse()?;
    let http = transport::Http::new(origin, target, certificate)?;
    let mut clients = Clients::new(config, &provision, http)?;
    send(
        serde_json::json!({"ready":true,"application_address":address.to_string(),"client_id":provision.client,"native_client_id":provision.native_client}),
    )?;
    let result = async {
        while let Some(command) = read_command(input)? {
            if command["command"].as_str() == Some("close") {
                break;
            }
            let mut response = match command["command"].as_str() {
                Some("publish_rotation") => serde_json::json!({"propagation_seconds":provision.publish_rotation(&database.pool).await?}),
                Some("activate_rotation") => {
                    provision.activate_rotation(&database.pool).await?;
                    server.take().ok_or("owned process required")?.stop()?;
                    let (next,address) = Server::start(config,&database.name,&provision).await?;
                    server=Some(next);
                    serde_json::json!({"application_address":address.to_string()})
                }
                _ => clients.command(&command).await?,
            };
            response["id"] = command["id"].clone();
            send(response)?;
        }
        Ok(())
    }
    .await;
    if let Some(server) = server {
        server.stop()?;
    }
    result
}
