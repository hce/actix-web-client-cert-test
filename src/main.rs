//! This example shows how to use `actix_web::HttpServer::on_connect` to access a lower-level socket
//! properties and pass them to a handler through request-local data.
//!
//! For an example of extracting a client TLS certificate, see:
//! <https://github.com/actix/examples/tree/HEAD/rustls-client-cert>

use std::io::BufReader;
use std::{any::Any, env, io, net::SocketAddr};

use actix_tls::rustls::{ServerConfig, TlsStream};
use actix_web::rt::net::TcpStream;
use actix_web::{dev::Extensions, web, App, HttpServer};
use rustls::Session;

#[derive(Debug, Clone)]
struct ConnectionInfo {
    bind: SocketAddr,
    peer: SocketAddr,
    ttl: Option<u32>,
}

async fn route_whoami(conn_info: web::ReqData<ConnectionInfo>) -> String {
    format!(
        "Here is some info about your connection:\n\n{:#?}",
        conn_info
    )
}

fn get_conn_info(connection: &dyn Any, data: &mut Extensions) {
    eprintln!("1 CONNINFO");
    if let Some(tls_socket) = connection.downcast_ref::<TlsStream<TcpStream>>() {
        eprintln!("2 TLS CONNECTION");
        let (socket, tls_session) = tls_socket.get_ref();

        data.insert(ConnectionInfo {
            bind: socket.local_addr().unwrap(),
            peer: socket.peer_addr().unwrap(),
            ttl: socket.ttl().ok(),
        });

        if let Some(mut certs) = tls_session.get_peer_certificates() {
            eprintln!("3 WITH CLIENT CERTIFICATE");
            // insert a `rustls::Certificate` into request data
            data.insert(certs.pop().unwrap());
        }
    }
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }

    env_logger::init();

    let http_server = HttpServer::new(|| App::new().default_service(web::to(route_whoami)));

    let http_server = http_server.on_connect(get_conn_info);

    let http_server = {
        let mut roots = rustls::RootCertStore::empty();
        let f = std::fs::File::open("ca.pem")
            .expect(&format!("Unable to open {} for reading", "ca.pem"));
        let mut buf_read = std::io::BufReader::new(f);
        roots
            .add_pem_file(&mut buf_read)
            .expect("Error reading PEM file");
        let cca = rustls::AllowAnyAuthenticatedClient::new(roots);
        let mut rustls_config = ServerConfig::new(cca);
        let cert_file = std::fs::File::open("cert.pem").expect("Cannot find cert.pem");
        let mut cert_buf = BufReader::new(cert_file);
        let certs =
            rustls::internal::pemfile::certs(&mut cert_buf).expect("Unable to read cert.pem");
        let key_file = std::fs::File::open("key.pem").expect("Cannot find key.pem");
        let mut key_buf = BufReader::new(key_file);
        let keys = rustls::internal::pemfile::pkcs8_private_keys(&mut key_buf)
            .expect("Unable to read key.pem");
        if keys.len() != 1 {
            eprintln!("Expected number of keys: 1. Got {}", keys.len());
            std::process::exit(3);
        }
        let key = keys.into_iter().next().unwrap();
        rustls_config
            .set_single_cert(certs, key)
            .expect("Unable to use the supplied certificate");
        http_server.bind_rustls("127.0.0.1:8443", rustls_config)
    }
    .unwrap();

    http_server.run().await
}
