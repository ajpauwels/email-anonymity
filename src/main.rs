use std::error::Error as StdError;
use std::{collections::HashMap, time::Duration};

use ::oauth2::{AuthorizationCode, CsrfToken, TokenResponse};
use base64::prelude::*;
use config::{Config, ConfigError};
use lettre::{
    message::{
        header::{
            ContentType as LettreContentType, Header as LettreHeader,
            HeaderName as LettreHeaderName, HeaderValue as LettreHeaderValue,
        },
        Mailbox as LettreMailbox,
    },
    transport::smtp::authentication::{
        Credentials as LettreCredentials, Mechanism as LettreMechanism,
    },
    Message as LettreMessage, SmtpTransport, Transport,
};
use mail_parser::MessageParser;
use oauth2::OAuth2Config;
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::box_::{self};
use sphinx_packet::header::delays;
use sphinx_packet::route::{Destination, DestinationAddressBytes, Node, NodeAddressBytes};
use sphinx_packet::{ProcessedPacketData, SURBMaterial, SphinxPacket, SURB};
use tiny_http::{Response, Server};
use tokio::time::sleep;
use url::Url;
use x25519_dalek::{PublicKey as PublicKeyDalek, StaticSecret as StaticSecretDalek};

mod deserialization;
use deserialization::{
    as_base64, as_base64_option, as_durationstring_option, string_is_duration_option,
    string_is_ecc_public_key_dalek, string_is_ecc_secret_key_dalek_option,
};
mod oauth2;

#[derive(Deserialize, Serialize)]
struct SmtpConfig {
    address: String,
}

#[derive(Deserialize, Serialize)]
struct ImapConfig {
    address: String,
    #[serde(
        default,
        serialize_with = "as_durationstring_option",
        deserialize_with = "string_is_duration_option"
    )]
    keepalive: Option<Duration>,
    #[serde(
        default,
        serialize_with = "as_durationstring_option",
        deserialize_with = "string_is_duration_option"
    )]
    poll: Option<Duration>,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(tag = "type")]
enum AuthConfig {
    #[serde(rename = "oauth2")]
    OAuth2(OAuth2Config),
    #[serde(rename = "password")]
    Password { password: String },
}

#[derive(Deserialize, Serialize)]
struct EmailConfig {
    auth: AuthConfig,
    smtp: SmtpConfig,
    imap: ImapConfig,
    mailboxes: Vec<String>,
}

#[derive(Deserialize, Serialize)]
struct SecretIdentityConfig {
    address: String,
    name: String,
    #[serde(
        default,
        rename = "secretkey",
        serialize_with = "as_base64_option",
        deserialize_with = "string_is_ecc_secret_key_dalek_option"
    )]
    secret_key: Option<StaticSecretDalek>,
}

#[derive(Deserialize, Serialize)]
struct PublicIdentityConfig {
    address: String,
    name: String,
    #[serde(
        rename = "publickey",
        serialize_with = "as_base64",
        deserialize_with = "string_is_ecc_public_key_dalek"
    )]
    public_key: PublicKeyDalek,
}

#[derive(Deserialize, Serialize)]
struct ShallotConfig {
    email: EmailConfig,
    identity: SecretIdentityConfig,
    #[serde(rename = "addressbook")]
    address_book: Vec<PublicIdentityConfig>,
}

#[derive(Clone)]
struct PublicKeyHeader {
    key: String,
}
impl LettreHeader for PublicKeyHeader {
    fn name() -> LettreHeaderName {
        LettreHeaderName::new_from_ascii_str("X-Shallot-Public-Key")
    }

    fn parse(s: &str) -> Result<Self, Box<dyn StdError + Send + Sync>> {
        Ok(PublicKeyHeader { key: s.to_owned() })
    }

    fn display(&self) -> LettreHeaderValue {
        LettreHeaderValue::new(Self::name(), self.key.clone())
    }
}

fn load_config(path: &str, prefix: &str) -> Result<ShallotConfig, ConfigError> {
    let mut config_builder = Config::builder();
    let paths = std::fs::read_dir(path)
        .map_err(|_| ConfigError::Message(format!("Could not read directory at {}", path)))?
        .filter_map(|result| result.ok())
        .map(|de| de.path());
    for path in paths {
        config_builder = match path.as_path().to_str() {
            Some(s) => {
                if s.ends_with(".yaml") {
                    config_builder.add_source(config::File::with_name(s))
                } else {
                    config_builder
                }
            }
            None => config_builder,
        };
    }
    config_builder
        .add_source(config::Environment::with_prefix(prefix).separator("_"))
        .build()?
        .try_deserialize()
}

struct ImapOauth2 {
    user: String,
    access_token: String,
}

impl imap::Authenticator for ImapOauth2 {
    type Response = String;
    fn process(&self, _: &[u8]) -> Self::Response {
        format!(
            "user={}\x01auth=Bearer {}\x01\x01",
            self.user, self.access_token
        )
    }
}

#[derive(Deserialize, Debug)]
struct Oauth2Redirect {
    code: AuthorizationCode,
    state: CsrfToken,
}

enum CryptoLibrary {
    NaCl,
    Dalek,
}

impl std::fmt::Display for CryptoLibrary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NaCl => f.write_str("nacl"),
            Self::Dalek => f.write_str("dalek"),
        }
    }
}

#[tokio::main]
async fn main() {
    // Set our default crypto library
    let default_crypto_lib = CryptoLibrary::Dalek;

    // Get app config
    let config_path = "./config";
    let config = load_config(config_path, "APPCFG").unwrap();

    // Generate keys if they don't exist
    let (pk, pk_b64, sk, sk_b64) = match default_crypto_lib {
        CryptoLibrary::NaCl => {
            let (_, sk_nacl) = box_::gen_keypair();
            let sk = StaticSecretDalek::from(sk_nacl.0);
            let pk = PublicKeyDalek::from(&sk);
            let pk_b64 = BASE64_STANDARD.encode(pk);
            let sk_b64 = BASE64_STANDARD.encode(&sk);
            (pk, pk_b64, sk, sk_b64)
        }
        CryptoLibrary::Dalek => {
            let sk = StaticSecretDalek::random();
            let pk = PublicKeyDalek::from(&sk);
            let pk_b64 = BASE64_STANDARD.encode(pk);
            let sk_b64 = BASE64_STANDARD.encode(&sk);
            (pk, pk_b64, sk, sk_b64)
        }
    };
    let sk = match config.identity.secret_key {
        Some(ref sk) => sk,
        None => {
            println!("Generated new key material using {}", default_crypto_lib);
            println!("Generated secret key: {}", sk_b64);
            println!("Generated public key: {}", pk_b64);
            println!(
                "To persist, set the environment variable APPCFG_IDENTITY_SECRETKEY_{}=\"{}\"",
                default_crypto_lib.to_string().to_uppercase(),
                sk_b64,
            );
            &sk
        }
    };

    // Generate the address book hashmap
    let address_book = build_address_book(config.address_book.as_ref());

    let (password, smtp_auth_mechanism) = match config.email.auth {
        AuthConfig::OAuth2(ref oauth2) => {
            // Build oauth2 redirect listener
            let redirect_url = Url::try_from(oauth2.redirect_url.as_str()).unwrap();
            let redirect_host = redirect_url.host_str().unwrap();
            let redirect_port = redirect_url.port_or_known_default().unwrap();

            let access_token = match oauth2.access_token_override {
                Some(ref t) => t.clone(),
                None => {
                    // Create server to handle oauth2 redirect
                    let server =
                        Server::http(format!("{}:{}", redirect_host, redirect_port)).unwrap();

                    // Begin oauth2 flow
                    let (pkce_verifier, csrf_token) =
                        oauth2::begin_oauth2_flow(oauth2.clone()).unwrap();

                    // Receive oauth2 redirection
                    let redirect_request = server.recv().unwrap();
                    drop(server);
                    let url =
                        Url::try_from(format!("localhost:8080{}", redirect_request.url()).as_ref())
                            .unwrap();
                    let oauth2_redirect_params: Oauth2Redirect =
                        serde_qs::from_str(url.query().unwrap()).unwrap();

                    // Send back a 200 response
                    redirect_request.respond(Response::empty(200)).unwrap();

                    // Verify received csrf token is generated csrf token
                    assert_eq!(csrf_token.secret(), oauth2_redirect_params.state.secret());

                    // Exchange authorization code for tokens
                    let token_response = oauth2::complete_oauth2_flow(
                        oauth2.clone(),
                        pkce_verifier,
                        oauth2_redirect_params.code,
                    )
                    .await
                    .unwrap();
                    let t = String::from(token_response.access_token().secret());
                    println!("Access token: {}", t);
                    t
                }
            };
            (access_token, LettreMechanism::Xoauth2)
        }
        AuthConfig::Password { ref password } => (password.clone(), LettreMechanism::Plain),
    };

    // Login to SMTP
    let smtp_creds = LettreCredentials::new(config.identity.address.clone(), password.clone());
    let mailer = SmtpTransport::relay(config.email.smtp.address.as_str())
        .unwrap()
        .credentials(smtp_creds)
        .authentication(vec![smtp_auth_mechanism])
        .build();

    // Uncomment to send an email
    send_email(
        config.identity.name.clone(),
        config.identity.address.clone(),
        pk,
        &address_book,
        &mailer,
    );

    // Store our async handles in a vector
    let mut handles = vec![];

    for mailbox in config.email.mailboxes.iter() {
        let mailbox = mailbox.clone();
        let email_address = config.identity.address.clone();
        let name = config.identity.name.clone();
        let password = password.clone();
        let mailer = mailer.clone();
        let sk = sk.clone();
        let email_auth = config.email.auth.clone();
        let imap_domain = config.email.imap.address.clone();
        let idle_keepalive = config.email.imap.keepalive;
        let poll_interval = config.email.imap.poll;

        let listener = tokio::spawn(async move {
            // Log in to IMAP
            let tls = native_tls::TlsConnector::builder().build().unwrap();
            let client =
                imap::connect((imap_domain.as_str(), 993), imap_domain.as_str(), &tls).unwrap();
            let mut imap_session = match email_auth {
                AuthConfig::OAuth2 { .. } => {
                    let gmail_auth = ImapOauth2 {
                        user: email_address.clone(),
                        access_token: password.clone(),
                    };
                    client.authenticate("XOAUTH2", &gmail_auth).unwrap()
                }
                AuthConfig::Password { .. } => client
                    .login(email_address.as_str(), password.as_str())
                    .unwrap(),
            };

            // Select our mailbox
            imap_session.select(&mailbox).unwrap();

            println!("Beginning to listen on IMAP mailbox {}", &mailbox);

            // Process shallot messages as they arrive
            loop {
                let search_response = imap_session.search("NOT SEEN SUBJECT \"shallot\"").unwrap();
                for uid in search_response.iter() {
                    let fetches = imap_session.fetch(uid.to_string(), "BODY[]").unwrap();
                    if let Some(f) = fetches.iter().next() {
                        if let Some(b) = f.body() {
                            let message = MessageParser::default().parse(b).unwrap();
                            let body_b64 = message.body_text(0).unwrap();
                            let body = BASE64_STANDARD.decode(body_b64.trim()).unwrap();

                            if let Ok(packet) = SphinxPacket::from_bytes(&body) {
                                match packet.process(&sk).unwrap().data {
                                    ProcessedPacketData::ForwardHop {
                                        next_hop_packet,
                                        next_hop_address,
                                        delay,
                                    } => {
                                        println!(
                                            "This is an intermediate packet that must be forwarded"
                                        );
                                        let from: LettreMailbox =
                                            format!("{} <{}>", &name, &email_address)
                                                .parse()
                                                .unwrap();
                                        let mut to_addr_vec = next_hop_address.to_bytes().to_vec();
                                        let to_addr =
                                            match to_addr_vec.iter().rposition(|&b| b != 0u8) {
                                                Some(len) => {
                                                    to_addr_vec.truncate(len + 1);
                                                    String::from_utf8(to_addr_vec).unwrap()
                                                }
                                                None => String::from_utf8(to_addr_vec).unwrap(),
                                            };
                                        let to: LettreMailbox = to_addr.parse().unwrap();
                                        let body =
                                            BASE64_STANDARD.encode(next_hop_packet.to_bytes());
                                        println!("Forwarding packet to: {}", to);
                                        let email = LettreMessage::builder()
                                            .from(from)
                                            .to(to)
                                            .subject("shallot")
                                            .header(LettreContentType::TEXT_PLAIN)
                                            .body(body)
                                            .unwrap();
                                        sleep(delay.to_duration()).await;
                                        mailer.send(&email).unwrap();
                                    }
                                    ProcessedPacketData::FinalHop {
                                        destination,
                                        identifier,
                                        payload,
                                    } => {
                                        println!("This is the final encrypted hop of the payload");
                                        let mut to_addr_vec = destination.as_bytes().to_vec();
                                        let to_addr =
                                            match to_addr_vec.iter().rposition(|&b| b != 0u8) {
                                                Some(len) => {
                                                    to_addr_vec.truncate(len + 1);
                                                    String::from_utf8(to_addr_vec).unwrap()
                                                }
                                                None => String::from_utf8(to_addr_vec).unwrap(),
                                            };
                                        let payload_b64 = payload.recover_plaintext().unwrap();
                                        if to_addr == email_address.clone() {
                                            println!("This inbox is the final destination of the payload");
                                            let payload_decoded =
                                                BASE64_STANDARD.decode(payload_b64).unwrap();

                                            if let Ok(surb) = SURB::from_bytes(&payload_decoded) {
                                                println!("Payload is a SURB, responding");
                                                use_surb(
                                                    &name,
                                                    &email_address,
                                                    surb,
                                                    "XATTACKXHASXBEGUNX",
                                                    &mailer,
                                                );
                                            } else {
                                                let payload_string =
                                                    String::from_utf8(payload_decoded).unwrap();
                                                println!("Payload: {}", payload_string);
                                            }
                                        } else {
                                            println!("WARNING: This inbox is not the final destination of the payload, payload must be forwarded in plaintext");
                                            let from: LettreMailbox =
                                                format!("{} <{}>", &name, &email_address)
                                                    .parse()
                                                    .unwrap();
                                            let to: LettreMailbox = to_addr.parse().unwrap();
                                            println!("Forwarding plaintext payload to: {}", to);
                                            let email = LettreMessage::builder()
                                                .from(from)
                                                .to(to)
                                                .subject("shallot")
                                                .header(LettreContentType::TEXT_PLAIN)
                                                .body(payload_b64)
                                                .unwrap();
                                            mailer.send(&email).unwrap();
                                        }
                                    }
                                };
                            } else {
                                println!("Received contents could not be deserialized into a Sphinx packet");
                            }
                        } else {
                            println!(
                                "Message with uid \"{}\" exists but did not have a body",
                                uid
                            );
                        }
                    } else {
                        println!("Message with uid \"{}\" could not be fetched", uid);
                    }
                }

                // Either wait for updates using IDLE or sleep and
                // poll again
                match (poll_interval, idle_keepalive) {
                    (Some(interval), _) => {
                        // Logout
                        imap_session.logout().unwrap();

                        // Sleep before trying again
                        sleep(interval).await;

                        // Log in to IMAP again
                        let tls = native_tls::TlsConnector::builder().build().unwrap();
                        let client =
                            imap::connect((imap_domain.as_str(), 993), imap_domain.as_str(), &tls)
                                .unwrap();
                        imap_session = match email_auth {
                            AuthConfig::OAuth2 { .. } => {
                                let gmail_auth = ImapOauth2 {
                                    user: email_address.clone(),
                                    access_token: password.clone(),
                                };
                                client.authenticate("XOAUTH2", &gmail_auth).unwrap()
                            }
                            AuthConfig::Password { .. } => client
                                .login(email_address.as_str(), password.as_str())
                                .unwrap(),
                        };

                        // Select our mailbox
                        imap_session.select(&mailbox).unwrap();
                    }
                    (None, Some(keepalive)) => {
                        let mut idle_handle = imap_session.idle().unwrap();
                        idle_handle.set_keepalive(keepalive);
                        idle_handle.wait_keepalive().unwrap();
                    }
                    (None, None) => {
                        let idle_handle = imap_session.idle().unwrap();
                        idle_handle.wait_keepalive().unwrap();
                    }
                }
            }
        });
        handles.push(listener);
    }

    futures::future::join_all(handles).await;
}

// Takes a string and converts it to an array of 32-bytes, panicking
// if the string is too long, and filling the rest of the array with
// zeros if it's too short
fn string_to_byte_array_32(s: String) -> [u8; 32] {
    if s.len() > 32 {
        panic!("String \"{}\" is longer than 32 character", s);
    } else {
        let s_bytes = s.into_bytes();
        let mut v = [0u8; 32];
        v[..s_bytes.len()].copy_from_slice(&s_bytes[..]);
        v
    }
}

fn build_sphinx_packet(
    sender_tuple: (String, PublicKeyDalek),
    destination_tuple: (String, PublicKeyDalek),
    route: Vec<(String, PublicKeyDalek)>,
) -> String {
    // Define destination
    let destination = Destination::new(
        DestinationAddressBytes::from_bytes(string_to_byte_array_32(destination_tuple.0)),
        [0u8; 16],
    );

    // Define sender
    let sender = Destination::new(
        DestinationAddressBytes::from_bytes(string_to_byte_array_32(sender_tuple.0.clone())),
        [1u8; 16],
    );

    // Define forward route
    let mut forward_route: Vec<Node> = route
        .into_iter()
        .map(|(addr, pk)| {
            Node::new(
                NodeAddressBytes::from_bytes(string_to_byte_array_32(addr)),
                pk,
            )
        })
        .collect();

    // Define SURB route as reverse of forward route
    let mut reverse_route = forward_route.clone();
    reverse_route.reverse();

    // Add last endpoint to each route
    forward_route.push(Node::new(
        NodeAddressBytes::from_bytes(destination.address.as_bytes()),
        destination_tuple.1,
    ));
    reverse_route.push(Node::new(
        NodeAddressBytes::from_bytes(sender.address.as_bytes()),
        sender_tuple.1,
    ));

    // Generate the SURB
    let surb_initial_secret = StaticSecretDalek::random();
    let surb_average_delay = Duration::from_secs(3);
    let surb_delays =
        delays::generate_from_average_duration(reverse_route.len(), surb_average_delay);
    let surb = SURB::new(
        surb_initial_secret,
        SURBMaterial::new(reverse_route, surb_delays, sender),
    )
    .unwrap();
    let surb_b64 = BASE64_STANDARD.encode(surb.to_bytes()).into_bytes();
    println!("SURB is {} bytes long", surb_b64.len());
    let plain_b64 = BASE64_STANDARD
        .encode("XATTACKXATXDAWNX".as_bytes())
        .into_bytes();

    // Generate the Sphinx packet containing the SURB as payload
    let average_delay = Duration::from_secs(1);
    let delays = delays::generate_from_average_duration(forward_route.len(), average_delay);
    let sphinx_packet = SphinxPacket::new(surb_b64, &forward_route, &destination, &delays).unwrap();

    BASE64_STANDARD.encode(sphinx_packet.to_bytes())
}

fn send_email(
    sender_name: String,
    sender_addr: String,
    sender_pk: PublicKeyDalek,
    address_book: &HashMap<String, &PublicIdentityConfig>,
    mailer: &SmtpTransport,
) {
    let route_addrs = [
        "johncamacuk@yahoo.com".to_string(),
        //"johncamacuk@gmail.com".to_string(),
    ];
    let destination_addr = "johncamacuk@gmail.com".to_string();
    let destination_pk = address_book
        .get(destination_addr.as_str())
        .unwrap()
        .public_key;

    let packet = {
        let route = route_addrs
            .iter()
            .filter_map(|addr| {
                address_book
                    .get(addr.as_str())
                    .map(|entry| (addr.to_string(), entry.public_key))
            })
            .collect();
        build_sphinx_packet(
            (sender_addr.clone(), sender_pk),
            (destination_addr, destination_pk),
            route,
        )
    };

    // Construct email
    let from: LettreMailbox = format!("{} <{}>", sender_name, sender_addr)
        .parse()
        .unwrap();
    let to: LettreMailbox = format!("{} <{}>", "John Camacuk", "johncamacuk@yahoo.com")
        .parse()
        .unwrap();
    let email = LettreMessage::builder()
        .from(from.clone())
        .to(to.clone())
        .subject("shallot")
        .header(LettreContentType::TEXT_PLAIN)
        .body(packet)
        .unwrap();

    println!("Sending message");
    mailer.send(&email).unwrap();
    println!("Message sent");
}

fn use_surb(
    from_name: &str,
    from_address: &str,
    surb: SURB,
    message: &str,
    mailer: &SmtpTransport,
) {
    let message_b64 = BASE64_STANDARD.encode(message.as_bytes());
    match surb.use_surb(message_b64.as_bytes(), 1024) {
        Ok((packet, next_hop_address)) => {
            let packet_b64 = BASE64_STANDARD.encode(packet.to_bytes());

            // Construct email
            let from: LettreMailbox = format!("{} <{}>", from_name, from_address).parse().unwrap();
            let mut to_addr_vec = next_hop_address.to_bytes().to_vec();
            let to_addr = match to_addr_vec.iter().rposition(|&b| b != 0u8) {
                Some(len) => {
                    to_addr_vec.truncate(len + 1);
                    String::from_utf8(to_addr_vec).unwrap()
                }
                None => String::from_utf8(to_addr_vec).unwrap(),
            };
            let to: LettreMailbox = to_addr.parse().unwrap();
            let email = LettreMessage::builder()
                .from(from.clone())
                .to(to.clone())
                .subject("shallot")
                .header(LettreContentType::TEXT_PLAIN)
                .body(packet_b64)
                .unwrap();

            println!("Sending message");
            mailer.send(&email).unwrap();
            println!("Message sent");
        }
        Err(e) => println!("Could not use SURB: {}", e),
    };
}

fn build_address_book(
    addresses: &[PublicIdentityConfig],
) -> HashMap<String, &PublicIdentityConfig> {
    let mut hm = HashMap::new();
    for address in addresses.iter() {
        hm.insert(address.address.clone(), address);
    }
    hm
}
