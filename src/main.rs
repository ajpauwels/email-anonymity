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
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::box_::{
    self, Nonce, PublicKey as PublicKeyNaCl, SecretKey as SecretKeyNaCl,
};
use sphinx_packet::header::delays;
use sphinx_packet::route::{Destination, DestinationAddressBytes, Node, NodeAddressBytes};
use sphinx_packet::{ProcessedPacketData, SURBMaterial, SphinxPacket, SURB};
use surb::{Link, SingleUseReplyBlock};
use tiny_http::{Response, Server};
use tokio::time::sleep;
use url::Url;
use x25519_dalek::{PublicKey as PublicKeyDalek, StaticSecret as StaticSecretDalek};

mod deserialization;
use deserialization::{
    as_base64, string_is_duration_option, string_is_ecc_public_key, string_is_ecc_public_key_dalek,
    string_is_ecc_secret_key, string_is_ecc_secret_key_dalek, string_is_nonce,
};
mod oauth2;
use oauth2::OAuth2Config;
mod surb;

#[derive(Deserialize)]
struct SmtpConfig {
    address: String,
}

#[derive(Deserialize)]
struct ImapConfig {
    address: String,
    #[serde(default, deserialize_with = "string_is_duration_option")]
    keepalive: Option<Duration>,
    #[serde(default, deserialize_with = "string_is_duration_option")]
    poll: Option<Duration>,
}

#[derive(Deserialize)]
struct AuthConfig {
    r#type: AuthType,
    oauth2: Option<OAuth2Config>,
    password: Option<String>,
    smtp: SmtpConfig,
    imap: ImapConfig,
}

#[derive(Deserialize, Copy, Clone)]
enum AuthType {
    #[serde(rename = "oauth2")]
    OAuth2,
    #[serde(rename = "password")]
    Password,
}

#[derive(Serialize, Deserialize, Clone)]
//#[serde(tag = "type")]
enum SecretKey {
    #[serde(
        serialize_with = "as_base64",
        deserialize_with = "string_is_ecc_secret_key",
        rename = "nacl"
    )]
    NaCl(SecretKeyNaCl),
    #[serde(
        serialize_with = "as_base64",
        deserialize_with = "string_is_ecc_secret_key_dalek",
        rename = "dalek"
    )]
    Dalek(StaticSecretDalek),
}

#[derive(Serialize, Deserialize)]
struct SecretIdentityConfig {
    address: String,
    name: String,
    #[serde(rename = "secretkey")]
    secret_key: Option<SecretKey>,
}

#[derive(Serialize, Deserialize, Clone)]
//#[serde(tag = "type")]
enum PublicKey {
    #[serde(
        serialize_with = "as_base64",
        deserialize_with = "string_is_ecc_public_key",
        rename = "nacl"
    )]
    NaCl(PublicKeyNaCl),
    #[serde(
        serialize_with = "as_base64",
        deserialize_with = "string_is_ecc_public_key_dalek",
        rename = "dalek"
    )]
    Dalek(PublicKeyDalek),
}

#[derive(Deserialize)]
struct PublicIdentityConfig {
    address: String,
    name: String,
    #[serde(rename = "publickey")]
    public_key: PublicKey,
}

#[derive(Deserialize)]
struct ShallotConfig {
    auth: AuthConfig,
    mailboxes: Vec<String>,
    identity: SecretIdentityConfig,
    #[serde(rename = "addressbook")]
    address_book: Vec<PublicIdentityConfig>,
}

#[derive(Deserialize, Serialize, Debug)]
struct ShallotHeader {
    next: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct ShallotMessage {
    header: Option<ShallotHeader>,
    body: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct ShallotMessageWrapper {
    #[serde(
        serialize_with = "as_base64",
        deserialize_with = "string_is_ecc_public_key"
    )]
    ephemeral_key: PublicKeyNaCl,
    #[serde(serialize_with = "as_base64", deserialize_with = "string_is_nonce")]
    nonce: Nonce,
    message: String,
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

#[tokio::main]
async fn main() {
    // Set our default crypto library
    let default_crypto_lib = CryptoLibrary::Dalek;

    // Get app config
    let config_path = "./config";
    let config = load_config(config_path, "APPCFG").unwrap();

    // Generate keys if they don't exist
    let (_, pk_b64, sk, sk_b64) = match default_crypto_lib {
        CryptoLibrary::NaCl => {
            let (pk, sk) = box_::gen_keypair();
            let pk_b64 = BASE64_STANDARD.encode(&pk);
            let sk_b64 = BASE64_STANDARD.encode(&sk);
            (PublicKey::NaCl(pk), pk_b64, SecretKey::NaCl(sk), sk_b64)
        }
        CryptoLibrary::Dalek => {
            let sk = StaticSecretDalek::random();
            let pk = PublicKeyDalek::from(&sk);
            let pk_b64 = BASE64_STANDARD.encode(&pk);
            let sk_b64 = BASE64_STANDARD.encode(&sk);
            (PublicKey::Dalek(pk), pk_b64, SecretKey::Dalek(sk), sk_b64)
        }
    };
    let sk = match config.identity.secret_key {
        Some(ref sk) => sk,
        None => {
            println!("Generated secret key: {}", BASE64_STANDARD.encode(sk_b64),);
            println!("Generated public key: {}", BASE64_STANDARD.encode(pk_b64),);
            &sk
        }
    };

    // Generate the address book hashmap
    let address_book = build_address_book(config.address_book.as_ref());

    let (password, smtp_auth_mechanism) = match config.auth.r#type {
        AuthType::OAuth2 => {
            // Build oauth2 redirect listener
            let oauth2_config = config.auth.oauth2.as_ref().unwrap();
            let redirect_url = Url::try_from(oauth2_config.redirect_url.as_str()).unwrap();
            let redirect_host = redirect_url.host_str().unwrap();
            let redirect_port = redirect_url.port_or_known_default().unwrap();

            let access_token = match oauth2_config.access_token_override {
                Some(ref t) => t.clone(),
                None => {
                    // Create server to handle oauth2 redirect
                    let server =
                        Server::http(format!("{}:{}", redirect_host, redirect_port)).unwrap();

                    // Begin oauth2 flow
                    let (pkce_verifier, csrf_token) =
                        oauth2::begin_oauth2_flow(oauth2_config.clone()).unwrap();

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
                        oauth2_config.clone(),
                        pkce_verifier,
                        oauth2_redirect_params.code,
                    )
                    .await
                    .unwrap();
                    let t = String::from(token_response.access_token().secret());
                    println!("{}", t);
                    t
                }
            };
            (access_token, LettreMechanism::Xoauth2)
        }
        AuthType::Password => (
            config.auth.password.clone().unwrap(),
            LettreMechanism::Plain,
        ),
    };

    // Login to SMTP
    let smtp_creds = LettreCredentials::new(config.identity.address.clone(), password.clone());
    let mailer = SmtpTransport::relay(config.auth.smtp.address.as_str())
        .unwrap()
        .credentials(smtp_creds)
        .authentication(vec![smtp_auth_mechanism])
        .build();

    // Uncomment to send an email
    let secret_keys = send_email(&config, &address_book, sk, &mailer);
    // let secret_keys = vec![];

    // Store our async handles in a vector
    let mut handles = vec![];

    for mailbox in config.mailboxes.iter() {
        let mailbox = mailbox.clone();
        let email_address = config.identity.address.clone();
        let name = config.identity.name.clone();
        let password = password.clone();
        let mailer = mailer.clone();
        let sk = sk.clone();
        let imap_domain = config.auth.imap.address.clone();
        let idle_keepalive = config.auth.imap.keepalive;
        let poll_interval = config.auth.imap.poll;
        let secret_keys = secret_keys.clone();

        let listener = tokio::spawn(async move {
            // Log in to IMAP
            let tls = native_tls::TlsConnector::builder().build().unwrap();
            let client =
                imap::connect((imap_domain.as_str(), 993), imap_domain.as_str(), &tls).unwrap();
            let mut imap_session = match config.auth.r#type {
                AuthType::OAuth2 => {
                    let gmail_auth = ImapOauth2 {
                        user: email_address.clone(),
                        access_token: password.clone(),
                    };
                    client.authenticate("XOAUTH2", &gmail_auth).unwrap()
                }
                AuthType::Password => client
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

                            if let Ok(sm_wrapped) =
                                serde_yaml::from_slice::<ShallotMessageWrapper>(&body)
                            {
                                if let SecretKey::NaCl(ref sk) = sk {
                                    let sm_encrypted =
                                        BASE64_STANDARD.decode(&sm_wrapped.message).unwrap();
                                    let sm_decrypted = box_::open(
                                        &sm_encrypted,
                                        &sm_wrapped.nonce,
                                        &sm_wrapped.ephemeral_key,
                                        sk,
                                    )
                                    .unwrap();
                                    let sm: ShallotMessage =
                                        serde_yaml::from_slice(&sm_decrypted).unwrap();

                                    match sm.header {
                                        Some(header) => {
                                            let from: LettreMailbox =
                                                format!("{} <{}>", name, email_address.clone())
                                                    .parse()
                                                    .unwrap();
                                            let to: LettreMailbox = header.next.parse().unwrap();
                                            println!("Forwarding message to: {}", to);
                                            let email = LettreMessage::builder()
                                                .from(from)
                                                .to(to)
                                                .subject("shallot")
                                                .header(LettreContentType::TEXT_PLAIN)
                                                // .header(PublicKeyHeader {
                                                //     key: "0xDEADBEEF".to_owned(),
                                                // })
                                                .body(sm.body)
                                                .unwrap();
                                            mailer.send(&email).unwrap();
                                        }
                                        None => {
                                            let m_bytes = &BASE64_STANDARD.decode(sm.body).unwrap();
                                            let m = std::str::from_utf8(m_bytes).unwrap();
                                            match serde_yaml::from_str::<SingleUseReplyBlock>(m) {
                                                Ok(surb) => {
                                                    let response_msg = "XATTACKXHASXBEGUNX";
                                                    println!("Message is a shallot message containing a SURB, sending SURB back with response {}", response_msg);
                                                    surb.process(
                                                        email_address.clone(),
                                                        Some(response_msg),
                                                        &sk,
                                                        &secret_keys,
                                                        &mailer,
                                                    )
                                                    .unwrap();
                                                }
                                                Err(e) => {
                                                    println!("{}", e);
                                                    println!("Message is: {}", m);
                                                }
                                            }
                                        }
                                    }
                                }
                            } else if let Ok(surb) =
                                serde_yaml::from_slice::<SingleUseReplyBlock>(&body)
                            {
                                println!("Message is a SURB that needs to be either forwarded or the payload unraveled locally");
                                if let SecretKey::NaCl(ref sk) = sk {
                                    let msg = surb
                                        .process(
                                            email_address.clone(),
                                            None,
                                            sk,
                                            &secret_keys,
                                            &mailer,
                                        )
                                        .unwrap();
                                    if let Some(msg) = msg {
                                        println!("SURB response: {}", msg);
                                    }
                                }
                            } else if let Ok(packet) = SphinxPacket::from_bytes(&body) {
                                println!("This is a Sphinx packet");
                                if let SecretKey::Dalek(ref sk) = sk {
                                    println!("Local secret key is of Dalek-type");
                                    match packet.process(sk).unwrap().data {
                                        ProcessedPacketData::ForwardHop {
                                            next_hop_packet,
                                            next_hop_address,
                                            delay,
                                        } => {
                                            let from: LettreMailbox =
                                                format!("{} <{}>", name, email_address.clone())
                                                    .parse()
                                                    .unwrap();
                                            let mut to_addr_vec =
                                                next_hop_address.to_bytes().to_vec();
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
                                            let mut to_addr_vec = destination.as_bytes().to_vec();
                                            let to_addr =
                                                match to_addr_vec.iter().rposition(|&b| b != 0u8) {
                                                    Some(len) => {
                                                        to_addr_vec.truncate(len + 1);
                                                        String::from_utf8(to_addr_vec).unwrap()
                                                    }
                                                    None => String::from_utf8(to_addr_vec).unwrap(),
                                                };
                                            if to_addr == email_address.clone() {
                                                let payload_decoded = BASE64_STANDARD
                                                    .decode(payload.into_bytes())
                                                    .unwrap();
                                                let payload_string =
                                                    String::from_utf8(payload_decoded).unwrap();
                                                println!("Final payload: {}", payload_string);
                                            } else {
                                                let from: LettreMailbox =
                                                    format!("{} <{}>", name, email_address.clone())
                                                        .parse()
                                                        .unwrap();
                                                let to: LettreMailbox = to_addr.parse().unwrap();
                                                let body =
                                                    BASE64_STANDARD.encode(payload.into_bytes());
                                                println!("Forwarding payload to: {}", to);
                                                let email = LettreMessage::builder()
                                                    .from(from)
                                                    .to(to)
                                                    .subject("shallot")
                                                    .header(LettreContentType::TEXT_PLAIN)
                                                    .body(body)
                                                    .unwrap();
                                                mailer.send(&email).unwrap();
                                            }
                                        }
                                    };
                                }
                            } else {
                                println!("Did not recognize message type");
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
                        imap_session = match config.auth.r#type {
                            AuthType::OAuth2 => {
                                let gmail_auth = ImapOauth2 {
                                    user: email_address.clone(),
                                    access_token: password.clone(),
                                };
                                client.authenticate("XOAUTH2", &gmail_auth).unwrap()
                            }
                            AuthType::Password => client
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

fn build_custom_packet(
    sender_addr: String,
    destination_addr: String,
    destination_pk: PublicKeyNaCl,
    route: Vec<(String, PublicKeyNaCl)>,
) -> (String, Vec<SecretKeyNaCl>) {
    // Create the SURB
    let surb_route: Vec<Link> = route
        .clone()
        .into_iter()
        .rev()
        .map(|(addr, pk)| Link {
            address: addr,
            public_key: pk,
        })
        .collect();

    let (surb, secret_keys) =
        SingleUseReplyBlock::new(sender_addr, surb_route.as_slice(), None).unwrap();
    let surb_string_b64 = BASE64_STANDARD.encode(serde_yaml::to_string(&surb).unwrap());

    // Add destination to links list
    let mut route = route.clone();
    route.push((destination_addr, destination_pk));

    // Create message
    let plain_string_b64 = BASE64_STANDARD.encode("XATTACKXATXDAWNX");
    let mut prev_bytes = plain_string_b64;
    let mut prev_header = None;
    for (addr, pk) in route.into_iter().rev() {
        let sm = ShallotMessage {
            header: prev_header,
            body: prev_bytes,
        };
        let (sm_pk, sm_sk) = box_::gen_keypair();
        let sm_nonce = box_::gen_nonce();
        let sm_string = serde_yaml::to_string(&sm).unwrap();
        let sm_encrypted = box_::seal(sm_string.as_bytes(), &sm_nonce, &pk, &sm_sk);
        let sm_encrypted_b64 = BASE64_STANDARD.encode(&sm_encrypted);
        let sm_wrapped = ShallotMessageWrapper {
            ephemeral_key: sm_pk,
            nonce: sm_nonce,
            message: sm_encrypted_b64,
        };
        let sm_wrapped_string = serde_yaml::to_string(&sm_wrapped).unwrap();
        prev_bytes = BASE64_STANDARD.encode(&sm_wrapped_string);
        prev_header = Some(ShallotHeader { next: addr });
    }
    (prev_bytes, secret_keys)
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
    sender_addr: String,
    destination_addr: String,
    route: Vec<(String, PublicKeyDalek)>,
) -> (String, Vec<SecretKeyNaCl>) {
    let sphinx_route: Vec<Node> = route
        .into_iter()
        .map(|(addr, pk)| {
            Node::new(
                NodeAddressBytes::from_bytes(string_to_byte_array_32(addr)),
                pk,
            )
        })
        .collect();
    let mut surb_route = sphinx_route.clone();
    surb_route.reverse();

    // Define destination
    let destination = Destination::new(
        DestinationAddressBytes::from_bytes(string_to_byte_array_32(destination_addr)),
        [0u8; 16],
    );

    // Define sender
    let sender = Destination::new(
        DestinationAddressBytes::from_bytes(string_to_byte_array_32(sender_addr)),
        [1u8; 16],
    );

    // Generate the SURB
    let surb_initial_secret = StaticSecretDalek::random();
    let surb_average_delay = Duration::from_secs(3);
    let surb_delays = delays::generate_from_average_duration(surb_route.len(), surb_average_delay);
    let surb = SURB::new(
        surb_initial_secret,
        SURBMaterial::new(surb_route, surb_delays, sender),
    )
    .unwrap();
    let surb_bytes = surb.to_bytes();
    let plain_bytes = BASE64_STANDARD.encode("XATTACKXATXDAWNX".as_bytes());

    // Generate the Sphinx packet containing the SURB as payload
    let average_delay = Duration::from_secs(1);
    let delays = delays::generate_from_average_duration(sphinx_route.len(), average_delay);
    let sphinx_packet = SphinxPacket::new(
        plain_bytes.into_bytes(),
        &sphinx_route,
        &destination,
        &delays,
    )
    .unwrap();

    let sphinx_packet_bytes = BASE64_STANDARD.encode(sphinx_packet.to_bytes());
    (sphinx_packet_bytes, vec![])
}

fn send_email(
    config: &ShallotConfig,
    address_book: &HashMap<String, &PublicIdentityConfig>,
    sk: &SecretKey,
    mailer: &SmtpTransport,
) -> Vec<SecretKeyNaCl> {
    let route_addrs = ["johncamacuk@yahoo.com".to_string()];
    let sender_addr = config.identity.address.clone();
    let destination_addr = "johncamacuk@gmail.com".to_string();
    let destination_entry = address_book.get(&destination_addr).unwrap();

    let (packet, secret_keys) = match sk {
        SecretKey::NaCl(_) => {
            let route = route_addrs
                .iter()
                .filter_map(|addr| {
                    if let Some(entry) = address_book.get(addr.as_str()) {
                        if let PublicKey::NaCl(pk) = entry.public_key {
                            Some((addr.to_string(), pk))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect();
            let destination_pk = if let PublicKey::NaCl(pk) = destination_entry.public_key {
                pk
            } else {
                panic!("Destination public key was not sodiumoxide");
            };
            build_custom_packet(sender_addr, destination_addr, destination_pk, route)
        }
        SecretKey::Dalek(_) => {
            let route = route_addrs
                .iter()
                .filter_map(|addr| {
                    if let Some(entry) = address_book.get(addr.as_str()) {
                        if let PublicKey::Dalek(pk) = entry.public_key {
                            Some((addr.to_string(), pk))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect();
            build_sphinx_packet(sender_addr, destination_addr, route)
        }
    };

    // Construct email
    let from: LettreMailbox = format!("{} <{}>", config.identity.name, config.identity.address)
        .parse()
        .unwrap();
    let to: LettreMailbox = format!("{} <{}>", destination_entry.name, destination_entry.address)
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

    secret_keys
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
