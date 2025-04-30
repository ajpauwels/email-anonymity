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
use sodiumoxide::crypto::box_::{self, Nonce, PublicKey, SecretKey};
use surb::{Link, SingleUseReplyBlock};
use tiny_http::{Response, Server};
use tokio::time::sleep;
use url::Url;

mod deserialization;
use deserialization::{
    as_base64, string_is_duration_option, string_is_ecc_public_key,
    string_is_ecc_secret_key_option, string_is_nonce,
};
mod oauth2;
use oauth2::OAuth2Config;
mod constant_size;
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

#[derive(Deserialize)]
struct SecretIdentityConfig {
    address: String,
    name: String,
    #[serde(
        rename = "secretkey",
        deserialize_with = "string_is_ecc_secret_key_option"
    )]
    secret_key: Option<SecretKey>,
}

#[derive(Deserialize)]
struct PublicIdentityConfig {
    address: String,
    name: String,
    #[serde(rename = "publickey", deserialize_with = "string_is_ecc_public_key")]
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
    ephemeral_key: PublicKey,
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

#[tokio::main]
async fn main() {
    // Get app config
    let config_path = "./config";
    let config = load_config(config_path, "APPCFG").unwrap();

    // Generate keys if they don't exist
    let (pk, sk) = box_::gen_keypair();
    let sk = match config.identity.secret_key {
        Some(ref sk) => sk,
        None => {
            println!(
                "Generated secret key: {}",
                BASE64_STANDARD.encode(sk.as_ref()),
            );
            println!(
                "Generated public key: {}",
                BASE64_STANDARD.encode(pk.as_ref()),
            );
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

            //println!("{:?}", imap_session.list(None, Some("*")).unwrap());
            // for c in imap_session.capabilities().unwrap().iter() {
            //     println!("{:?}", c);
            // }

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
                                let sm_encrypted =
                                    BASE64_STANDARD.decode(&sm_wrapped.message).unwrap();
                                let sm_decrypted = box_::open(
                                    &sm_encrypted,
                                    &sm_wrapped.nonce,
                                    &sm_wrapped.ephemeral_key,
                                    &sk,
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
                            } else if let Ok(surb) =
                                serde_yaml::from_slice::<SingleUseReplyBlock>(&body)
                            {
                                println!("Message is a SURB that needs to be either forwarded or the payload unraveled locally");
                                let msg = surb
                                    .process(
                                        email_address.clone(),
                                        None,
                                        &sk,
                                        &secret_keys,
                                        &mailer,
                                    )
                                    .unwrap();
                                if let Some(msg) = msg {
                                    println!("SURB response: {}", msg);
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

fn send_email(
    config: &ShallotConfig,
    address_book: &HashMap<String, &PublicIdentityConfig>,
    sk: &SecretKey,
    mailer: &SmtpTransport,
) -> Vec<SecretKey> {
    // Layer 0
    let surb_link0 = &address_book.get("johncamacuk@yahoo.com").unwrap();
    let surb_links = vec![Link {
        address: surb_link0.address.clone(),
        public_key: surb_link0.public_key,
    }];
    let (surb, secret_keys) = SingleUseReplyBlock::new(
        &Link {
            address: config.identity.address.clone(),
            public_key: sk.public_key(),
        },
        surb_links.as_slice(),
        None,
    )
    .unwrap();
    // let surb_string_b64 = BASE64_STANDARD.encode(serde_yaml::to_string(&surb).unwrap());
    let plain_string_b64 = BASE64_STANDARD.encode("XATTACKXATXDAWNX");
    let sm0 = ShallotMessage {
        header: None,
        body: plain_string_b64,
        // body: surb_string_b64,
    };
    let (sm0_pk, sm0_sk) = box_::gen_keypair();
    let sm0_nonce = box_::gen_nonce();
    let sm0_string = serde_yaml::to_string(&sm0).unwrap();
    let sm0_recipient = &address_book.get("johncamacuk@gmail.com").unwrap();
    let sm0_encrypted = box_::seal(
        sm0_string.as_bytes(),
        &sm0_nonce,
        &sm0_recipient.public_key,
        &sm0_sk,
    );
    let sm0_encrypted_b64 = BASE64_STANDARD.encode(&sm0_encrypted);
    let sm0_wrapped = ShallotMessageWrapper {
        ephemeral_key: sm0_pk,
        nonce: sm0_nonce,
        message: sm0_encrypted_b64,
    };
    let sm0_wrapped_string = serde_yaml::to_string(&sm0_wrapped).unwrap();
    let sm0_wrapped_b64 = BASE64_STANDARD.encode(&sm0_wrapped_string);

    // Layer 1
    let sm1 = ShallotMessage {
        header: Some(ShallotHeader {
            next: "johncamacuk@gmail.com".to_string(),
        }),
        body: sm0_wrapped_b64,
    };
    let (sm1_pk, sm1_sk) = box_::gen_keypair();
    let sm1_nonce = box_::gen_nonce();
    let sm1_string = serde_yaml::to_string(&sm1).unwrap();
    let sm1_recipient = &address_book.get("johncamacuk@yahoo.com").unwrap();
    let sm1_encrypted = box_::seal(
        sm1_string.as_bytes(),
        &sm1_nonce,
        &sm1_recipient.public_key,
        &sm1_sk,
    );
    let sm1_encrypted_b64 = BASE64_STANDARD.encode(&sm1_encrypted);
    let sm1_wrapped = ShallotMessageWrapper {
        ephemeral_key: sm1_pk,
        nonce: sm1_nonce,
        message: sm1_encrypted_b64,
    };
    let sm1_wrapped_string = serde_yaml::to_string(&sm1_wrapped).unwrap();
    let sm1_wrapped_b64 = BASE64_STANDARD.encode(&sm1_wrapped_string);

    // Construct email
    let from: LettreMailbox = format!("{} <{}>", config.identity.name, config.identity.address)
        .parse()
        .unwrap();
    let to: LettreMailbox = format!("{} <{}>", sm1_recipient.name, sm1_recipient.address)
        .parse()
        .unwrap();
    let email = LettreMessage::builder()
        .from(from.clone())
        .to(to.clone())
        .subject("shallot")
        .header(LettreContentType::TEXT_PLAIN)
        .body(sm1_wrapped_b64)
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
