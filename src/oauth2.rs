use crate::deserialization::empty_string_is_none;
use oauth2::basic::BasicClient;
use oauth2::{
    AsyncHttpClient, ErrorResponse, PkceCodeVerifier, RequestTokenError, RevocationUrl,
    TokenResponse,
};
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    Scope, TokenUrl,
};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::Display;

#[derive(Deserialize, Clone, Serialize)]
pub struct OAuth2Config {
    #[serde(rename = "clientid")]
    pub client_id: String,
    #[serde(rename = "clientsecret")]
    pub client_secret: String,
    #[serde(
        rename = "accesstokenoverride",
        deserialize_with = "empty_string_is_none"
    )]
    pub access_token_override: Option<String>,
    #[serde(rename = "authurl")]
    pub auth_url: String,
    #[serde(rename = "tokenurl")]
    pub token_url: String,
    #[serde(rename = "revocationurl")]
    pub revocation_url: String,
    #[serde(rename = "redirecturl")]
    pub redirect_url: String,
}

#[derive(Debug)]
pub enum OAuth2Error {
    Parse {
        source: ::url::ParseError,
    },
    Open {
        source: std::io::Error,
    },
    RequestToken {
        source: Box<dyn Error + Send + Sync>,
    },
}

impl Error for OAuth2Error {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match *self {
            OAuth2Error::Parse { ref source } => Some(source),
            OAuth2Error::RequestToken { ref source } => Some(source.as_ref()),
            OAuth2Error::Open { ref source } => Some(source),
        }
    }
}

impl Display for OAuth2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            OAuth2Error::Parse { .. } => write!(f, "One of the provided URLs was invalid"),
            OAuth2Error::RequestToken { .. } => {
                write!(f, "Could not request the token")
            }
            OAuth2Error::Open { .. } => todo!("Could not redirect user to the browser"),
        }
    }
}

impl From<::url::ParseError> for OAuth2Error {
    fn from(value: ::url::ParseError) -> Self {
        OAuth2Error::Parse { source: value }
    }
}

impl From<std::io::Error> for OAuth2Error {
    fn from(value: std::io::Error) -> Self {
        OAuth2Error::Open { source: value }
    }
}

impl<TE> From<RequestTokenError<<oauth2::reqwest::Client as AsyncHttpClient<'_>>::Error, TE>>
    for OAuth2Error
where
    TE: ErrorResponse + Send + Sync,
{
    fn from(
        value: RequestTokenError<<oauth2::reqwest::Client as AsyncHttpClient>::Error, TE>,
    ) -> Self {
        OAuth2Error::RequestToken {
            source: Box::new(value),
        }
    }
}

pub fn begin_oauth2_flow(
    config: &OAuth2Config,
) -> Result<(PkceCodeVerifier, CsrfToken), OAuth2Error> {
    let config = config.clone();
    let client = BasicClient::new(ClientId::new(config.client_id))
        .set_client_secret(ClientSecret::new(config.client_secret))
        .set_auth_uri(AuthUrl::new(config.auth_url)?)
        .set_token_uri(TokenUrl::new(config.token_url)?)
        .set_redirect_uri(RedirectUrl::new(config.redirect_url)?)
        .set_revocation_url(RevocationUrl::new(config.revocation_url)?);

    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL.
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new(
            // "https://www.googleapis.com/auth/gmail.modify".to_string(),
            "https://mail.google.com".to_string(),
        ))
        .set_pkce_challenge(pkce_challenge)
        .url();

    open::that(auth_url.to_string())?;

    Ok((pkce_verifier, csrf_token))
}

pub async fn complete_oauth2_flow(
    config: &OAuth2Config,
    pkce_verifier: PkceCodeVerifier,
    auth_code: AuthorizationCode,
) -> Result<impl TokenResponse, OAuth2Error> {
    let config = config.clone();
    let client = BasicClient::new(ClientId::new(config.client_id))
        .set_client_secret(ClientSecret::new(config.client_secret))
        .set_auth_uri(AuthUrl::new(config.auth_url)?)
        .set_token_uri(TokenUrl::new(config.token_url)?)
        .set_redirect_uri(RedirectUrl::new(config.redirect_url)?)
        .set_revocation_url(RevocationUrl::new(config.revocation_url)?);

    let http_client = oauth2::reqwest::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(oauth2::reqwest::redirect::Policy::none())
        .build()
        .expect("Client should build");

    // Now you can trade it for an access token.
    Ok(client
        .exchange_code(auth_code)
        .set_pkce_verifier(pkce_verifier)
        .request_async(&http_client)
        .await?)
}
