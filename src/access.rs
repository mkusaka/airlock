//! Verification of Cloudflare Access JWTs (`Cf-Access-Jwt-Assertion`).

use std::time::{Duration, Instant};

use anyhow::Context;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::Value;
use tokio::sync::Mutex;

/// Minimum time between JWKS refetches triggered by an unknown `kid`.
const REFRESH_INTERVAL: Duration = Duration::from_secs(60);

pub struct Verifier {
    certs_url: String,
    validation: Validation,
    http: reqwest::Client,
    jwks: Mutex<Option<(Instant, JwkSet)>>,
}

impl Verifier {
    pub fn new(team_domain: &str, aud: &str) -> Self {
        let issuer = team_domain.trim_end_matches('/');
        let issuer = if issuer.contains("://") {
            issuer.to_owned()
        } else {
            format!("https://{issuer}")
        };
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&issuer]);
        validation.set_audience(&[aud]);
        Self {
            certs_url: format!("{issuer}/cdn-cgi/access/certs"),
            validation,
            http: reqwest::Client::new(),
            jwks: Mutex::default(),
        }
    }

    /// Verifies the token and returns the caller's identity (email, service
    /// token client id, or subject).
    pub async fn verify(&self, token: &str) -> anyhow::Result<String> {
        let kid = jsonwebtoken::decode_header(token)?
            .kid
            .context("token has no kid")?;
        let key = self.key(&kid).await?;
        let claims = jsonwebtoken::decode::<Value>(token, &key, &self.validation)?.claims;
        ["email", "common_name", "sub"]
            .iter()
            .find_map(|name| claims.get(name)?.as_str().filter(|s| !s.is_empty()))
            .map(str::to_owned)
            .context("token has no identity claim")
    }

    async fn key(&self, kid: &str) -> anyhow::Result<DecodingKey> {
        let mut jwks = self.jwks.lock().await;
        let stale = jwks.as_ref().is_none_or(|(fetched, set)| {
            set.find(kid).is_none() && fetched.elapsed() > REFRESH_INTERVAL
        });
        if stale {
            let body = self
                .http
                .get(&self.certs_url)
                .send()
                .await?
                .error_for_status()?
                .bytes()
                .await?;
            *jwks = Some((Instant::now(), serde_json::from_slice(&body)?));
        }
        let (_, set) = jwks.as_ref().context("JWKS unavailable")?;
        let jwk = set.find(kid).context("unknown kid")?;
        Ok(DecodingKey::from_jwk(jwk)?)
    }
}
