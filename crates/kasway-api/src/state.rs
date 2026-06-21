//! Shared application state injected into every handler.

use kasway_db::Db;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub config: Arc<AppConfig>,
}

#[derive(Clone, Debug)]
pub struct AppConfig {
    /// Token required by `internalApiToken()` routes. When `None`, those routes
    /// reply 503 — matching `internal_api_token_middleware.ts`.
    pub internal_api_token: Option<String>,
    /// Cloudflare Turnstile secret. When unset and not production, captcha
    /// validation is bypassed (see `captcha_service.ts`).
    pub turnstile_secret: Option<String>,
    pub node_env: String,
    pub kpr1: Kpr1Config,
    pub google: GoogleConfig,
    /// CoinGecko simple-price base URL (overridable for tests). PricesController.
    pub price_api_url: String,
}

/// Google OAuth (auth_controller redirectGoogle/callbackGoogle via @adonisjs/ally).
/// Endpoint URLs are overridable so tests can point at a local mock.
#[derive(Clone, Debug)]
pub struct GoogleConfig {
    pub client_id: String,
    pub client_secret: String,
    pub app_url: String,
    pub frontend_url: String,
    pub authorize_url: String,
    pub token_url: String,
    pub userinfo_url: String,
}

impl Default for GoogleConfig {
    fn default() -> Self {
        Self {
            client_id: String::new(),
            client_secret: String::new(),
            app_url: "https://app.kasway.test".to_string(),
            frontend_url: "https://kasway.test".to_string(),
            authorize_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            userinfo_url: "https://www.googleapis.com/oauth2/v3/userinfo".to_string(),
        }
    }
}

/// KPR-1 intent minter config (env: KASWAY_PLATFORM_FEE_*, KPR1_*).
#[derive(Clone, Debug)]
pub struct Kpr1Config {
    pub enabled: bool,
    pub platform_fee_bps: i64,
    pub platform_fee_flat_sompi: i64,
    pub platform_fee_address: String,
    pub signing_key_id: String,
    /// 32-byte ed25519 seed (hex). Fixed default keeps signatures deterministic.
    pub signing_seed: [u8; 32],
    /// Global default payment mode: "address" (legacy multi-output) or "covenant".
    pub payment_mode: String,
    pub default_network: String,
    pub default_asset: String,
    pub app_url: String,
    pub app_name: String,
}

impl Default for Kpr1Config {
    fn default() -> Self {
        Self {
            enabled: true,
            platform_fee_bps: 100,
            platform_fee_flat_sompi: 0,
            platform_fee_address: "kaspatest:platformfeeaddr00000".to_string(),
            signing_key_id: "kpr1-key-1".to_string(),
            signing_seed: [7u8; 32],
            payment_mode: "address".to_string(),
            default_network: "tn10".to_string(),
            default_asset: "KAS".to_string(),
            app_url: "https://app.kasway.test".to_string(),
            app_name: "Kasway Merchant".to_string(),
        }
    }
}

impl AppConfig {
    pub fn from_env() -> Self {
        let mut kpr1 = Kpr1Config::default();
        if let Ok(v) = std::env::var("KASWAY_PLATFORM_FEE_BPS") {
            if let Ok(n) = v.parse() {
                kpr1.platform_fee_bps = n;
            }
        }
        if let Ok(v) = std::env::var("KASWAY_PLATFORM_FEE_FLAT_SOMPI") {
            if let Ok(n) = v.parse() {
                kpr1.platform_fee_flat_sompi = n;
            }
        }
        if let Ok(v) = std::env::var("KASWAY_PLATFORM_FEE_ADDRESS") {
            if !v.is_empty() {
                kpr1.platform_fee_address = v;
            }
        }
        if let Ok(v) = std::env::var("KPR1_COVENANT_PAYMENT_MODE") {
            if !v.is_empty() {
                kpr1.payment_mode = v;
            }
        }
        if let Ok(v) = std::env::var("APP_URL") {
            if !v.is_empty() {
                kpr1.app_url = v;
            }
        }
        if let Ok(v) = std::env::var("APP_NAME") {
            if !v.is_empty() {
                kpr1.app_name = v;
            }
        }
        let mut google = GoogleConfig::default();
        if let Ok(v) = std::env::var("GOOGLE_CLIENT_ID") { google.client_id = v; }
        if let Ok(v) = std::env::var("GOOGLE_CLIENT_SECRET") { google.client_secret = v; }
        if let Ok(v) = std::env::var("APP_URL") { if !v.is_empty() { google.app_url = v; } }
        if let Ok(v) = std::env::var("FRONTEND_URL") { if !v.is_empty() { google.frontend_url = v; } }
        Self {
            internal_api_token: std::env::var("INTERNAL_API_TOKEN").ok().filter(|s| !s.is_empty()),
            turnstile_secret: std::env::var("TURNSTILE_SECRET").ok().filter(|s| !s.is_empty()),
            node_env: std::env::var("NODE_ENV").unwrap_or_else(|_| "development".to_string()),
            kpr1,
            google,
            price_api_url: std::env::var("PRICE_API_URL").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "https://api.coingecko.com/api/v3/simple/price".to_string()),
        }
    }

    /// Default config for tests (captcha bypass, KPR-1 enabled with defaults).
    pub fn test_default() -> Self {
        Self {
            internal_api_token: None,
            turnstile_secret: None,
            node_env: "test".to_string(),
            kpr1: Kpr1Config::default(),
            google: GoogleConfig::default(),
            price_api_url: "https://api.coingecko.com/api/v3/simple/price".to_string(),
        }
    }

    /// Replicates `CaptchaService.validateTurnstile`. Returns true when captcha
    /// is satisfied. When no secret is configured the check is bypassed outside
    /// production (dev/test behavior). When a secret is set, the token is
    /// verified against Cloudflare's Turnstile siteverify endpoint; any failure
    /// (missing token, network error, non-success response) fails closed.
    pub async fn captcha_ok(&self, token: Option<&str>, remote_ip: Option<&str>) -> bool {
        // No secret configured: bypass outside production, fail closed in prod.
        let Some(secret) = self.turnstile_secret.as_deref() else {
            return self.node_env != "production";
        };
        // Secret configured: a non-empty token is mandatory.
        let Some(token) = token.filter(|t| !t.is_empty()) else {
            return false;
        };

        // POST secret/response (+ optional remoteip) to Cloudflare siteverify.
        let mut form: Vec<(&str, &str)> = vec![("secret", secret), ("response", token)];
        if let Some(ip) = remote_ip.filter(|s| !s.is_empty()) {
            form.push(("remoteip", ip));
        }
        let resp = match reqwest::Client::new()
            .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
            .form(&form)
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => return false, // network error -> fail closed
        };
        match resp.json::<serde_json::Value>().await {
            Ok(body) => body.get("success").and_then(|v| v.as_bool()).unwrap_or(false),
            Err(_) => false,
        }
    }
}
