//! Shared application state injected into every handler.

use crate::util::{decode_hex32, http_client};
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
    pub covenant: CovenantConfig,
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
            default_network: "tn10".to_string(),
            default_asset: "KAS".to_string(),
            app_url: "https://app.kasway.test".to_string(),
            app_name: "Kasway Merchant".to_string(),
        }
    }
}

/// Covenant settlement config (env: COVENANT_*). Covenant is the sole settlement
/// path; these tune the refund window and the keeper that spends covenants.
#[derive(Clone, Debug)]
pub struct CovenantConfig {
    /// Dispute/capture window in seconds from mint. After this, an unresolved
    /// covenant auto-captures to the merchant (`release_captured`).
    pub capture_window_secs: i64,
    /// Miner fee per settlement transaction (sompi), paid from the fee input —
    /// never from the covenant value. Measured on TN10: a covenant settlement's
    /// compute mass (~10k, driven by the committed compute budgets) requires
    /// ~1_034_600 sompi at ~100 sompi/gram, so this defaults well above a plain
    /// tx's dust fee. Large splits (many payout outputs) add size mass; tune
    /// `COVENANT_KEEPER_MIN_FEE_SOMPI` up if a big split is ever rejected for fee.
    pub keeper_min_fee_sompi: u64,
    /// Keeper fee-source secret key (hex, 32 bytes). Signs ONLY the keeper's fee
    /// input for merchant captures. `None` disables the auto-capture keeper.
    pub keeper_fee_secret_hex: Option<String>,
    /// Kasway ARBITER secret key (hex, 32 bytes). Used only in the transitional
    /// 1-of-1 panel (see `arbiter_panel_hex`): if no independent panel is
    /// configured, the covenant's arbiter panel is `[this pubkey]` with threshold
    /// 1, and the secret signs dispute rulings server-side. Configure a real
    /// `arbiter_panel_hex` to take Kasway out of the decider seat.
    pub arbiter_secret_hex: Option<String>,
    /// EscrowV2 M-of-N arbiter PANEL: independent arbiter x-only pubkeys (32-byte
    /// hex), consented to at funding. When empty, the covenant falls back to a
    /// 1-of-1 panel = `[arbiter_secret's pubkey]` (behaviour-preserving during
    /// migration). Kasway's key SHOULD NOT be in a real panel.
    pub arbiter_panel_hex: Vec<String>,
    /// M in the M-of-N arbiter threshold. Clamped to `1..=panel.len()`.
    pub arbiter_threshold: u32,
}

impl Default for CovenantConfig {
    fn default() -> Self {
        Self {
            capture_window_secs: 1800,
            keeper_min_fee_sompi: 2_000_000,
            keeper_fee_secret_hex: None,
            arbiter_secret_hex: None,
            arbiter_panel_hex: Vec::new(),
            arbiter_threshold: 1,
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
        let mut covenant = CovenantConfig::default();
        if let Ok(v) = std::env::var("COVENANT_CAPTURE_WINDOW_SECS") {
            if let Ok(n) = v.parse() { covenant.capture_window_secs = n; }
        }
        if let Ok(v) = std::env::var("COVENANT_KEEPER_MIN_FEE_SOMPI") {
            if let Ok(n) = v.parse() { covenant.keeper_min_fee_sompi = n; }
        }
        covenant.keeper_fee_secret_hex = std::env::var("COVENANT_KEEPER_FEE_SECRET").ok().filter(|s| !s.is_empty());
        covenant.arbiter_secret_hex = std::env::var("COVENANT_ARBITER_SECRET").ok().filter(|s| !s.is_empty());
        // Comma-separated 32-byte pubkey hex list for the M-of-N arbiter panel.
        covenant.arbiter_panel_hex = std::env::var("COVENANT_ARBITER_PANEL")
            .ok()
            .map(|s| s.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect())
            .unwrap_or_default();
        if let Ok(v) = std::env::var("COVENANT_ARBITER_THRESHOLD") {
            if let Ok(n) = v.parse() { covenant.arbiter_threshold = n; }
        }
        let mut google = GoogleConfig::default();
        if let Ok(v) = std::env::var("GOOGLE_CLIENT_ID") { google.client_id = v; }
        if let Ok(v) = std::env::var("GOOGLE_CLIENT_SECRET") { google.client_secret = v; }
        if let Ok(v) = std::env::var("APP_URL") { if !v.is_empty() { google.app_url = v; } }
        if let Ok(v) = std::env::var("FRONTEND_URL") { if !v.is_empty() { google.frontend_url = v; } }

        let node_env = std::env::var("NODE_ENV").unwrap_or_else(|_| "development".to_string());

        // KPR-1 signing seed / key id: override the source-visible defaults from
        // env. `signing_seed` must be 64-char hex → [u8; 32].
        let seed_set = match std::env::var("KPR1_SIGNING_SEED").ok().filter(|s| !s.is_empty()) {
            Some(hex) => match decode_hex32(hex.trim()) {
                Some(seed) => { kpr1.signing_seed = seed; true }
                None => false,
            },
            None => false,
        };
        if let Ok(v) = std::env::var("KPR1_SIGNING_KEY_ID") {
            if !v.is_empty() { kpr1.signing_key_id = v; }
        }

        // Fail closed at startup: production must not run with the source-visible
        // default signing seed or the placeholder platform fee address.
        if node_env == "production" {
            if !seed_set {
                panic!(
                    "KPR1_SIGNING_SEED must be set to a valid 64-char hex value in production; \
                     refusing to start with the source-visible default seed"
                );
            }
            let fee_addr = kpr1.platform_fee_address.trim();
            if fee_addr.is_empty() || fee_addr == "kaspatest:platformfeeaddr00000" {
                panic!(
                    "KASWAY_PLATFORM_FEE_ADDRESS must be set to a real address in production; \
                     refusing to start with the placeholder fee address"
                );
            }
        }

        Self {
            internal_api_token: std::env::var("INTERNAL_API_TOKEN").ok().filter(|s| !s.is_empty()),
            turnstile_secret: std::env::var("TURNSTILE_SECRET").ok().filter(|s| !s.is_empty()),
            node_env,
            kpr1,
            covenant,
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
            covenant: CovenantConfig::default(),
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
        let resp = match http_client()
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
