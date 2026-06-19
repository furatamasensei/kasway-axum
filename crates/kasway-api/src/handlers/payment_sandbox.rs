//! `/api/payments/sandbox/*` — PaymentSandboxController. All actions are retired
//! and return 410 Gone (the simulator was replaced by KPR-1/TN10 fixtures).

use crate::auth::AuthMerchant;
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

fn retired() -> (StatusCode, Json<Value>) {
    (
        StatusCode::GONE,
        Json(json!({
            "message": "Payment sandbox simulator has been retired. Use KPR-1 paymentRequestUri handoff, TN10 wallet submission, and controlled KPR-1/TN10 test fixtures instead.",
            "code": "PAYMENT_SANDBOX_RETIRED",
            "replacement": {
                "checkoutIntent": "/api/checkout/invoices/{publicId}/kpr1-intent",
                "walletSubmission": "/api/checkout/invoices/{publicId}/kpr1-payments",
                "operationsStatus": "/api/payments/ops/invoices/{id}",
            },
        })),
    )
}

pub async fn observations(_auth: AuthMerchant) -> (StatusCode, Json<Value>) { retired() }
pub async fn confirm(_auth: AuthMerchant) -> (StatusCode, Json<Value>) { retired() }
pub async fn underpay(_auth: AuthMerchant) -> (StatusCode, Json<Value>) { retired() }
pub async fn overpay(_auth: AuthMerchant) -> (StatusCode, Json<Value>) { retired() }
pub async fn test_event(_auth: AuthMerchant) -> (StatusCode, Json<Value>) { retired() }
