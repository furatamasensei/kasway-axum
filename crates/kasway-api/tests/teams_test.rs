mod common;

use serde_json::{json, Value};

async fn merchant(app: &common::TestApp, email: &str) -> String {
    common::register_merchant(app, email, "secret123").await
}

async fn create_team(app: &common::TestApp, token: &str, name: &str, currency_id: i64, members: Value) -> Value {
    app.client
        .post(app.url("/api/teams"))
        .bearer_auth(token)
        .json(&json!({ "name": name, "currencyId": currency_id, "teamMembers": members }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// Set a member's password and log in via the client path -> client token.
async fn login_member(app: &common::TestApp, email: &str, password: &str) -> String {
    let hash = kasway_api::password::hash_password(password);
    sqlx::query("UPDATE team_members SET password = ? WHERE email = ?")
        .bind(&hash)
        .bind(email)
        .execute(&app.db.pool)
        .await
        .unwrap();
    let res: Value = app
        .client
        .post(app.url("/api/auth/login"))
        .json(&json!({ "email": email, "password": password }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    res["token"].as_str().unwrap().to_string()
}

// --- teams ---

#[tokio::test]
async fn teams_index_requires_auth() {
    let app = common::spawn_app().await;
    let res = app.client.get(app.url("/api/teams")).send().await.unwrap();
    assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn teams_store_creates_team() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "tm1@example.com").await;
    let cur = common::seed_currency(&app.db, "USD", "US Dollar").await;

    let res = app
        .client
        .post(app.url("/api/teams"))
        .bearer_auth(&token)
        .json(&json!({
            "name": "Sales",
            "currencyId": cur,
            "teamMembers": [{ "name": "Bob", "email": "bob@example.com", "role": "manager" }]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["name"], "Sales");
    assert_eq!(body["currencyId"], cur);
    assert_eq!(body["isActive"], true);

    // member persisted
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM team_members WHERE team_id = ?")
        .bind(body["id"].as_i64().unwrap())
        .fetch_one(&app.db.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn teams_store_validation() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "tm2@example.com").await;

    // missing currencyId + no members
    let res = app
        .client
        .post(app.url("/api/teams"))
        .bearer_auth(&token)
        .json(&json!({ "name": "NoCur", "teamMembers": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);
    let body: Value = res.json().await.unwrap();
    let fields: Vec<&str> = body["errors"].as_array().unwrap().iter().map(|e| e["field"].as_str().unwrap()).collect();
    assert!(fields.contains(&"currencyId"));
    assert!(fields.contains(&"teamMembers"));
}

#[tokio::test]
async fn teams_store_duplicate_name_422() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "tm3@example.com").await;
    let cur = common::seed_currency(&app.db, "USD", "US Dollar").await;
    create_team(&app, &token, "Dup", cur, json!([{ "name": "Aa", "email": "a@x.com", "role": "staff" }])).await;

    let res = app
        .client
        .post(app.url("/api/teams"))
        .bearer_auth(&token)
        .json(&json!({ "name": "DUP", "currencyId": cur, "teamMembers": [{ "name": "Bb", "email": "b@x.com", "role": "staff" }] }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);
    assert_eq!(res.json::<Value>().await.unwrap()["errors"][0]["rule"], "database.unique");
}

#[tokio::test]
async fn teams_index_includes_currency_and_members() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "tm4@example.com").await;
    let cur = common::seed_currency(&app.db, "USD", "US Dollar").await;
    create_team(&app, &token, "Ops", cur, json!([
        { "name": "Mgr", "email": "mgr@x.com", "role": "manager" },
        { "name": "Stf", "email": "stf@x.com", "role": "staff" }
    ])).await;

    let body: Value = app.client.get(app.url("/api/teams")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(body["meta"]["total"], 1);
    let team = &body["data"][0];
    assert_eq!(team["currency"]["code"], "USD");
    let members = team["teamMembers"].as_array().unwrap();
    assert_eq!(members.len(), 2);
    // manager first
    assert_eq!(members[0]["role"], "manager");
}

#[tokio::test]
async fn teams_show_ownership_and_missing() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "tm5@example.com").await;
    let other = merchant(&app, "tm5b@example.com").await;
    let cur = common::seed_currency(&app.db, "USD", "US Dollar").await;
    let team = create_team(&app, &token, "Mine", cur, json!([{ "name": "Aa", "email": "a5@x.com", "role": "staff" }])).await;
    let id = team["id"].as_i64().unwrap();

    let own = app.client.get(app.url(&format!("/api/teams/{id}"))).bearer_auth(&token).send().await.unwrap();
    assert_eq!(own.status(), 200);
    assert!(own.json::<Value>().await.unwrap()["teamMembers"].is_array());

    let foreign = app.client.get(app.url(&format!("/api/teams/{id}"))).bearer_auth(&other).send().await.unwrap();
    assert_eq!(foreign.status(), 403);

    let missing = app.client.get(app.url("/api/teams/99999")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(missing.status(), 404);
}

#[tokio::test]
async fn teams_destroy_cascades_members() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "tm6@example.com").await;
    let cur = common::seed_currency(&app.db, "USD", "US Dollar").await;
    let team = create_team(&app, &token, "Temp", cur, json!([{ "name": "Aa", "email": "a6@x.com", "role": "staff" }])).await;
    let id = team["id"].as_i64().unwrap();

    let res = app.client.delete(app.url(&format!("/api/teams/{id}"))).bearer_auth(&token).send().await.unwrap();
    assert_eq!(res.status(), 204);

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM team_members WHERE team_id = ?").bind(id).fetch_one(&app.db.pool).await.unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn teams_add_member_and_duplicate() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "tm7@example.com").await;
    let cur = common::seed_currency(&app.db, "USD", "US Dollar").await;
    let team = create_team(&app, &token, "Grow", cur, json!([{ "name": "Aa", "email": "a7@x.com", "role": "manager" }])).await;
    let id = team["id"].as_i64().unwrap();

    let added: Value = app
        .client
        .post(app.url(&format!("/api/teams/{id}/add-member")))
        .bearer_auth(&token)
        .json(&json!({ "name": "New", "email": "new7@x.com", "role": "staff" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(added["email"], "new7@x.com");
    assert_eq!(added["role"], "staff");
    assert_eq!(added["status"], "invited");

    // duplicate email
    let dup = app
        .client
        .post(app.url(&format!("/api/teams/{id}/add-member")))
        .bearer_auth(&token)
        .json(&json!({ "name": "Dup", "email": "new7@x.com", "role": "staff" }))
        .send()
        .await
        .unwrap();
    assert_eq!(dup.status(), 422);
}

// --- team-members (merchant) ---

async fn team_with_members(app: &common::TestApp, token: &str, cur: i64) -> (i64, Vec<Value>) {
    let team = create_team(app, token, "Crew", cur, json!([
        { "name": "Mgr", "email": "crewmgr@x.com", "role": "manager" },
        { "name": "Stf", "email": "crewstf@x.com", "role": "staff" }
    ])).await;
    let id = team["id"].as_i64().unwrap();
    let shown: Value = app.client.get(app.url(&format!("/api/teams/{id}"))).bearer_auth(token).send().await.unwrap().json().await.unwrap();
    let members = shown["teamMembers"].as_array().unwrap().clone();
    (id, members)
}

#[tokio::test]
async fn team_member_payment_permissions_roundtrip() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "tm8@example.com").await;
    let cur = common::seed_currency(&app.db, "USD", "US Dollar").await;
    let (_id, members) = team_with_members(&app, &token, cur).await;
    let mid = members[0]["id"].as_i64().unwrap();

    // initially empty
    let empty: Value = app.client.get(app.url(&format!("/api/team-members/{mid}/payment-permissions"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(empty["permissions"], json!([]));

    // set with a duplicate -> normalized unique
    let set: Value = app
        .client
        .put(app.url(&format!("/api/team-members/{mid}/payment-permissions")))
        .bearer_auth(&token)
        .json(&json!({ "permissions": ["payments.ops.read", "payments.ops.read", "payments.ops.export"] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(set["permissions"], json!(["payments.ops.read", "payments.ops.export"]));

    // invalid permission -> 422
    let bad = app
        .client
        .put(app.url(&format!("/api/team-members/{mid}/payment-permissions")))
        .bearer_auth(&token)
        .json(&json!({ "permissions": ["nope"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 422);
}

#[tokio::test]
async fn team_member_activate_deactivate_destroy() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "tm9@example.com").await;
    let cur = common::seed_currency(&app.db, "USD", "US Dollar").await;
    let (_id, members) = team_with_members(&app, &token, cur).await;
    let mid = members[1]["id"].as_i64().unwrap();

    let de: Value = app.client.post(app.url(&format!("/api/team-members/{mid}/deactivate"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(de["status"], "inactive");
    let ac: Value = app.client.post(app.url(&format!("/api/team-members/{mid}/activate"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(ac["status"], "active");

    let del: Value = app.client.delete(app.url(&format!("/api/team-members/{mid}"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(del["success"], true);
}

#[tokio::test]
async fn team_member_promote_demotes_current_manager() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "tm10@example.com").await;
    let cur = common::seed_currency(&app.db, "USD", "US Dollar").await;
    let (_id, members) = team_with_members(&app, &token, cur).await;
    let manager = members.iter().find(|m| m["role"] == "manager").unwrap();
    let staff = members.iter().find(|m| m["role"] == "staff").unwrap();
    let mgr_id = manager["id"].as_i64().unwrap();
    let staff_id = staff["id"].as_i64().unwrap();

    let promoted: Value = app.client.post(app.url(&format!("/api/team-members/{staff_id}/promote"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(promoted["role"], "manager");

    // old manager demoted
    let old_role: String = sqlx::query_scalar("SELECT role FROM team_members WHERE id = ?").bind(mgr_id).fetch_one(&app.db.pool).await.unwrap();
    assert_eq!(old_role, "staff");
}

#[tokio::test]
async fn team_member_resend_invite() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "tm11@example.com").await;
    let cur = common::seed_currency(&app.db, "USD", "US Dollar").await;
    let (_id, members) = team_with_members(&app, &token, cur).await;
    let mid = members[0]["id"].as_i64().unwrap();

    let res: Value = app.client.post(app.url(&format!("/api/team-members/{mid}/resend-invite"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(res["success"], true);
}

// --- client self routes ---

#[tokio::test]
async fn team_member_client_routes() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "tm12@example.com").await;
    let cur = common::seed_currency(&app.db, "USD", "US Dollar").await;
    create_team(&app, &token, "Self", cur, json!([{ "name": "Self", "email": "self12@x.com", "role": "staff" }])).await;

    let client = login_member(&app, "self12@x.com", "memberpass").await;
    assert!(client.starts_with("tmat_"));

    // set-online
    let online = app.client.post(app.url("/api/team-members/set-online")).bearer_auth(&client).send().await.unwrap();
    assert_eq!(online.status(), 200);
    let is_online: bool = sqlx::query_scalar("SELECT is_online FROM team_members WHERE email = ?").bind("self12@x.com").fetch_one(&app.db.pool).await.unwrap();
    assert!(is_online);

    // update-profile
    let prof: Value = app
        .client
        .put(app.url("/api/team-members/update-profile"))
        .bearer_auth(&client)
        .json(&json!({ "name": "Renamed Self" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(prof["name"], "Renamed Self");

    // logout invalidates token
    let out: Value = app.client.post(app.url("/api/team-members/logout")).bearer_auth(&client).send().await.unwrap().json().await.unwrap();
    assert_eq!(out["success"], true);
    let after = app.client.post(app.url("/api/team-members/set-online")).bearer_auth(&client).send().await.unwrap();
    assert_eq!(after.status(), 401);
}

#[tokio::test]
async fn client_route_rejects_merchant_token() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "tm13@example.com").await;
    // merchant token (oat_) must not pass the client guard
    let res = app.client.post(app.url("/api/team-members/set-online")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(res.status(), 401);
}
