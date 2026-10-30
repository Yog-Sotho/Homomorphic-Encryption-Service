//! Security regression tests for `/api/v1/auth` and account management, over HTTP.

use super::auth::email::outbox;
use super::auth::session::{REFRESH_COOKIE, ROTATION_GRACE_SECS};
use super::integration_tests::TestEnv;
use crate::config::{parse_trusted_proxies, Config, RateLimitSettings};
use crate::middleware::jwt::issue_access_token;
use actix_web::cookie::{Cookie, SameSite};
use actix_web::dev::{Service, ServiceResponse};
use actix_web::http::StatusCode;
use actix_web::test::{self, TestRequest};
use serde_json::{json, Value};
use std::net::SocketAddr;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORIGIN: &str = "http://localhost:3000";
const PASSWORD: &str = "Correct-Horse-9";

trait TestApp:
    Service<actix_http::Request, Response = ServiceResponse, Error = actix_web::Error>
{
}
impl<S: Service<actix_http::Request, Response = ServiceResponse, Error = actix_web::Error>> TestApp
    for S
{
}

fn post(uri: &str, body: Value) -> TestRequest {
    TestRequest::post()
        .uri(uri)
        .insert_header(("Origin", ORIGIN))
        .set_json(body)
}

fn with_cookie(req: TestRequest, cookie: &Cookie<'static>) -> TestRequest {
    req.cookie(cookie.clone())
}

async fn call(app: &impl TestApp, req: TestRequest) -> ServiceResponse {
    test::call_service(app, req.to_request()).await
}

/// The refresh cookie a response set, if any.
fn refresh_cookie(resp: &ServiceResponse) -> Option<Cookie<'static>> {
    resp.response()
        .cookies()
        .find(|c| c.name() == REFRESH_COOKIE)
        .map(|c| c.into_owned())
}

async fn json_body(resp: ServiceResponse) -> Value {
    test::read_body_json(resp).await
}

fn location(resp: &ServiceResponse) -> String {
    resp.headers()
        .get("location")
        .expect("a redirect")
        .to_str()
        .unwrap()
        .to_string()
}

/// Registers and verifies `email`, returning the session cookie and token.
async fn signed_up(app: &impl TestApp, email: &str) -> (Cookie<'static>, String) {
    let resp = call(
        app,
        post(
            "/api/v1/auth/register",
            json!({ "email": email, "password": PASSWORD }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let token = outbox::latest_token(email);
    let resp = call(app, post("/api/v1/auth/verify", json!({ "token": token }))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let cookie = refresh_cookie(&resp).expect("session cookie");
    let body = json_body(resp).await;
    (cookie, body["token"].as_str().unwrap().to_string())
}

async fn refresh(app: &impl TestApp, cookie: &Cookie<'static>) -> ServiceResponse {
    call(
        app,
        with_cookie(post("/api/v1/auth/refresh", json!({})), cookie),
    )
    .await
}

async fn me(app: &impl TestApp, token: &str) -> StatusCode {
    let req = TestRequest::get()
        .uri("/api/v1/user/me")
        .insert_header(("Authorization", format!("Bearer {token}")));
    match test::try_call_service(app, req.to_request()).await {
        Ok(resp) => resp.status(),
        Err(e) => e.as_response_error().status_code(),
    }
}

#[actix_web::test]
async fn sessions_live_in_an_httponly_cookie_and_rotate() {
    let env = TestEnv::without_workers(|_| {}).await;
    let app = env.app().await;
    let (cookie, token) = signed_up(&app, "rotate@example.com").await;

    assert!(cookie.http_only().unwrap_or(false));
    assert!(cookie.secure().unwrap_or(false));
    assert_eq!(cookie.same_site(), Some(SameSite::Strict));
    assert_eq!(cookie.path(), Some("/api/v1/auth"));
    assert_eq!(me(&app, &token).await, StatusCode::OK);

    let resp = refresh(&app, &cookie).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let next = refresh_cookie(&resp).unwrap();
    assert_ne!(next.value(), cookie.value());
    let body = json_body(resp).await;
    assert_eq!(body["user"]["email"], "rotate@example.com");
    assert!(body.get("refresh_token").is_none(), "never in the body");
    assert_eq!(
        me(&app, body["token"].as_str().unwrap()).await,
        StatusCode::OK
    );

    // A second tab presenting the old cookie within the grace period is fine.
    assert_eq!(refresh(&app, &cookie).await.status(), StatusCode::OK);

    // After the grace period, the old cookie is a replay: the family is revoked,
    // including the successor the legitimate client holds.
    sqlx::query(
        "UPDATE refresh_tokens SET rotated_at = datetime('now', ?) WHERE rotated_at IS NOT NULL",
    )
    .bind(format!("-{} seconds", ROTATION_GRACE_SECS + 5))
    .execute(&env.pool)
    .await
    .unwrap();
    let replay = refresh(&app, &cookie).await;
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        refresh_cookie(&replay).unwrap().value(),
        "",
        "cookie cleared"
    );
    assert_eq!(
        refresh(&app, &next).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[actix_web::test]
async fn logout_ends_the_session_and_garbage_cookies_are_refused() {
    let env = TestEnv::without_workers(|_| {}).await;
    let app = env.app().await;
    let (cookie, _) = signed_up(&app, "logout@example.com").await;

    let resp = call(
        &app,
        with_cookie(post("/api/v1/auth/logout", json!({})), &cookie),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(refresh_cookie(&resp).unwrap().value(), "");
    assert_eq!(
        refresh(&app, &cookie).await.status(),
        StatusCode::UNAUTHORIZED
    );

    let forged = Cookie::new(REFRESH_COOKIE, "forged");
    assert_eq!(
        refresh(&app, &forged).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let none = call(&app, post("/api/v1/auth/refresh", json!({}))).await;
    assert_eq!(none.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn cross_origin_requests_cannot_use_the_session() {
    let env = TestEnv::without_workers(|_| {}).await;
    let app = env.app().await;
    let (cookie, _) = signed_up(&app, "csrf@example.com").await;

    let evil = TestRequest::post()
        .uri("/api/v1/auth/refresh")
        .insert_header(("Origin", "https://evil.example"))
        .cookie(cookie.clone());
    assert_eq!(call(&app, evil).await.status(), StatusCode::FORBIDDEN);
    let cross_site = TestRequest::post()
        .uri("/api/v1/auth/logout")
        .insert_header(("Sec-Fetch-Site", "cross-site"))
        .cookie(cookie.clone());
    assert_eq!(call(&app, cross_site).await.status(), StatusCode::FORBIDDEN);
    // The session survived both attempts.
    assert_eq!(refresh(&app, &cookie).await.status(), StatusCode::OK);
}

#[actix_web::test]
async fn verification_links_are_single_use_and_get_has_no_side_effect() {
    let env = TestEnv::without_workers(|_| {}).await;
    let app = env.app().await;
    let email = "verify@example.com";
    let resp = call(
        &app,
        post(
            "/api/v1/auth/register",
            json!({ "email": email, "password": PASSWORD }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let link = outbox::links_to(email).pop().unwrap();
    assert!(
        link.starts_with("http://localhost:3000/heaas/verify#token="),
        "{link}"
    );
    let token = outbox::latest_token(email);

    // Old-style links (and mail scanners prefetching them) only get redirected.
    let resp = call(
        &app,
        TestRequest::get().uri(&format!("/api/v1/auth/verify?token={token}")),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(
        location(&resp),
        format!("http://localhost:3000/heaas/verify#token={token}")
    );
    let (verified,): (bool,) = sqlx::query_as("SELECT email_verified FROM users WHERE email = ?")
        .bind(email)
        .fetch_one(&env.pool)
        .await
        .unwrap();
    assert!(!verified, "GET changed nothing");

    // Unverified accounts cannot sign in.
    let login = call(
        &app,
        post(
            "/api/v1/auth/login",
            json!({ "email": email, "password": PASSWORD }),
        ),
    )
    .await;
    assert_eq!(login.status(), StatusCode::UNAUTHORIZED);

    let first = call(&app, post("/api/v1/auth/verify", json!({ "token": token }))).await;
    assert_eq!(first.status(), StatusCode::OK);
    let again = call(&app, post("/api/v1/auth/verify", json!({ "token": token }))).await;
    assert_eq!(again.status(), StatusCode::BAD_REQUEST);

    let login = call(
        &app,
        post(
            "/api/v1/auth/login",
            json!({ "email": email, "password": PASSWORD }),
        ),
    )
    .await;
    assert_eq!(login.status(), StatusCode::OK);
    assert!(refresh_cookie(&login).is_some());
}

#[actix_web::test]
async fn expired_verification_links_are_refused() {
    let env = TestEnv::without_workers(|_| {}).await;
    let app = env.app().await;
    let email = "late@example.com";
    call(
        &app,
        post(
            "/api/v1/auth/register",
            json!({ "email": email, "password": PASSWORD }),
        ),
    )
    .await;
    sqlx::query(
        "UPDATE users SET email_verify_expires_at = datetime('now', '-1 minute') WHERE email = ?",
    )
    .bind(email)
    .execute(&env.pool)
    .await
    .unwrap();
    let resp = call(
        &app,
        post(
            "/api/v1/auth/verify",
            json!({ "token": outbox::latest_token(email) }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn password_reset_is_single_use_and_signs_out_everywhere() {
    let env = TestEnv::without_workers(|_| {}).await;
    let app = env.app().await;
    let email = "reset@example.com";
    let (cookie, _) = signed_up(&app, email).await;

    let resp = call(
        &app,
        post("/api/v1/auth/forgot-password", json!({ "email": email })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let link = outbox::links_to(email).pop().unwrap();
    assert!(
        link.starts_with("http://localhost:3000/heaas/reset#token="),
        "{link}"
    );
    let token = outbox::latest_token(email);

    let weak = call(
        &app,
        post(
            "/api/v1/auth/reset-password",
            json!({ "token": token, "new_password": "short" }),
        ),
    )
    .await;
    assert_eq!(weak.status(), StatusCode::BAD_REQUEST);
    let new_password = "Brand-New-Pass-7";
    let reset = post(
        "/api/v1/auth/reset-password",
        json!({ "token": token, "new_password": new_password }),
    );
    assert_eq!(call(&app, reset).await.status(), StatusCode::OK);
    let reuse = post(
        "/api/v1/auth/reset-password",
        json!({ "token": token, "new_password": "Another-Pass-8!" }),
    );
    assert_eq!(call(&app, reuse).await.status(), StatusCode::BAD_REQUEST);

    assert_eq!(
        refresh(&app, &cookie).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let old = call(
        &app,
        post(
            "/api/v1/auth/login",
            json!({ "email": email, "password": PASSWORD }),
        ),
    )
    .await;
    assert_eq!(old.status(), StatusCode::UNAUTHORIZED);
    let new = call(
        &app,
        post(
            "/api/v1/auth/login",
            json!({ "email": email, "password": new_password }),
        ),
    )
    .await;
    assert_eq!(new.status(), StatusCode::OK);

    // Unknown addresses get the same answer and no email.
    let unknown = call(
        &app,
        post(
            "/api/v1/auth/forgot-password",
            json!({ "email": "nobody@example.com" }),
        ),
    )
    .await;
    assert_eq!(unknown.status(), StatusCode::OK);
    assert!(outbox::links_to("nobody@example.com").is_empty());
}

fn limited(settings: RateLimitSettings) -> impl FnOnce(&mut Config) {
    move |c: &mut Config| c.rate_limits = settings
}

const GENEROUS: RateLimitSettings = RateLimitSettings {
    auth_per_minute: 10_000,
    logins_per_email: 10_000,
    emails_per_ip_per_hour: 10_000,
    emails_per_address_per_hour: 10_000,
    user_per_minute: 10_000,
};

#[actix_web::test]
async fn sign_in_attempts_are_limited_per_account() {
    let env = TestEnv::without_workers(limited(RateLimitSettings {
        logins_per_email: 3,
        ..GENEROUS
    }))
    .await;
    let app = env.app().await;
    let attempt = |email: &str| {
        post(
            "/api/v1/auth/login",
            json!({ "email": email, "password": "Wrong-Pass-1!" }),
        )
    };
    for _ in 0..3 {
        assert_eq!(
            call(&app, attempt("target@example.com")).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let blocked = call(&app, attempt("Target@Example.com ")).await;
    assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(blocked.headers().get("retry-after").is_some());
    // Other accounts are unaffected.
    assert_eq!(
        call(&app, attempt("other@example.com")).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[actix_web::test]
async fn forwarded_for_only_counts_from_trusted_proxies() {
    let env = TestEnv::without_workers(|c| {
        c.rate_limits = RateLimitSettings {
            auth_per_minute: 2,
            ..GENEROUS
        };
        c.trusted_proxies = parse_trusted_proxies("10.0.0.0/8").unwrap();
    })
    .await;
    let app = env.app().await;
    let from = |peer: &str, forwarded: &str| {
        TestRequest::get()
            .uri("/api/v1/auth/providers")
            .peer_addr(peer.parse::<SocketAddr>().unwrap())
            .insert_header(("X-Forwarded-For", forwarded))
    };

    // A direct client rotating fake X-Forwarded-For values is still one client.
    for (i, status) in [
        StatusCode::OK,
        StatusCode::OK,
        StatusCode::TOO_MANY_REQUESTS,
    ]
    .into_iter()
    .enumerate()
    {
        let resp = call(&app, from("203.0.113.5:4000", &format!("192.0.2.{i}"))).await;
        assert_eq!(resp.status(), status, "request {i}");
    }
    // Behind the trusted proxy, each real client has its own budget.
    for client in ["198.51.100.1", "198.51.100.2"] {
        for _ in 0..2 {
            let resp = call(&app, from("10.0.0.2:5000", &format!("6.6.6.6, {client}"))).await;
            assert_eq!(resp.status(), StatusCode::OK, "{client}");
        }
    }
    let resp = call(&app, from("10.0.0.2:5000", "198.51.100.1")).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[actix_web::test]
async fn email_floods_are_capped_silently_per_address() {
    let env = TestEnv::without_workers(limited(RateLimitSettings {
        emails_per_address_per_hour: 1,
        ..GENEROUS
    }))
    .await;
    let app = env.app().await;
    let email = "inbox@example.com";
    call(
        &app,
        post(
            "/api/v1/auth/register",
            json!({ "email": email, "password": PASSWORD }),
        ),
    )
    .await;
    for _ in 0..3 {
        let resp = call(
            &app,
            post(
                "/api/v1/auth/resend-verification",
                json!({ "email": email }),
            ),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "same answer whether or not mail went out"
        );
    }
    assert_eq!(outbox::links_to(email).len(), 1);
}

#[actix_web::test]
async fn email_requests_are_limited_per_client() {
    let env = TestEnv::without_workers(limited(RateLimitSettings {
        emails_per_ip_per_hour: 2,
        ..GENEROUS
    }))
    .await;
    let app = env.app().await;
    for i in 0..2 {
        let resp = call(
            &app,
            post(
                "/api/v1/auth/forgot-password",
                json!({ "email": format!("x{i}@example.com") }),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
    let resp = call(
        &app,
        post(
            "/api/v1/auth/forgot-password",
            json!({ "email": "x9@example.com" }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[actix_web::test]
async fn password_changes_end_every_session() {
    let env = TestEnv::without_workers(|_| {}).await;
    let app = env.app().await;
    let (cookie, token) = signed_up(&app, "change@example.com").await;

    let req = TestRequest::put()
        .uri("/api/v1/user/password")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(json!({ "current_password": PASSWORD, "new_password": "Changed-Pass-42" }));
    let resp = call(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(refresh_cookie(&resp).unwrap().value(), "");
    assert_eq!(
        refresh(&app, &cookie).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[actix_web::test]
async fn accounts_without_a_password_need_a_recent_sign_in_to_be_deleted() {
    let env = TestEnv::without_workers(|_| {}).await;
    let app = env.app().await;
    env.user("social").await;
    let delete = |token: String| {
        TestRequest::delete()
            .uri("/api/v1/user/account")
            .insert_header(("Authorization", format!("Bearer {token}")))
            .set_json(json!({ "password": "" }))
    };

    let an_hour_ago = chrono::Utc::now().timestamp() - 3600;
    let stale = issue_access_token("social", an_hour_ago, &env.config).unwrap();
    assert_eq!(
        call(&app, delete(stale)).await.status(),
        StatusCode::FORBIDDEN
    );

    let fresh = issue_access_token("social", chrono::Utc::now().timestamp(), &env.config).unwrap();
    let resp = call(&app, delete(fresh)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(refresh_cookie(&resp).unwrap().value(), "");
}

// ── OAuth ────────────────────────────────────────────────────────────────────

async fn oauth_env(server: &MockServer) -> TestEnv {
    let uri = server.uri();
    TestEnv::without_workers(move |c| {
        c.google_client_id = Some("google-client".into());
        c.google_client_secret = Some("google-secret".into());
        c.github_client_id = Some("github-client".into());
        c.github_client_secret = Some("github-secret".into());
        c.oauth.google_token = format!("{uri}/google/token");
        c.oauth.google_userinfo = format!("{uri}/google/userinfo");
        c.oauth.github_token = format!("{uri}/github/token");
        c.oauth.github_api = format!("{uri}/github/api");
    })
    .await
}

/// Starts sign-in; returns the state cookie and the authorize URL's query.
async fn start_oauth(app: &impl TestApp, provider: &str) -> (Cookie<'static>, url::Url) {
    let resp = call(
        app,
        TestRequest::get().uri(&format!("/api/v1/auth/{provider}")),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let cookie = resp
        .response()
        .cookies()
        .find(|c| c.name() == "heaas_oauth")
        .unwrap()
        .into_owned();
    assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    assert!(cookie.http_only().unwrap_or(false));
    (cookie, url::Url::parse(&location(&resp)).unwrap())
}

fn param(url: &url::Url, name: &str) -> String {
    url.query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
        .unwrap_or_else(|| panic!("{name} missing from {url}"))
}

async fn finish_oauth(
    app: &impl TestApp,
    provider: &str,
    cookie: &Cookie<'static>,
    state: &str,
) -> String {
    let req = TestRequest::get()
        .uri(&format!(
            "/api/v1/auth/{provider}/callback?code=the-code&state={state}"
        ))
        .cookie(cookie.clone());
    location(&call(app, req).await)
}

fn token_response() -> ResponseTemplate {
    ResponseTemplate::new(200)
        .set_body_json(json!({ "access_token": "provider-token", "token_type": "bearer" }))
}

#[actix_web::test]
async fn google_sign_in_uses_pkce_and_hands_over_a_one_time_code() {
    let server = MockServer::start().await;
    let env = oauth_env(&server).await;
    let app = env.app().await;
    let (cookie, authorize) = start_oauth(&app, "google").await;
    assert_eq!(param(&authorize, "code_challenge_method"), "S256");
    assert_eq!(
        param(&authorize, "redirect_uri"),
        "http://localhost:3000/api/v1/auth/google/callback"
    );

    // The token request must carry a verifier (checked against the challenge below).
    Mock::given(method("POST"))
        .and(path("/google/token"))
        .and(body_string_contains("code_verifier="))
        .and(body_string_contains("code=the-code"))
        .respond_with(token_response())
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/google/userinfo"))
        .and(header("authorization", "Bearer provider-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "g-42", "email": "Person@Example.com", "verified_email": true
        })))
        .mount(&server)
        .await;

    let done = finish_oauth(&app, "google", &cookie, &param(&authorize, "state")).await;
    let code = done
        .strip_prefix("http://localhost:3000/heaas/login#code=")
        .unwrap_or_else(|| panic!("unexpected redirect {done}"));
    assert!(!done.contains("token"), "no tokens in URLs");

    let verifier_sent = server.received_requests().await.unwrap()[0].body.clone();
    let form: Vec<(String, String)> = url::form_urlencoded::parse(&verifier_sent)
        .into_owned()
        .collect();
    let verifier = &form.iter().find(|(k, _)| k == "code_verifier").unwrap().1;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use sha2::{Digest, Sha256};
    assert_eq!(
        URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
        param(&authorize, "code_challenge")
    );

    let resp = call(&app, post("/api/v1/auth/exchange", json!({ "code": code }))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(refresh_cookie(&resp).is_some());
    let body = json_body(resp).await;
    assert_eq!(body["user"]["email"], "person@example.com");
    let again = call(&app, post("/api/v1/auth/exchange", json!({ "code": code }))).await;
    assert_eq!(
        again.status(),
        StatusCode::UNAUTHORIZED,
        "codes are single-use"
    );
}

#[actix_web::test]
async fn google_accounts_with_unverified_email_are_refused() {
    let server = MockServer::start().await;
    let env = oauth_env(&server).await;
    let app = env.app().await;
    Mock::given(path("/google/token"))
        .respond_with(token_response())
        .mount(&server)
        .await;
    Mock::given(path("/google/userinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "g-1", "email": "unproven@example.com", "verified_email": false
        })))
        .mount(&server)
        .await;
    let (cookie, authorize) = start_oauth(&app, "google").await;
    let done = finish_oauth(&app, "google", &cookie, &param(&authorize, "state")).await;
    assert!(done.contains("/heaas/login#error="), "{done}");
    let (users,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&env.pool)
        .await
        .unwrap();
    assert_eq!(users, 0);
}

#[actix_web::test]
async fn callbacks_without_the_matching_state_cookie_are_refused() {
    let server = MockServer::start().await;
    let env = oauth_env(&server).await;
    let app = env.app().await;
    Mock::given(path("/google/token"))
        .respond_with(token_response())
        .expect(0)
        .mount(&server)
        .await;

    let (cookie, authorize) = start_oauth(&app, "google").await;
    let state = param(&authorize, "state");
    // Wrong state, no cookie, and a cookie for another provider.
    assert!(finish_oauth(&app, "google", &cookie, "attacker-state")
        .await
        .contains("#error="));
    let no_cookie = TestRequest::get().uri(&format!(
        "/api/v1/auth/google/callback?code=c&state={state}"
    ));
    assert!(location(&call(&app, no_cookie).await).contains("#error="));
    let (github_cookie, github_authorize) = start_oauth(&app, "github").await;
    let crossed = finish_oauth(
        &app,
        "google",
        &github_cookie,
        &param(&github_authorize, "state"),
    )
    .await;
    assert!(crossed.contains("#error="));

    // Provider-supplied error text is never reflected.
    let denied = TestRequest::get().uri("/api/v1/auth/google/callback?error=Call+0800+scam");
    let redirect = location(&call(&app, denied).await);
    assert!(!redirect.contains("scam"), "{redirect}");
}

#[actix_web::test]
async fn github_sign_in_trusts_only_the_verified_primary_email() {
    let server = MockServer::start().await;
    let env = oauth_env(&server).await;
    let app = env.app().await;
    Mock::given(path("/github/token"))
        .respond_with(token_response())
        .mount(&server)
        .await;
    Mock::given(path("/github/api/user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 7, "email": "public-unverified@example.com"
        })))
        .mount(&server)
        .await;
    Mock::given(path("/github/api/user/emails"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "email": "secondary@example.com", "primary": false, "verified": true },
            { "email": "primary@example.com", "primary": true, "verified": true },
        ])))
        .mount(&server)
        .await;

    let (cookie, authorize) = start_oauth(&app, "github").await;
    let done = finish_oauth(&app, "github", &cookie, &param(&authorize, "state")).await;
    let code = done.split_once("#code=").expect("signed in").1;
    let resp = call(&app, post("/api/v1/auth/exchange", json!({ "code": code }))).await;
    assert_eq!(
        json_body(resp).await["user"]["email"],
        "primary@example.com"
    );
}

#[actix_web::test]
async fn github_accounts_without_a_verified_primary_email_are_refused() {
    let server = MockServer::start().await;
    let env = oauth_env(&server).await;
    let app = env.app().await;
    Mock::given(path("/github/token"))
        .respond_with(token_response())
        .mount(&server)
        .await;
    Mock::given(path("/github/api/user"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "id": 8, "email": "x@example.com" })),
        )
        .mount(&server)
        .await;
    Mock::given(path("/github/api/user/emails"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "email": "x@example.com", "primary": true, "verified": false },
        ])))
        .mount(&server)
        .await;
    let (cookie, authorize) = start_oauth(&app, "github").await;
    let done = finish_oauth(&app, "github", &cookie, &param(&authorize, "state")).await;
    assert!(done.contains("#error="), "{done}");
}

#[actix_web::test]
async fn provider_errors_fail_cleanly() {
    let server = MockServer::start().await;
    let env = oauth_env(&server).await;
    let app = env.app().await;
    Mock::given(path("/google/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({ "error": "invalid_grant" })))
        .mount(&server)
        .await;
    let (cookie, authorize) = start_oauth(&app, "google").await;
    let done = finish_oauth(&app, "google", &cookie, &param(&authorize, "state")).await;
    assert!(done.contains("#error="), "{done}");

    let providers: Value =
        json_body(call(&app, TestRequest::get().uri("/api/v1/auth/providers")).await).await;
    assert_eq!(providers, json!({ "google": true, "github": true }));
}
