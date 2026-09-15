//! Masked-secret injection: surrogate → real in request headers, real →
//! surrogate in response headers, ordered around Lua middleware.

use axum::Router;
use axum::routing::get;

use super::helpers::*;
use crate::project::MaskedSecret;

const REAL: &str = "sk-real-token-0123456789";
const SURROGATE: &str = "SURROGATEabcdef0123456789";

fn token() -> MaskedSecret {
    MaskedSecret {
        name: "TOKEN".into(),
        real: REAL.into(),
        surrogate: SURROGATE.into(),
    }
}

fn get_with_auth(port: u16, path: &str, auth: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {auth}\r\nConnection: close\r\n\r\n"
    )
}

/// Upstream that echoes the `authorization` header it received in the body
/// and mirrors it into an `x-echo` response header.
fn echo_router() -> Router {
    Router::new().route(
        "/",
        get(|headers: axum::http::HeaderMap| async move {
            let auth = headers
                .get("authorization")
                .map_or("missing".to_string(), |v| v.to_str().unwrap().to_string());
            ([("x-echo", auth.clone())], auth)
        }),
    )
}

#[test]
fn request_header_surrogate_is_replaced_with_real_value() {
    run_with_config(
        TestNetworkConfig {
            inject: vec![token()],
            ..Default::default()
        },
        |proxy, _log, _ca| async move {
            let addr = serve(echo_router()).await;
            let mut conn = TestConnection::connect(&proxy, "127.0.0.1", addr.port())
                .await
                .unwrap();
            let resp = conn
                .roundtrip(&get_with_auth(addr.port(), "/", SURROGATE))
                .await;
            // Body carries what the upstream saw: the real token.
            let (_, body) = resp.split_once("\r\n\r\n").unwrap();
            assert_eq!(body, format!("Bearer {REAL}"), "upstream saw: {resp}");
        },
    );
}

#[test]
fn response_header_real_value_is_masked_back() {
    run_with_config(
        TestNetworkConfig {
            inject: vec![token()],
            ..Default::default()
        },
        |proxy, _log, _ca| async move {
            let addr = serve(echo_router()).await;
            let mut conn = TestConnection::connect(&proxy, "127.0.0.1", addr.port())
                .await
                .unwrap();
            let resp = conn
                .roundtrip(&get_with_auth(addr.port(), "/", SURROGATE))
                .await;
            let (head, _) = resp.split_once("\r\n\r\n").unwrap();
            assert!(
                head.contains(&format!("x-echo: Bearer {SURROGATE}")),
                "response header should carry the surrogate: {head}"
            );
            assert!(
                !head.contains(REAL),
                "real value leaked into response headers: {head}"
            );
        },
    );
}

#[test]
fn middleware_observes_real_request_value() {
    run_with_config(
        TestNetworkConfig {
            inject: vec![token()],
            middleware_scripts: vec![("log auth", r#"log(req:header("authorization"))"#)],
            ..Default::default()
        },
        |proxy, log, _ca| async move {
            let addr = serve(echo_router()).await;
            let mut conn = TestConnection::connect(&proxy, "127.0.0.1", addr.port())
                .await
                .unwrap();
            let resp = conn
                .roundtrip(&get_with_auth(addr.port(), "/", SURROGATE))
                .await;
            assert!(resp.contains("200"), "expected 200: {resp}");
            assert_eq!(log.messages(), vec![format!("Bearer {REAL}")]);
        },
    );
}

#[test]
fn middleware_response_header_with_real_value_is_masked() {
    run_with_config(
        TestNetworkConfig {
            inject: vec![token()],
            middleware_scripts: vec![(
                "set real",
                r#"
                local auth = req:header("authorization")
                local res = req:send()
                res:setHeader("x-from-lua", "leak " .. auth)
                "#,
            )],
            ..Default::default()
        },
        |proxy, _log, _ca| async move {
            let addr = serve(echo_router()).await;
            let mut conn = TestConnection::connect(&proxy, "127.0.0.1", addr.port())
                .await
                .unwrap();
            let resp = conn
                .roundtrip(&get_with_auth(addr.port(), "/", SURROGATE))
                .await;
            let (head, _) = resp.split_once("\r\n\r\n").unwrap();
            assert!(
                head.contains(&format!("x-from-lua: leak Bearer {SURROGATE}")),
                "lua-set header should be masked: {head}"
            );
            assert!(!head.contains(REAL), "real value leaked: {head}");
        },
    );
}

#[test]
fn middleware_error_body_is_masked() {
    run_with_config(
        TestNetworkConfig {
            inject: vec![token()],
            middleware_scripts: vec![(
                "fail with header",
                r#"error("bad auth: " .. req:header("authorization"))"#,
            )],
            ..Default::default()
        },
        |proxy, _log, _ca| async move {
            let addr = serve(echo_router()).await;
            let mut conn = TestConnection::connect(&proxy, "127.0.0.1", addr.port())
                .await
                .unwrap();
            let resp = conn
                .roundtrip(&get_with_auth(addr.port(), "/", SURROGATE))
                .await;
            assert!(resp.contains("502"), "expected 502: {resp}");
            assert!(resp.contains("bad auth"), "expected the error text: {resp}");
            assert!(
                !resp.contains(REAL),
                "real value leaked in 502 body: {resp}"
            );
            assert!(
                resp.contains(SURROGATE),
                "expected surrogate in body: {resp}"
            );
        },
    );
}

#[test]
fn allowed_host_without_inject_leaves_surrogate_untouched() {
    run_with_config(
        TestNetworkConfig {
            // The inject rule covers nothing reachable; a plain rule allows
            // the upstream. The surrogate must pass through unchanged.
            allowed_hosts: vec!["nowhere.example.com".into()],
            plain_allowed_hosts: vec!["127.0.0.1".into()],
            inject: vec![token()],
            ..Default::default()
        },
        |proxy, _log, _ca| async move {
            let addr = serve(echo_router()).await;
            let mut conn = TestConnection::connect(&proxy, "127.0.0.1", addr.port())
                .await
                .unwrap();
            let resp = conn
                .roundtrip(&get_with_auth(addr.port(), "/", SURROGATE))
                .await;
            let (_, body) = resp.split_once("\r\n\r\n").unwrap();
            assert_eq!(body, format!("Bearer {SURROGATE}"), "got: {resp}");
        },
    );
}

#[test]
fn resolve_target_attaches_secrets_only_to_inject_rules() {
    let (_log, _ca, network) = build_network(TestNetworkConfig {
        allowed_hosts: vec!["api.example.com:443".into()],
        plain_allowed_hosts: vec!["plain.example.com".into()],
        inject: vec![token()],
        ..Default::default()
    });
    let t = network.resolve_target("api.example.com", 443);
    assert!(t.allowed);
    assert_eq!(t.secrets.len(), 1);
    assert_eq!(t.secrets[0].name, "TOKEN");

    let t = network.resolve_target("plain.example.com", 443);
    assert!(t.allowed);
    assert!(t.secrets.is_empty());

    let t = network.resolve_target("api.example.com", 80);
    assert!(!t.allowed);
    assert!(t.secrets.is_empty());
}
