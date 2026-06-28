use anyhow::{Context, Result};
use axum::{
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

use crate::{
    allowlist,
    audit::{AuditEvent, AuditLog, EventType},
    config::ProjectConfig,
    identity,
    session::SharedSession,
};

// ── State ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ProxyState {
    pub session: SharedSession,
    pub audit: Arc<AuditLog>,
    pub config: Arc<ProjectConfig>,
}

// ── Router ─────────────────────────────────────────────────────────────────

/// Build the axum Router. In production, call
/// `build_router(state).into_make_service_with_connect_info::<SocketAddr>()`
/// so that `ConnectInfo<SocketAddr>` is populated in handlers.
///
/// In tests, layer `MockConnectInfo(addr)` onto the router before `oneshot`.
pub fn build_router(state: ProxyState) -> Router {
    Router::new()
        .route("/status", get(handle_status))
        .route("/secrets", get(handle_list))
        .route("/secret/:name", get(handle_get_secret))
        .with_state(state)
}

/// Bind to 127.0.0.1:52731 and serve until the returned future is awaited.
/// Uses graceful-shutdown: pass in a `shutdown` future (e.g. ctrl-c signal).
pub async fn run_proxy(state: ProxyState, shutdown: impl std::future::Future<Output = ()> + Send + 'static) -> Result<()> {
    let addr: SocketAddr = "127.0.0.1:52731"
        .parse()
        .context("parsing proxy bind address")?;

    let app = build_router(state).into_make_service_with_connect_info::<SocketAddr>();
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding proxy to {addr}"))?;

    tracing::info!("MeVault proxy listening on {addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .context("running proxy server")?;

    Ok(())
}

// ── Handlers ───────────────────────────────────────────────────────────────

async fn handle_status(State(state): State<ProxyState>) -> Json<Value> {
    let lock = state.session.read().await;
    match lock.as_ref() {
        None => Json(json!({ "status": "locked" })),
        Some(s) if !s.is_active() => Json(json!({ "status": "expired" })),
        Some(s) => Json(json!({
            "status": "active",
            "vault": s.vault_name,
            "session_id": s.id.to_string(),
            "expires_at": s.expires_at.map(|e| e.to_rfc3339()),
            "secret_count": s.secret_names().len(),
        })),
    }
}

async fn handle_list(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<ProxyState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let lock = state.session.read().await;
    let session = require_active_session(&lock)?;

    if state.config.security.require_identity_check {
        resolve_and_check(peer, "", &state.config, &session.project_root).await?;
    }

    let names = session.secret_names();
    Ok(Json(json!({ "secrets": names })))
}

async fn handle_get_secret(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(name): Path<String>,
    State(state): State<ProxyState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let lock = state.session.read().await;
    let session = require_active_session(&lock)?;

    let allowed = if state.config.security.require_identity_check {
        // Map identity + allow-list errors to explicit denial (never allow on error).
        match resolve_and_check(peer, &name, &state.config, &session.project_root).await {
            Ok(()) => true,
            Err(_) => false,
        }
    } else {
        true
    };

    if !allowed {
        let event = AuditEvent::new(EventType::Denied)
            .secret(&name)
            .vault(&session.vault_name)
            .session(session.id.to_string())
            .reason("allow_list_denied");
        let audit = Arc::clone(&state.audit);
        tokio::spawn(async move {
            if let Err(e) = audit.write(event).await {
                tracing::warn!("audit write failed: {e}");
            }
        });
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "access_denied" })),
        ));
    }

    let value = session.get_secret(&name).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "secret_not_found", "name": name })),
        )
    })?;

    use secrecy::ExposeSecret;
    let event = AuditEvent::new(EventType::Allowed)
        .secret(&name)
        .vault(&session.vault_name)
        .session(session.id.to_string());

    let audit = Arc::clone(&state.audit);
    tokio::spawn(async move {
        if let Err(e) = audit.write(event).await {
            tracing::warn!("audit write failed: {e}");
        }
    });

    Ok(Json(json!({
        "name": name,
        "value": value.expose_secret(),
    })))
}

// ── Identity helpers ────────────────────────────────────────────────────────

async fn resolve_and_check(
    peer: SocketAddr,
    secret_name: &str,
    config: &ProjectConfig,
    project_root: &std::path::Path,
) -> Result<(), (StatusCode, Json<Value>)> {
    let local_port: u16 = 52731;
    let remote_port = peer.port();

    let pid = identity::find_connection_pid(local_port, remote_port).map_err(|e| {
        tracing::warn!("find_connection_pid failed: {e}");
        (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "caller_identity_unknown" })),
        )
    })?;

    let chain = identity::build_process_chain(pid).map_err(|e| {
        tracing::warn!("build_process_chain({pid}) failed: {e}");
        (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "caller_identity_unknown" })),
        )
    })?;

    let decision = allowlist::check_access(&chain, secret_name, config, project_root);
    if !decision.is_allowed() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "access_denied",
                "reason": decision.reason(),
            })),
        ));
    }

    Ok(())
}

// ── Auth helper ─────────────────────────────────────────────────────────────

fn require_active_session<'a>(
    lock: &'a tokio::sync::RwLockReadGuard<'a, Option<crate::session::Session>>,
) -> Result<&'a crate::session::Session, (StatusCode, Json<Value>)> {
    let session = lock.as_ref().ok_or_else(|| {
        (StatusCode::UNAUTHORIZED, Json(json!({ "error": "vault_locked" })))
    })?;
    if !session.is_active() {
        return Err((StatusCode::UNAUTHORIZED, Json(json!({ "error": "session_expired" }))));
    }
    Ok(session)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        audit::AuditLog,
        config::{
            AllowListConfig, DenyListConfig, ExpiryMode, ProjectConfig, ProjectMeta,
            SecurityConfig, SessionConfig, UnknownProcessMode,
        },
        crypto::CryptoPolicy,
        session::{Session, SessionManager},
        vault::VaultStore,
    };
    use axum::body::to_bytes;
    use axum::extract::connect_info::MockConnectInfo;
    use axum::http::Request;
    use secrecy::SecretString;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// A config with identity checking disabled so tests don't need real TCP connections.
    fn test_config() -> Arc<ProjectConfig> {
        Arc::new(ProjectConfig {
            project: ProjectMeta {
                name: "Test".into(),
                vault_name: "Test".into(),
                created_at: chrono::Utc::now().to_rfc3339(),
            },
            session: SessionConfig {
                expiry_mode: ExpiryMode::Both,
                expiry_hours: 8,
            },
            security: SecurityConfig {
                unknown_process_mode: UnknownProcessMode::DenyAndLog,
                require_identity_check: false, // skip Win32 in tests
                require_signature_check: false,
                require_parent_check: true,
                require_working_dir_check: false,
            },
            allow_list: AllowListConfig { rules: vec![] },
            deny_list: DenyListConfig::default(),
        })
    }

    async fn make_state(secrets: HashMap<String, SecretString>) -> ProxyState {
        let dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(&dir.path().join("a.db")).await.unwrap());
        let manager = SessionManager::new();

        // Build a real vault with fast_test policy so proxy tests don't need
        // to hold a password in a session — the DEK is cached in UnlockedVault.
        let pw = SecretString::new("proxy-test-password".to_owned().into());
        let store = VaultStore::new_at_with_policy(dir.path().to_path_buf(), CryptoPolicy::fast_test());
        store.create_vault("TestVault", &pw).unwrap();
        if !secrets.is_empty() {
            store.set_secrets_bulk(&secrets, "TestVault", &pw).unwrap();
        }
        let vault = Arc::new(store.unlock("TestVault", &pw).unwrap());

        let session = Session::new(
            vault,
            ExpiryMode::Both,
            Some(8),
            std::process::id(),
            PathBuf::from("."),
        );
        manager.start(session).await;

        ProxyState {
            session: manager.shared(),
            audit,
            config: test_config(),
        }
    }

    fn test_app(state: ProxyState) -> impl tower::Service<Request<axum::body::Body>, Response = axum::response::Response, Error = std::convert::Infallible> + Clone + Send {
        let mock_addr = SocketAddr::from(([127, 0, 0, 1], 1234));
        build_router(state).layer(MockConnectInfo(mock_addr))
    }

    #[tokio::test]
    async fn status_returns_active() {
        let state = make_state(HashMap::new()).await;
        let resp = test_app(state)
            .oneshot(Request::get("/status").body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["status"], "active");
    }

    #[tokio::test]
    async fn get_secret_returns_value() {
        let mut secrets = HashMap::new();
        secrets.insert(
            "DB_URL".to_owned(),
            SecretString::new("postgres://test".to_owned().into()),
        );
        let state = make_state(secrets).await;

        let resp = test_app(state)
            .oneshot(
                Request::get("/secret/DB_URL")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["name"], "DB_URL");
        assert_eq!(v["value"], "postgres://test");
    }

    #[tokio::test]
    async fn get_nonexistent_secret_is_404() {
        let state = make_state(HashMap::new()).await;

        let resp = test_app(state)
            .oneshot(
                Request::get("/secret/NOPE")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn inject_route_does_not_exist() {
        let state = make_state(HashMap::new()).await;
        let resp = test_app(state)
            .oneshot(Request::get("/inject").body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
