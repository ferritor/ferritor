//! The JSON API: secret CRUD over HTTP, served on the same port as gRPC
//! (see `tls::serve`), so it shares the TLS setup, the client certificate
//! identity ([`tls::caller`]) and, through [`Secrets`], the authorizer, the
//! audit log and every seal rule. HTTP/1.1 and HTTP/2 both work.
//!
//! ```text
//! GET    /v1/secrets/{path}[?version=N]  200 {"path", "version", "created_at", "value"}
//! PUT    /v1/secrets/{path}              200 {"path", "version", "created_at"}
//!        body {"value": "<base64>"[, "expected_version": N][, "labels": {…}]}; every PUT stores a
//!        new version; with `expected_version`, only if the latest live version
//!        is still N (0: only if none), else 409 `version_mismatch`
//! DELETE /v1/secrets/{path}              204, every version
//! POST   /v1/restore/{path}              200 {"path", "version", "created_at"}
//!        body {} or {"version": N}: a deleted version made live again,
//!        within the retention. Without a version it undoes a delete: the
//!        newest deleted, only if none is live (409 live_version otherwise)
//! GET    /v1/secrets[?prefix=&page_size=&page_token=&label=k=v…]
//!                                        200 {"secrets": [metadata…], "next_page_token"}
//! GET    /v1/versions/{path}[?page_size=&page_token=]
//!                                        200 {"versions": [metadata + "deleted_at"…],
//!                                        "next_page_token"}: the history, newest
//!        first, live and deleted (`deleted_at` null while live), metadata only
//! GET    /v1/metadata/{path}             200 {"path", "created_at", "updated_at",
//!        "current_version", "oldest_version", "versions", "labels",
//!        "labels_updated_at"}: the path as a whole, never values (`list`)
//! PATCH  /v1/metadata/{path}             200 {"labels"}
//!        body {"set": {"k": "v"…}, "remove": ["k"…]}: change its labels (`label`)
//! GET    /v1/health                      200 {"ready": true, "sealed": false}, or 503
//!        when not ready (sealed, or shutting down): a readiness check for
//!        HTTP-only load balancers (see [`health`])
//! ```
//!
//! Values are standard base64 (with padding), since secrets are bytes;
//! `created_at` and `deleted_at` are RFC 3339 (UTC, seconds). Listings page like gRPC's
//! `ListSecrets`: an empty `next_page_token` is the last page. Unknown query
//! parameters and body fields are refused, so a typo (`?verison=2`) can't
//! silently read the latest version instead. Values are capped at
//! [`MAX_VALUE_SIZE`] (by `Secrets`, for both APIs alike), and the body
//! limit follows from it.
//!
//! Errors are `{"error": {"code", "message"}}`, with the gRPC API's status
//! mapped to HTTP and its message unchanged. `code` is the gRPC status's
//! `ErrorInfo` reason, lowercased, where it has one (`sealed`, `unaudited`
//! and `unknown_kek`: 503; `busy`, retry as is, and `version_mismatch`, read
//! again first: 409; see `ferritor_core::messages`), else the gRPC code's name
//! (`not_found`, `permission_denied`, …). Match on `code`, never the
//! message. Every response carries `Cache-Control: no-store`.
//!
//! **Browsers.** A client certificate the user installed is an ambient
//! credential, like a cookie: a browser presents it to this server whatever
//! page made the request. Two things keep other sites out, and must stay:
//! - Every state change needs a request a page can't send cross-site
//!   without a CORS preflight, which this server never grants: `PUT`,
//!   `PATCH` (labels), `DELETE`, and `POST` (restore) only with an
//!   `application/json` body,
//!   required even when empty (`{}`). So: no CORS headers, no
//!   state-changing `GET`, and no endpoint accepting form or text bodies.
//! - A cross-site `GET` does send the certificate, but without CORS the
//!   page can't read the response.
//!
//! In dev mode (no TLS, everyone allowed) there's no certificate, so the
//! remaining risk is a page reaching the server under its own name via DNS
//! rebinding; plaintext serving refuses any request not addressed to
//! loopback ([`loopback_hosts_only`]).

use std::sync::Arc;

use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{DefaultBodyLimit, Path, Query, RawQuery, Request, State};
use axum::http::uri::Authority;
use axum::http::{Extensions, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ferritor_core::labels::{self, Labels};
use ferritor_core::messages::reason;
use ferritor_core::path::SecretPath;
use ferritor_datastore::SecretMetadata;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};
use tonic::service::Routes;
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};
use tonic::{Code, Status};
use utoipa::{IntoParams, OpenApi, ToSchema};
use zeroize::Zeroizing;

use crate::audit::Gate;
use crate::authz::{Action, Caller};
use crate::health::Readiness;
use crate::policies::{self, Policies};
use crate::secrets::{MAX_VALUE_SIZE, Secrets, SecretsError};
use crate::tls;
use crate::{config, error_chain, grpc};

/// The JSON API's routes, to serve next to the gRPC services, with the
/// readiness check answered from `readiness`.
///
/// A route added here also needs a `#[utoipa::path]` on its handler, an
/// entry in `ApiDoc`'s `paths` and one in `ROUTES` in `tests/http.rs`.
/// Nothing fails if all three are missing (axum can't list its routes): the
/// route works, undocumented.
pub fn router(secrets: Arc<Secrets>, readiness: Arc<Readiness>, policies: Arc<Policies>) -> Router {
    let ready = Router::new()
        .route("/v1/health", get(health))
        .with_state(readiness);
    // Their own body limit, sized from the largest apply; set here, closer
    // to the handlers, it wins over the secret endpoints' one below.
    let policy_routes = Router::new()
        .route("/v1/policies", get(list_policies))
        .route(
            "/v1/policies/{*name}",
            get(get_policy).put(put_policy).delete(delete_policy),
        )
        .route("/v1/policy-apply", post(apply_policies))
        .route("/v1/policy-check", get(check_access))
        .layer(DefaultBodyLimit::max(POLICY_BODY_LIMIT))
        .with_state(policies);
    Router::new()
        .route("/v1/secrets", get(list))
        .route("/v1/secrets/{*path}", get(read).put(write).delete(remove))
        .route("/v1/restore/{*path}", post(restore))
        .route("/v1/versions/{*path}", get(versions))
        .route(
            "/v1/metadata/{*path}",
            get(get_metadata).patch(update_labels),
        )
        .merge(ready)
        .merge(policy_routes)
        .fallback(|| async {
            ApiError::new(
                StatusCode::NOT_FOUND,
                ErrorCode::NotFound,
                "no such endpoint",
            )
        })
        .method_not_allowed_fallback(|| async {
            ApiError::new(
                StatusCode::METHOD_NOT_ALLOWED,
                ErrorCode::MethodNotAllowed,
                "method not allowed here",
            )
        })
        .layer(axum::middleware::map_response(no_store))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .with_state(secrets)
}

/// The OpenAPI description of these routes, derived from the handlers and
/// the types serde uses: `docs/openapi.json` is this, and a test fails when
/// the file is out of date (regenerate it with `FERRITOR_UPDATE_OPENAPI=1 cargo
/// test -p ferritor-server --lib openapi`).
pub fn openapi() -> utoipa::openapi::OpenApi {
    ApiDoc::openapi()
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "ferritor HTTP API",
        version = "1",
        description = "Secrets and stored policies over JSON, on the same port as gRPC. \
            Authentication is mutual TLS only: the caller is the one `ferritor://<name>` URI SAN \
            of its client certificate, and the policy decides what it may do (https://ferritor.dev/reference/http-api, \
            https://ferritor.dev/guides/policy). Every response carries `Cache-Control: no-store`, none carries \
            CORS headers. Errors are `{\"error\": {\"code\", \"message\"}}`: match on `code`. \
            Unknown body fields (422) and query parameters (400) are refused."
    ),
    servers(
        (url = "https://ferritor.example.internal:7070", description = "Secured mode (mutual TLS)."),
        (url = "http://localhost:7070", description = "Dev mode: plaintext, loopback only, everyone allowed."),
    ),
    paths(
        health,
        list,
        read,
        write,
        remove,
        restore,
        versions,
        get_metadata,
        update_labels,
        list_policies,
        get_policy,
        put_policy,
        delete_policy,
        apply_policies,
        check_access,
    ),
    modifiers(&MutualTls),
    security(("client_certificate" = [])),
    tags(
        (name = "health", description = "Readiness, for load balancers."),
        (name = "secrets", description = "Secrets: versions, history, metadata and labels."),
        (name = "policies", description = "Stored policies: the applications' grants."),
    )
)]
struct ApiDoc;

/// The one authentication: a client certificate (OpenAPI 3.1 `mutualTLS`).
struct MutualTls;

impl utoipa::Modify for MutualTls {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "client_certificate",
            utoipa::openapi::security::SecurityScheme::MutualTls {
                description: Some(
                    "A client certificate from the server's client CA with one \
                     `ferritor://<name>` URI SAN and the clientAuth extended key usage."
                        .to_owned(),
                ),
                deprecated: None,
                extensions: None,
            },
        );
    }
}

/// Whether this server should get traffic now.
///
/// For load balancers that only speak HTTP: 200 when ready, 503 otherwise
/// (`sealed` says whether that's why; not sealed means it's shutting down;
/// uninitialized counts as sealed). The same as gRPC's health service
/// reports for `ferritor.v1.SecretsService`. No authorization and not audited;
/// in secured mode the TLS handshake still needs a client certificate.
#[utoipa::path(
    get,
    path = "/v1/health",
    tag = "health",
    operation_id = "health",
    security(()),
    responses(
        (status = 200, description = "Ready.", body = Health),
        (status = 503, description = "Not ready: sealed, or shutting down.", body = Health),
    )
)]
async fn health(State(readiness): State<Arc<Readiness>>) -> Response {
    let (ready, sealed) = (readiness.is_ready(), readiness.is_sealed());
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(Health { ready, sealed })).into_response()
}

#[derive(Serialize, ToSchema)]
struct Health {
    ready: bool,
    sealed: bool,
}

/// A JSON body carrying the largest put, escaped as badly as a JSON encoder
/// may: the value's base64 (4 bytes of every 3) with each `/` as `\/`
/// (doubling it), and every label at its longest with each character as
/// `\uXXXX` (6 bytes for a 1-byte character; multi-byte characters escape
/// to less per byte), plus the quotes, colon and comma around each, and room
/// for the rest of the object. Only a coarse bound: `Secrets` checks the
/// value and labels themselves.
const BODY_LIMIT: usize = 2 * MAX_VALUE_SIZE.div_ceil(3) * 4
    + 6 * labels::MAX_LABELS_SIZE
    + 8 * labels::MAX_LABELS
    + 1024;

/// The policy endpoints' body limit: the largest apply, with room for JSON's
/// escaping (names, paths and identities are ASCII, so escaping only grows
/// a description; twice the bytes is plenty).
const POLICY_BODY_LIMIT: usize = 2 * ferritor_core::policy::MAX_APPLY_BYTES;

/// Every route of `routes` (gRPC's too) refuses requests not addressed to
/// `localhost` or a loopback IP (any port; by [`config::is_loopback`], the
/// rule for where dev mode may listen), with 421: the defence against DNS
/// rebinding for plaintext dev mode (see `tls::serve`). The
/// name comes from the URI's authority (HTTP/2's `:authority`, or an
/// absolute-form HTTP/1.1 target) and every `Host` header; all present must
/// be loopback, and at least one must be present.
pub fn loopback_hosts_only(routes: Routes) -> Routes {
    Routes::from(
        routes
            .into_axum_router()
            .layer(axum::middleware::from_fn(require_loopback_host)),
    )
}

async fn require_loopback_host(request: Request, next: Next) -> Response {
    if addressed_to_loopback(&request) {
        return next.run(request).await;
    }
    tracing::warn!(
        host = ?request.headers().get(header::HOST),
        authority = ?request.uri().authority(),
        "refused a request not addressed to loopback (DNS rebinding?)"
    );
    ApiError::new(
        StatusCode::MISDIRECTED_REQUEST,
        ErrorCode::MisdirectedRequest,
        "in dev mode this server only answers requests addressed to localhost or a loopback \
         address",
    )
    .into_response()
}

fn addressed_to_loopback<B>(request: &axum::http::Request<B>) -> bool {
    let mut hosts = Vec::new();
    if let Some(authority) = request.uri().authority() {
        hosts.push(authority.host().to_owned());
    }
    for value in request.headers().get_all(header::HOST) {
        let Some(authority) = value
            .to_str()
            .ok()
            .and_then(|host| host.parse::<Authority>().ok())
        else {
            return false;
        };
        hosts.push(authority.host().to_owned());
    }
    !hosts.is_empty() && hosts.iter().all(|host| is_loopback_host(host))
}

/// `localhost`, or an IP literal (IPv6 in `[ ]`) that's loopback by the
/// same rule as where dev mode may listen ([`config::is_loopback`]). Any IP
/// literal is safe here: DNS rebinding needs a name the attacker controls.
pub(crate) fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let literal = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    literal.parse().is_ok_and(config::is_loopback)
}

/// Secrets, and errors about them, must not end up in any cache.
async fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Who is calling: the connection info tonic recorded, as for gRPC.
fn caller(secrets: &Secrets, extensions: &Extensions, action: Action) -> Result<Caller, ApiError> {
    caller_via(secrets.gate(), extensions, action)
}

fn caller_via(gate: &Gate, extensions: &Extensions, action: Action) -> Result<Caller, ApiError> {
    let tls_info = extensions.get::<TlsConnectInfo<TcpConnectInfo>>();
    let certs = tls_info.and_then(TlsConnectInfo::peer_certs);
    let peer = match tls_info {
        Some(info) => info.get_ref().remote_addr(),
        None => extensions
            .get::<TcpConnectInfo>()
            .and_then(TcpConnectInfo::remote_addr),
    };
    tls::caller(
        gate,
        certs.as_deref().map(Vec::as_slice),
        extensions.get(),
        peer,
        action,
    )
    .map_err(|e| Status::unauthenticated(error_chain(&e)).into())
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
struct ReadQuery {
    /// A specific version (from 1); leave it out for the latest.
    #[param(minimum = 1)]
    version: Option<u32>,
}

/// A new version of a secret.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct WriteBody {
    /// The value, standard base64 with padding (at most 1 MiB decoded).
    #[schema(content_encoding = "base64")]
    value: String,
    /// Check-and-set: store only if the latest version is still this one;
    /// 0: only if the secret doesn't exist yet.
    expected_version: Option<u32>,
    /// Labels to set with this put (needs the `label` action too): plain
    /// metadata, not encrypted.
    #[serde(default)]
    #[schema(value_type = std::collections::HashMap<String, String>)]
    labels: Labels,
}

/// A change to a secret's labels.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct LabelsBody {
    /// Added, or replacing a label's value.
    #[serde(default)]
    #[schema(value_type = std::collections::HashMap<String, String>)]
    set: Labels,
    /// Label keys to remove (absent ones are fine).
    #[serde(default)]
    remove: Vec<String>,
}

#[derive(Serialize, ToSchema)]
struct LabelsReply {
    /// The labels now.
    #[schema(value_type = std::collections::HashMap<String, String>)]
    labels: Labels,
}

/// A secret as a whole: never its value.
#[derive(Serialize, ToSchema)]
struct PathMetadataBody {
    path: String,
    #[schema(format = DateTime)]
    created_at: String,
    #[schema(format = DateTime)]
    updated_at: String,
    /// The latest live version; null when every version is deleted.
    #[schema(required)]
    current_version: Option<u32>,
    /// The oldest version still stored; null when every version was purged.
    #[schema(required)]
    oldest_version: Option<u32>,
    /// How many versions are stored, deleted ones included.
    versions: u64,
    #[schema(value_type = std::collections::HashMap<String, String>)]
    labels: Labels,
    /// When the labels last changed; null if they never did.
    #[schema(format = DateTime, required)]
    labels_updated_at: Option<String>,
}

/// Which deleted version to bring back.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct RestoreBody {
    /// That version, alongside any live one. Left out (`{}`): undo a delete,
    /// restoring the newest deleted version, only while none is live.
    #[schema(minimum = 1)]
    version: Option<u32>,
}

// A listing's query string: `prefix`, `page_size`, `page_token` at most once
// each, and `label=key=value` any number of times (paths having every one).
// Parsed by hand: serde's URL decoding can't collect a repeated parameter
// into a struct field. Anything else is refused, like a typo anywhere else.
// Described by hand in `list`'s `params`.
#[derive(Default)]
struct ListQuery {
    prefix: String,
    page_size: u32,
    page_token: String,
    labels: Labels,
}

impl ListQuery {
    fn parse(raw: Option<&str>) -> Result<Self, ApiError> {
        let pairs: Vec<(String, String)> = serde_urlencoded::from_str(raw.unwrap_or(""))
            .map_err(|_| ApiError::invalid("the query string isn't valid URL encoding"))?;
        let mut query = Self::default();
        let mut seen = Vec::new();
        for (key, value) in pairs {
            if key != "label" {
                if seen.contains(&key) {
                    return Err(ApiError::invalid(&format!("`{key}` is given twice")));
                }
                seen.push(key.clone());
            }
            match key.as_str() {
                "prefix" => query.prefix = value,
                "page_size" => {
                    query.page_size = value
                        .parse()
                        .map_err(|_| ApiError::invalid("`page_size` must be a number"))?;
                }
                "page_token" => query.page_token = value,
                "label" => {
                    let (key, value) = labels::parse_pair(&value)
                        .map_err(|e| ApiError::invalid(&e.to_string()))?;
                    if query.labels.insert(key.clone(), value).is_some() {
                        return Err(ApiError::invalid(&format!("label `{key}` is given twice")));
                    }
                }
                other => {
                    return Err(ApiError::invalid(&format!(
                        "unknown query parameter `{other}`; known: prefix, page_size, \
                         page_token, label"
                    )));
                }
            }
        }
        Ok(query)
    }
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
struct VersionsQuery {
    /// 0 or absent: 100; capped at 1000.
    #[serde(default)]
    page_size: u32,
    /// The previous page's `next_page_token`.
    #[serde(default)]
    page_token: String,
}

#[derive(Serialize, ToSchema)]
struct Version {
    #[serde(flatten)]
    metadata: Metadata,
    /// When it was deleted (restorable until purged); null while live.
    #[schema(format = DateTime, required)]
    deleted_at: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct VersionsBody {
    /// Newest first.
    versions: Vec<Version>,
    /// Empty when there's no next page.
    next_page_token: String,
}

/// One version of a secret, without its value.
#[derive(Serialize, ToSchema)]
struct Metadata {
    path: String,
    #[schema(minimum = 1)]
    version: u32,
    #[schema(format = DateTime)]
    created_at: String,
}

#[derive(Serialize, ToSchema)]
struct SecretBody {
    #[serde(flatten)]
    metadata: Metadata,
    /// The value, standard base64 with padding.
    // A plain copy, like gRPC's: the decrypted value itself is wiped.
    #[schema(content_encoding = "base64")]
    value: String,
}

#[derive(Serialize, ToSchema)]
struct ListBody {
    /// The latest version of each secret.
    secrets: Vec<Metadata>,
    /// Empty when there's no next page.
    next_page_token: String,
}

fn metadata(m: SecretMetadata) -> Result<Metadata, ApiError> {
    Ok(Metadata {
        created_at: rfc3339(m.created_at, &m.path)?,
        path: m.path.to_string(),
        version: m.version,
    })
}

/// A stored time as RFC 3339, UTC, to the second (like gRPC's unix
/// seconds). Fails only for a year RFC 3339 can't write (past 9999).
fn rfc3339(at: OffsetDateTime, path: &SecretPath) -> Result<String, ApiError> {
    at.checked_to_offset(UtcOffset::UTC)
        .and_then(|t| t.replace_nanosecond(0).ok())
        .and_then(|t| t.format(&Rfc3339).ok())
        .ok_or_else(|| {
            tracing::error!(%path, "a timestamp could not be formatted");
            ApiError::from(Status::internal("internal error"))
        })
}

/// Read a secret (`read`).
///
/// The latest version, or the one asked for. Deleted versions aren't
/// readable: restore one first.
#[utoipa::path(
    get,
    path = "/v1/secrets/{path}",
    operation_id = "getSecret",
    tag = "secrets",
    params(("path" = String, Path, description = "A canonical secret path, slashes included (`billing/db`); its first segment is its namespace."), ReadQuery),
    responses((status = 200, description = "The secret.", body = SecretBody), (status = "default", description = "An error: see `error.code`.", body = ErrorBody))
)]
async fn read(
    State(secrets): State<Arc<Secrets>>,
    extensions: Extensions,
    path: Result<Path<String>, PathRejection>,
    query: Result<Query<ReadQuery>, QueryRejection>,
) -> Result<Json<SecretBody>, ApiError> {
    let caller = caller(&secrets, &extensions, Action::Read)?;
    let Path(path) = path.map_err(|r| ApiError::rejected(r.status(), r.body_text()))?;
    let Query(query) = query.map_err(|r| ApiError::rejected(r.status(), r.body_text()))?;
    if query.version == Some(0) {
        return Err(ApiError::invalid(
            "versions start at 1; leave `version` out for the latest",
        ));
    }
    let secret = secrets.get(&caller, &path, query.version).await?;
    Ok(Json(SecretBody {
        value: STANDARD.encode(secret.value.as_slice()),
        metadata: metadata(secret.metadata)?,
    }))
}

/// Store a new version (`write`; `label` too with labels).
#[utoipa::path(
    put,
    path = "/v1/secrets/{path}",
    operation_id = "putSecret",
    tag = "secrets",
    params(("path" = String, Path, description = "A canonical secret path, slashes included (`billing/db`); its first segment is its namespace.")),
    request_body = WriteBody,
    responses((status = 200, description = "The version stored.", body = Metadata), (status = "default", description = "An error: see `error.code`.", body = ErrorBody))
)]
async fn write(
    State(secrets): State<Arc<Secrets>>,
    extensions: Extensions,
    path: Result<Path<String>, PathRejection>,
    body: Result<Json<WriteBody>, JsonRejection>,
) -> Result<Json<Metadata>, ApiError> {
    let caller = caller(&secrets, &extensions, Action::Write)?;
    let Path(path) = path.map_err(|r| ApiError::rejected(r.status(), r.body_text()))?;
    let Json(body) = body.map_err(|r| ApiError::rejected(r.status(), r.body_text()))?;
    let value = Zeroizing::new(body.value);
    let value = Zeroizing::new(
        STANDARD
            .decode(value.as_bytes())
            .map_err(|_| ApiError::invalid("`value` must be standard base64, with padding"))?,
    );
    let stored = secrets
        .put_labeled(&caller, &path, &value, body.expected_version, &body.labels)
        .await?;
    Ok(Json(metadata(stored)?))
}

/// Delete every version (`delete`).
///
/// Deleted versions are restorable until purged.
#[utoipa::path(
    delete,
    path = "/v1/secrets/{path}",
    operation_id = "deleteSecret",
    tag = "secrets",
    params(("path" = String, Path, description = "A canonical secret path, slashes included (`billing/db`); its first segment is its namespace.")),
    responses((status = 204, description = "Deleted."), (status = "default", description = "An error: see `error.code`.", body = ErrorBody))
)]
async fn remove(
    State(secrets): State<Arc<Secrets>>,
    extensions: Extensions,
    path: Result<Path<String>, PathRejection>,
) -> Result<StatusCode, ApiError> {
    let caller = caller(&secrets, &extensions, Action::Delete)?;
    let Path(path) = path.map_err(|r| ApiError::rejected(r.status(), r.body_text()))?;
    secrets.delete(&caller, &path).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Bring a deleted version back (`write`).
///
/// `{}` undoes a delete (the newest deleted version, only while none is
/// live; 409 `live_version` otherwise); `{"version": N}` restores that one.
// A JSON body is required even to restore the newest (`{}`): like every
// state change here, it then needs a CORS preflight (see the module docs).
#[utoipa::path(
    post,
    path = "/v1/restore/{path}",
    operation_id = "restoreSecret",
    tag = "secrets",
    params(("path" = String, Path, description = "A canonical secret path, slashes included (`billing/db`); its first segment is its namespace.")),
    request_body = RestoreBody,
    responses((status = 200, description = "The version restored.", body = Metadata), (status = "default", description = "An error: see `error.code`.", body = ErrorBody))
)]
async fn restore(
    State(secrets): State<Arc<Secrets>>,
    extensions: Extensions,
    path: Result<Path<String>, PathRejection>,
    body: Result<Json<RestoreBody>, JsonRejection>,
) -> Result<Json<Metadata>, ApiError> {
    let caller = caller(&secrets, &extensions, Action::Write)?;
    let Path(path) = path.map_err(|r| ApiError::rejected(r.status(), r.body_text()))?;
    let Json(body) = body.map_err(|r| ApiError::rejected(r.status(), r.body_text()))?;
    if body.version == Some(0) {
        return Err(ApiError::invalid(
            "versions start at 1; leave `version` out to undo a delete",
        ));
    }
    let restored = secrets.restore(&caller, &path, body.version).await?;
    Ok(Json(metadata(restored)?))
}

/// List the latest secret versions below a prefix (`list`).
///
/// Needs `list` on the prefix, or on every path without one.
#[utoipa::path(
    get,
    path = "/v1/secrets",
    operation_id = "listSecrets",
    tag = "secrets",
    params(
        ("prefix" = Option<String>, Query, description = "Whole segments; empty or absent lists everything."),
        ("label" = Option<Vec<String>>, Query, style = Form, explode, description = "`key=value`; repeatable, every one must match."),
        ("page_size" = Option<u32>, Query, description = "0 or absent: 100; capped at 1000."),
        ("page_token" = Option<String>, Query, description = "The previous page's `next_page_token`."),
    ),
    responses((status = 200, description = "One page.", body = ListBody), (status = "default", description = "An error: see `error.code`.", body = ErrorBody))
)]
async fn list(
    State(secrets): State<Arc<Secrets>>,
    extensions: Extensions,
    RawQuery(raw): RawQuery,
) -> Result<Json<ListBody>, ApiError> {
    let caller = caller(&secrets, &extensions, Action::List)?;
    let query = ListQuery::parse(raw.as_deref())?;
    let page = secrets
        .list(
            &caller,
            &query.prefix,
            query.page_size,
            &query.page_token,
            &query.labels,
        )
        .await?;
    Ok(Json(ListBody {
        secrets: page
            .secrets
            .into_iter()
            .map(metadata)
            .collect::<Result<_, _>>()?,
        next_page_token: page.next_page_token,
    }))
}

/// A secret's history, newest first (`list`).
///
/// Every version still stored, deleted ones included; metadata only.
#[utoipa::path(
    get,
    path = "/v1/versions/{path}",
    operation_id = "listVersions",
    tag = "secrets",
    params(("path" = String, Path, description = "A canonical secret path, slashes included (`billing/db`); its first segment is its namespace."), VersionsQuery),
    responses((status = 200, description = "One page.", body = VersionsBody), (status = "default", description = "An error: see `error.code`.", body = ErrorBody))
)]
async fn versions(
    State(secrets): State<Arc<Secrets>>,
    extensions: Extensions,
    path: Result<Path<String>, PathRejection>,
    query: Result<Query<VersionsQuery>, QueryRejection>,
) -> Result<Json<VersionsBody>, ApiError> {
    let caller = caller(&secrets, &extensions, Action::List)?;
    let Path(path) = path.map_err(|r| ApiError::rejected(r.status(), r.body_text()))?;
    let Query(query) = query.map_err(|r| ApiError::rejected(r.status(), r.body_text()))?;
    let page = secrets
        .versions(&caller, &path, query.page_size, &query.page_token)
        .await?;
    Ok(Json(VersionsBody {
        versions: page
            .versions
            .into_iter()
            .map(|v| {
                Ok(Version {
                    deleted_at: v
                        .deleted_at
                        .map(|at| rfc3339(at, &v.metadata.path))
                        .transpose()?,
                    metadata: metadata(v.metadata)?,
                })
            })
            .collect::<Result<_, ApiError>>()?,
        next_page_token: page.next_page_token,
    }))
}

/// A secret's metadata and labels (`list`).
#[utoipa::path(
    get,
    path = "/v1/metadata/{path}",
    operation_id = "getMetadata",
    tag = "secrets",
    params(("path" = String, Path, description = "A canonical secret path, slashes included (`billing/db`); its first segment is its namespace.")),
    responses((status = 200, description = "The metadata.", body = PathMetadataBody), (status = "default", description = "An error: see `error.code`.", body = ErrorBody))
)]
async fn get_metadata(
    State(secrets): State<Arc<Secrets>>,
    extensions: Extensions,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<PathMetadataBody>, ApiError> {
    let caller = caller(&secrets, &extensions, Action::List)?;
    let Path(path) = path.map_err(|r| ApiError::rejected(r.status(), r.body_text()))?;
    let m = secrets.metadata(&caller, &path).await?;
    Ok(Json(PathMetadataBody {
        created_at: rfc3339(m.created_at, &m.path)?,
        updated_at: rfc3339(m.updated_at, &m.path)?,
        labels_updated_at: m
            .labels_updated_at
            .map(|at| rfc3339(at, &m.path))
            .transpose()?,
        path: m.path.to_string(),
        current_version: m.current_version,
        oldest_version: m.oldest_version,
        versions: m.versions,
        labels: m.labels,
    }))
}

/// Change a secret's labels (`label`).
#[utoipa::path(
    patch,
    path = "/v1/metadata/{path}",
    operation_id = "updateLabels",
    tag = "secrets",
    params(("path" = String, Path, description = "A canonical secret path, slashes included (`billing/db`); its first segment is its namespace.")),
    request_body = LabelsBody,
    responses((status = 200, description = "The labels now.", body = LabelsReply), (status = "default", description = "An error: see `error.code`.", body = ErrorBody))
)]
async fn update_labels(
    State(secrets): State<Arc<Secrets>>,
    extensions: Extensions,
    path: Result<Path<String>, PathRejection>,
    body: Result<Json<LabelsBody>, JsonRejection>,
) -> Result<Json<LabelsReply>, ApiError> {
    let caller = caller(&secrets, &extensions, Action::Label)?;
    let Path(path) = path.map_err(|r| ApiError::rejected(r.status(), r.body_text()))?;
    let Json(body) = body.map_err(|r| ApiError::rejected(r.status(), r.body_text()))?;
    let labels = secrets
        .update_labels(&caller, &path, &body.set, &body.remove)
        .await?;
    Ok(Json(LabelsReply { labels }))
}

/// What went wrong, for programs to match on: the same condition always has
/// the same code (the message is for people, and may change). New codes may
/// be added; treat an unknown one by its HTTP status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ErrorCode {
    InvalidArgument,
    Unauthenticated,
    PermissionDenied,
    NotFound,
    MethodNotAllowed,
    VersionMismatch,
    LiveVersion,
    NoNamespace,
    Busy,
    Aborted,
    MisdirectedRequest,
    Sealed,
    Unaudited,
    UnknownKek,
    PolicyUnverified,
    /// Over one of the caller's rate limits; the message says which, and
    /// `Retry-After` when to retry.
    RateLimited,
    Unavailable,
    FailedPrecondition,
    Internal,
}

/// Every error's body.
#[derive(Serialize, ToSchema)]
pub(crate) struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ErrorDetail {
    /// Match on this, never on the message.
    code: ErrorCode,
    /// For people; may change.
    message: String,
}

// `{"error": {"code", "message"}}` with an HTTP status.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: ErrorCode,
    message: String,
    /// When to retry (a rate limit's `RetryInfo`): sent as `Retry-After`.
    retry_after: Option<std::time::Duration>,
}

impl ApiError {
    fn new(status: StatusCode, code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            retry_after: None,
        }
    }

    fn invalid(message: &str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, ErrorCode::InvalidArgument, message)
    }

    /// A request axum couldn't parse (body, query or path), keeping its
    /// status (400, 413, 415, 422).
    fn rejected(status: StatusCode, message: String) -> Self {
        Self::new(status, ErrorCode::InvalidArgument, message)
    }
}

impl From<SecretsError> for ApiError {
    /// Through the gRPC mapping, so both APIs answer alike, reasons
    /// included (and internal errors are logged there, never sent).
    fn from(e: SecretsError) -> Self {
        Status::from(e).into()
    }
}

impl From<Status> for ApiError {
    /// The `ErrorInfo` reason, where there is one, lowercased as `code` (so
    /// JSON clients get what gRPC clients get from the details), else the
    /// gRPC code's name.
    fn from(status: Status) -> Self {
        let message = status.message().to_owned();
        let reason = grpc::reason_of(&status);
        let (http, code) = match (reason.as_deref(), status.code()) {
            (Some(reason::SEALED), _) => (StatusCode::SERVICE_UNAVAILABLE, ErrorCode::Sealed),
            (Some(reason::UNAUDITED), _) => (StatusCode::SERVICE_UNAVAILABLE, ErrorCode::Unaudited),
            // Retry as is.
            (Some(reason::BUSY), _) => (StatusCode::CONFLICT, ErrorCode::Busy),
            // Read again first; a 503 would say "try another server".
            (Some(reason::VERSION_MISMATCH), _) => {
                (StatusCode::CONFLICT, ErrorCode::VersionMismatch)
            }
            // This server can't serve it now; another may.
            (Some(reason::UNKNOWN_KEK), _) => {
                (StatusCode::SERVICE_UNAVAILABLE, ErrorCode::UnknownKek)
            }
            // Name the version instead; retrying as is fails the same way.
            (Some(reason::LIVE_VERSION), _) => (StatusCode::CONFLICT, ErrorCode::LiveVersion),
            // Create the namespace first; retrying as is fails the same way.
            (Some(reason::NO_NAMESPACE), _) => (StatusCode::CONFLICT, ErrorCode::NoNamespace),
            // Repair the stored policies; retrying as is fails the same way.
            (Some(reason::POLICY_UNVERIFIED), _) => {
                (StatusCode::SERVICE_UNAVAILABLE, ErrorCode::PolicyUnverified)
            }
            // Over one of the caller's limits: retry after `Retry-After`.
            (Some(reason::RATE_LIMITED), _) => {
                (StatusCode::TOO_MANY_REQUESTS, ErrorCode::RateLimited)
            }
            (_, code) => code_to_http(code),
        };
        let mut error = Self::new(http, code, message);
        if code == ErrorCode::RateLimited {
            use tonic_types::StatusExt as _;
            error.retry_after = status
                .get_error_details()
                .retry_info()
                .and_then(|info| info.retry_delay);
        }
        error
    }
}

fn code_to_http(code: Code) -> (StatusCode, ErrorCode) {
    match code {
        Code::InvalidArgument => (StatusCode::BAD_REQUEST, ErrorCode::InvalidArgument),
        Code::Unauthenticated => (StatusCode::UNAUTHORIZED, ErrorCode::Unauthenticated),
        Code::PermissionDenied => (StatusCode::FORBIDDEN, ErrorCode::PermissionDenied),
        Code::NotFound => (StatusCode::NOT_FOUND, ErrorCode::NotFound),
        // Not a secret operation's condition today (those all carry a
        // reason), but a policy write's (another server rekeyed); a 503
        // like the others.
        Code::FailedPrecondition => (
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::FailedPrecondition,
        ),
        Code::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, ErrorCode::Unavailable),
        Code::Aborted => (StatusCode::CONFLICT, ErrorCode::Aborted),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::Internal),
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorBody {
            error: ErrorDetail {
                code: self.code,
                message: self.message,
            },
        };
        let mut response = (self.status, Json(body)).into_response();
        if let Some(after) = self.retry_after {
            // Whole seconds, rounded up, at least 1 (RFC 9110).
            let seconds = after.as_secs() + u64::from(after.subsec_nanos() > 0);
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(seconds.max(1)));
        }
        response
    }
}

// The policy endpoints (see `policies`): the JSON face of `PolicyService`,
// through the same `Policies` and the same status mapping. Every state change
// is a JSON-bodied `PUT`/`POST` or a `DELETE`: like the secret endpoints,
// each needs a CORS preflight the server never grants.

impl From<policies::PoliciesError> for ApiError {
    fn from(e: policies::PoliciesError) -> Self {
        Status::from(e).into()
    }
}

/// Where a rule comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
enum PolicySource {
    /// `[[policy]]` in ferritor.toml: read-only here.
    Config,
    Stored,
}

/// A rule as listed or read.
#[derive(Serialize, ToSchema)]
struct PolicyBody {
    /// Stored: its name. Config: `config:<name>`, or `config:<n>` by
    /// position.
    name: String,
    source: PolicySource,
    /// The `<name>` of a `ferritor://<name>` identity.
    identity: String,
    /// Action names (a config rule may hold admin actions).
    actions: Vec<String>,
    paths: Vec<String>,
    all_paths: bool,
    description: String,
    /// Stored policies only.
    // Left out when absent, never null.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(format = DateTime, nullable = false)]
    created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(format = DateTime, nullable = false)]
    updated_at: Option<String>,
}

fn policy_time(at: Option<OffsetDateTime>) -> Result<Option<String>, ApiError> {
    at.map(|at| {
        at.checked_to_offset(UtcOffset::UTC)
            .and_then(|t| t.replace_nanosecond(0).ok())
            .and_then(|t| t.format(&Rfc3339).ok())
            .ok_or_else(|| ApiError::from(Status::internal("internal error")))
    })
    .transpose()
}

fn policy_body(entry: policies::Entry) -> Result<PolicyBody, ApiError> {
    Ok(PolicyBody {
        created_at: policy_time(entry.created_at)?,
        updated_at: policy_time(entry.updated_at)?,
        name: entry.name,
        source: match entry.source {
            policies::Source::Config => PolicySource::Config,
            policies::Source::Stored => PolicySource::Stored,
        },
        identity: entry.identity,
        actions: entry.actions,
        paths: entry.paths,
        all_paths: entry.all_paths,
        description: entry.description,
        version: entry.version,
    })
}

#[derive(Deserialize, Default, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields, default)]
struct ListPoliciesQuery {
    /// Only this identity's rules.
    identity: Option<String>,
    /// 0 or absent: 100; capped at 1000.
    page_size: u32,
    /// The previous page's `next_page_token`.
    page_token: String,
}

/// Whether the stored policies are in force (listed) on this server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
enum StoredState {
    Loaded,
    /// Not in force while sealed: only config rules are listed.
    Sealed,
    /// The stored set doesn't verify: only config rules are listed.
    Unverified,
}

#[derive(Serialize, ToSchema)]
struct PolicyListBody {
    policies: Vec<PolicyBody>,
    /// Empty when there's no next page.
    next_page_token: String,
    stored: StoredState,
    /// The stored set's revision, when loaded.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    revision: Option<u64>,
}

/// List the config rules and the stored policies (`policy`).
#[utoipa::path(
    get,
    path = "/v1/policies",
    operation_id = "listPolicies",
    tag = "policies",
    params(ListPoliciesQuery),
    responses((status = 200, description = "One page, by name.", body = PolicyListBody), (status = "default", description = "An error: see `error.code`.", body = ErrorBody))
)]
async fn list_policies(
    State(policies): State<Arc<Policies>>,
    extensions: Extensions,
    query: Result<Query<ListPoliciesQuery>, QueryRejection>,
) -> Result<Json<PolicyListBody>, ApiError> {
    let caller = caller_via(policies.gate(), &extensions, Action::Policy)?;
    let Query(query) = query.map_err(|r| ApiError::rejected(r.status(), r.body_text()))?;
    let page = policies
        .list(
            &caller,
            query.identity.as_deref(),
            query.page_size,
            &query.page_token,
        )
        .await?;
    let (stored, revision) = match page.stored {
        policies::StoredState::Loaded { revision } => (StoredState::Loaded, Some(revision)),
        policies::StoredState::Sealed => (StoredState::Sealed, None),
        policies::StoredState::Unverified => (StoredState::Unverified, None),
    };
    Ok(Json(PolicyListBody {
        policies: page
            .entries
            .into_iter()
            .map(policy_body)
            .collect::<Result<_, _>>()?,
        next_page_token: page.next_page_token,
        stored,
        revision,
    }))
}

/// Get one rule: a stored policy or a config rule (`policy`).
///
/// A config rule by its `config:` name.
#[utoipa::path(
    get,
    path = "/v1/policies/{name}",
    operation_id = "getPolicy",
    tag = "policies",
    params(("name" = String, Path, description = "A stored policy's name (secret-path rules, may contain `/`), or `config:…` for a config rule.")),
    responses((status = 200, description = "The rule.", body = PolicyBody), (status = "default", description = "An error: see `error.code`.", body = ErrorBody))
)]
async fn get_policy(
    State(policies): State<Arc<Policies>>,
    extensions: Extensions,
    name: Result<Path<String>, PathRejection>,
) -> Result<Json<PolicyBody>, ApiError> {
    let caller = caller_via(policies.gate(), &extensions, Action::Policy)?;
    let Path(name) = name.map_err(|r| ApiError::rejected(r.status(), r.body_text()))?;
    Ok(Json(policy_body(policies.get(&caller, &name).await?)?))
}

/// What a stored policy may grant (an admin action is refused, 422).
// Documentation only: the bodies deserialize `ferritor_core::policy::
// SecretAction`, whose names a test checks against this.
#[derive(ToSchema)]
#[schema(rename_all = "snake_case")]
#[expect(dead_code, reason = "a schema for ferritor_core::policy::SecretAction")]
enum SecretActionName {
    Read,
    Write,
    Delete,
    List,
    Label,
}

/// A stored policy to create or replace; its name is the path's.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct PutPolicyBody {
    /// The `<name>` of a `ferritor://<name>` identity.
    identity: String,
    #[schema(value_type = Vec<SecretActionName>, min_items = 1)]
    actions: Vec<ferritor_core::policy::SecretAction>,
    /// Path prefixes, whole segments; exactly one of `paths` and
    /// `all_paths`.
    #[serde(default)]
    #[schema(max_items = 64)]
    paths: Vec<String>,
    #[serde(default)]
    all_paths: bool,
    /// What it's for (printable ASCII, newlines and tabs; at most 1 KiB).
    #[serde(default)]
    description: String,
    /// Check-and-set: 0 only creates; N only replaces version N.
    expected_version: Option<u32>,
}

#[derive(Serialize, ToSchema)]
struct WrittenBody {
    version: u32,
    /// The stored set's revision now.
    revision: u64,
    /// False: it replaced an existing policy.
    created: bool,
}

/// Create or replace a stored policy (`policy`).
#[utoipa::path(
    put,
    path = "/v1/policies/{name}",
    operation_id = "putPolicy",
    tag = "policies",
    params(("name" = String, Path, description = "A stored policy's name (secret-path rules, may contain `/`), or `config:…` for a config rule.")),
    request_body = PutPolicyBody,
    responses((status = 200, description = "Stored.", body = WrittenBody), (status = "default", description = "An error: see `error.code`.", body = ErrorBody))
)]
async fn put_policy(
    State(policies): State<Arc<Policies>>,
    extensions: Extensions,
    name: Result<Path<String>, PathRejection>,
    body: Result<Json<PutPolicyBody>, JsonRejection>,
) -> Result<Json<WrittenBody>, ApiError> {
    let caller = caller_via(policies.gate(), &extensions, Action::Policy)?;
    let Path(name) = name.map_err(|r| ApiError::rejected(r.status(), r.body_text()))?;
    let Json(body) = body.map_err(|r| ApiError::rejected(r.status(), r.body_text()))?;
    let spec = ferritor_core::policy::PolicySpec {
        name,
        identity: body.identity,
        actions: body.actions,
        paths: body.paths,
        all_paths: body.all_paths,
        description: body.description,
    };
    let written = policies.put(&caller, &spec, body.expected_version).await?;
    Ok(Json(WrittenBody {
        version: written.version,
        revision: written.revision,
        created: written.created,
    }))
}

#[derive(Deserialize, Default, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields, default)]
struct DeletePolicyQuery {
    /// Only if it's still at this version.
    expected_version: Option<u32>,
}

#[derive(Serialize, ToSchema)]
struct DeletedBody {
    /// False: there was no such policy.
    deleted: bool,
    revision: u64,
}

/// Delete a stored policy (`policy`; idempotent).
#[utoipa::path(
    delete,
    path = "/v1/policies/{name}",
    operation_id = "deletePolicy",
    tag = "policies",
    params(("name" = String, Path, description = "A stored policy's name (secret-path rules, may contain `/`), or `config:…` for a config rule."), DeletePolicyQuery),
    responses((status = 200, description = "Deleted, or there was none.", body = DeletedBody), (status = "default", description = "An error: see `error.code`.", body = ErrorBody))
)]
async fn delete_policy(
    State(policies): State<Arc<Policies>>,
    extensions: Extensions,
    name: Result<Path<String>, PathRejection>,
    query: Result<Query<DeletePolicyQuery>, QueryRejection>,
) -> Result<Json<DeletedBody>, ApiError> {
    let caller = caller_via(policies.gate(), &extensions, Action::Policy)?;
    let Path(name) = name.map_err(|r| ApiError::rejected(r.status(), r.body_text()))?;
    let Query(query) = query.map_err(|r| ApiError::rejected(r.status(), r.body_text()))?;
    let done = policies
        .delete(&caller, &name, query.expected_version)
        .await?;
    Ok(Json(DeletedBody {
        deleted: done.deleted,
        revision: done.revision,
    }))
}

/// One policy in an apply.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct ApplyPolicy {
    /// Secret-path rules, e.g. `apps/billing-read` (never `config:…`).
    name: String,
    /// The `<name>` of a `ferritor://<name>` identity.
    identity: String,
    #[schema(value_type = Vec<SecretActionName>, min_items = 1)]
    actions: Vec<ferritor_core::policy::SecretAction>,
    /// Path prefixes, whole segments; exactly one of `paths` and
    /// `all_paths`.
    #[serde(default)]
    #[schema(max_items = 64)]
    paths: Vec<String>,
    #[serde(default)]
    all_paths: bool,
    /// What it's for (printable ASCII, newlines and tabs; at most 1 KiB).
    #[serde(default)]
    description: String,
}

impl From<ApplyPolicy> for ferritor_core::policy::PolicySpec {
    fn from(p: ApplyPolicy) -> Self {
        Self {
            name: p.name,
            identity: p.identity,
            actions: p.actions,
            paths: p.paths,
            all_paths: p.all_paths,
            description: p.description,
        }
    }
}

/// The stored set as it should be.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct ApplyBody {
    /// As many as may be stored, so the whole set fits in one apply (at most
    /// 16 MiB in all).
    #[schema(max_items = 10000)]
    policies: Vec<ApplyPolicy>,
    /// Only if the stored set is still at this revision.
    expected_revision: Option<u64>,
    /// Delete every stored policy not listed. The only write allowed over a
    /// stored set that doesn't verify (the repair).
    #[serde(default)]
    prune: bool,
    /// Report what would change; write nothing.
    #[serde(default)]
    dry_run: bool,
}

#[derive(Serialize, ToSchema)]
struct AppliedBody {
    created: Vec<String>,
    updated: Vec<String>,
    deleted: Vec<String>,
    unchanged: Vec<String>,
    /// The revision now (for a dry run: what it would be).
    revision: u64,
    dry_run: bool,
    /// It replaced a stored set that didn't verify.
    replaced_unverified: bool,
    /// It created a new policy key (the old one was missing or didn't open).
    new_policy_key: bool,
}

/// Make the stored set match a list, atomically (`policy`).
///
/// Creates and replaces what's listed, and with `prune` deletes every other
/// stored policy. One invalid policy refuses the whole call.
#[utoipa::path(
    post,
    path = "/v1/policy-apply",
    operation_id = "applyPolicies",
    tag = "policies",
    request_body = ApplyBody,
    responses((status = 200, description = "What changed (or would).", body = AppliedBody), (status = "default", description = "An error: see `error.code`.", body = ErrorBody))
)]
async fn apply_policies(
    State(policies): State<Arc<Policies>>,
    extensions: Extensions,
    body: Result<Json<ApplyBody>, JsonRejection>,
) -> Result<Json<AppliedBody>, ApiError> {
    let caller = caller_via(policies.gate(), &extensions, Action::Policy)?;
    let Json(body) = body.map_err(|r| ApiError::rejected(r.status(), r.body_text()))?;
    let specs: Vec<ferritor_core::policy::PolicySpec> =
        body.policies.into_iter().map(Into::into).collect();
    let done = policies
        .apply(
            &caller,
            &specs,
            body.expected_revision,
            body.prune,
            body.dry_run,
        )
        .await?;
    Ok(Json(AppliedBody {
        created: done.created,
        updated: done.updated,
        deleted: done.deleted,
        unchanged: done.unchanged,
        revision: done.revision,
        dry_run: done.dry_run,
        replaced_unverified: done.replaced_unverified,
        new_policy_key: done.new_policy_key,
    }))
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
struct CheckQuery {
    /// The `<name>` of a `ferritor://<name>` identity.
    identity: String,
    /// Any action name (`read`, `rotate`, …).
    action: String,
    /// For a secret action: the secret or prefix; absent: every secret.
    path: Option<String>,
}

/// Why the stored policies couldn't answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
enum Undecided {
    Sealed,
    Unverified,
}

#[derive(Serialize, ToSchema)]
struct CheckedBody {
    allowed: bool,
    /// The rules that grant it, by name (config rules as `config:…`).
    granted_by: Vec<String>,
    /// False in dev mode: everyone may do everything there, whatever the
    /// rules say.
    enforced: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    undecided: Option<Undecided>,
}

/// Whether an identity may do an action (`policy`).
///
/// With the rules that grant it.
#[utoipa::path(
    get,
    path = "/v1/policy-check",
    operation_id = "checkAccess",
    tag = "policies",
    params(CheckQuery),
    responses((status = 200, description = "The verdict.", body = CheckedBody), (status = "default", description = "An error: see `error.code`.", body = ErrorBody))
)]
async fn check_access(
    State(policies): State<Arc<Policies>>,
    extensions: Extensions,
    query: Result<Query<CheckQuery>, QueryRejection>,
) -> Result<Json<CheckedBody>, ApiError> {
    let caller = caller_via(policies.gate(), &extensions, Action::Policy)?;
    let Query(query) = query.map_err(|r| ApiError::rejected(r.status(), r.body_text()))?;
    let checked = policies
        .check(
            &caller,
            &query.identity,
            &query.action,
            query.path.as_deref(),
        )
        .await?;
    Ok(Json(CheckedBody {
        allowed: checked.allowed,
        granted_by: checked.granted_by,
        enforced: checked.enforced,
        undecided: checked.undecided.map(|why| match why {
            policies::Undecided::Sealed => Undecided::Sealed,
            policies::Undecided::Unverified => Undecided::Unverified,
        }),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addressed(authority: Option<&str>, hosts: &[&str]) -> bool {
        let uri = match authority {
            Some(authority) => format!("http://{authority}/v1/secrets"),
            None => "/v1/secrets".to_owned(),
        };
        let mut request = axum::http::Request::builder().uri(uri);
        for host in hosts {
            request = request.header(header::HOST, *host);
        }
        addressed_to_loopback(&request.body(()).unwrap())
    }

    /// JSON codes come from the reasons: each ambiguous FAILED_PRECONDITION
    /// gets its own code and status.
    /// A rate limit is 429 `rate_limited`, with `Retry-After` in whole
    /// seconds, rounded up (an in-flight slot: 1 s).
    #[test]
    fn a_rate_limit_is_429_with_retry_after() {
        use crate::ratelimit::{Limit, Refused};
        for (refused, after) in [
            (
                Refused {
                    limit: Limit::Rate,
                    retry_after: Some(std::time::Duration::from_millis(1500)),
                },
                "2",
            ),
            (
                Refused {
                    limit: Limit::InFlight,
                    retry_after: None,
                },
                "1",
            ),
        ] {
            let api = ApiError::from(SecretsError::Limited(refused));
            assert_eq!(
                (api.status, api.code),
                (StatusCode::TOO_MANY_REQUESTS, ErrorCode::RateLimited)
            );
            let response = api.into_response();
            assert_eq!(response.headers()[header::RETRY_AFTER], after);
        }
    }

    #[test]
    fn reasons_become_json_codes() {
        use ferritor_core::path::SecretPath;

        let path = SecretPath::parse("app/db").unwrap();
        let cases = [
            (
                SecretsError::UnknownKek(3),
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::UnknownKek,
            ),
            (
                SecretsError::Sealed,
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::Sealed,
            ),
            (
                SecretsError::VersionMismatch {
                    path: path.clone(),
                    expected: 1,
                    latest: None,
                },
                StatusCode::CONFLICT,
                ErrorCode::VersionMismatch,
            ),
            (
                SecretsError::LiveVersion {
                    path: path.clone(),
                    latest: 2,
                },
                StatusCode::CONFLICT,
                ErrorCode::LiveVersion,
            ),
            (
                SecretsError::Busy(path),
                StatusCode::CONFLICT,
                ErrorCode::Busy,
            ),
            (
                SecretsError::NoNamespace(ferritor_core::path::Namespace::parse("app").unwrap()),
                StatusCode::CONFLICT,
                ErrorCode::NoNamespace,
            ),
        ];
        for (error, status, code) in cases {
            let api = ApiError::from(error);
            assert_eq!((api.status, api.code), (status, code));
        }
    }

    /// `docs/openapi.json` is what the code describes: regenerate it with
    /// `FERRITOR_UPDATE_OPENAPI=1 cargo test -p ferritor-server --lib openapi`.
    #[test]
    fn the_openapi_file_is_current() {
        let spec = openapi().to_pretty_json().unwrap() + "\n";
        let file = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/openapi.json");
        if std::env::var_os("FERRITOR_UPDATE_OPENAPI").is_some() {
            std::fs::write(file, &spec).unwrap();
            return;
        }
        let committed = std::fs::read_to_string(file).unwrap_or_default();
        assert!(
            committed == spec,
            "docs/openapi.json is out of date: regenerate it with \
             `FERRITOR_UPDATE_OPENAPI=1 cargo test -p ferritor-server --lib openapi`"
        );
    }

    /// The policy bodies deserialize core's `SecretAction`, documented by
    /// `SecretActionName`: the two must name the same actions.
    #[test]
    fn the_openapi_action_schema_names_every_secret_action() {
        let spec = serde_json::to_value(openapi()).unwrap();
        let documented = &spec["components"]["schemas"]["SecretActionName"]["enum"];
        let actions: Vec<&str> = ferritor_core::policy::SecretAction::ALL
            .iter()
            .map(|a| a.name())
            .collect();
        assert_eq!(documented, &serde_json::json!(actions));
    }

    /// The limits the description states are the server's: `max_items` takes
    /// only a literal, and the prose none at all, so a constant changed
    /// without them fails here (the staleness test only compares the file
    /// with the code).
    #[test]
    fn the_openapi_limits_are_the_servers() {
        use ferritor_core::policy::{MAX_APPLY, MAX_APPLY_BYTES, MAX_DESCRIPTION, MAX_PATHS};
        const MIB: usize = 1024 * 1024;
        let spec = serde_json::to_value(openapi()).unwrap();
        let schemas = &spec["components"]["schemas"];
        let says = |field: &serde_json::Value, wanted: &str| {
            let text = field["description"].as_str().unwrap_or_default();
            assert!(text.contains(wanted), "{text:?} should say {wanted:?}");
        };
        let query = |path: &str, name: &str| {
            spec["paths"][path]["get"]["parameters"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|p| p["name"] == name)
                .cloned()
                .unwrap_or_default()
        };

        for body in ["PutPolicyBody", "ApplyPolicy"] {
            let fields = &schemas[body]["properties"];
            assert_eq!(fields["paths"]["maxItems"], MAX_PATHS, "{body}.paths");
            assert_eq!(MAX_DESCRIPTION % 1024, 0, "described in whole KiB");
            says(
                &fields["description"],
                &format!("{} KiB", MAX_DESCRIPTION / 1024),
            );
        }
        let apply = &schemas["ApplyBody"]["properties"]["policies"];
        assert_eq!(apply["maxItems"], MAX_APPLY);
        assert_eq!(MAX_APPLY_BYTES % MIB, 0, "described in whole MiB");
        says(apply, &format!("{} MiB", MAX_APPLY_BYTES / MIB));

        assert_eq!(MAX_VALUE_SIZE % MIB, 0, "described in whole MiB");
        says(
            &schemas["WriteBody"]["properties"]["value"],
            &format!("{} MiB", MAX_VALUE_SIZE / MIB),
        );

        let secrets_pages = format!(
            "0 or absent: {}; capped at {}",
            crate::secrets::DEFAULT_PAGE_SIZE,
            crate::secrets::MAX_PAGE_SIZE
        );
        says(&query("/v1/secrets", "page_size"), &secrets_pages);
        says(&query("/v1/versions/{path}", "page_size"), &secrets_pages);
        let policy_pages = format!(
            "0 or absent: {}; capped at {}",
            policies::DEFAULT_PAGE_SIZE,
            policies::MAX_PAGE_SIZE
        );
        says(&query("/v1/policies", "page_size"), &policy_pages);
    }

    #[test]
    fn only_loopback_names_pass() {
        for host in [
            "localhost",
            "LocalHost:7070",
            "127.0.0.1",
            "127.0.0.1:7070",
            "[::1]",
            "[::1]:7070",
            // Wherever dev mode may listen (`config::ensure_loopback`).
            "127.0.0.2",
            "127.255.0.9:7070",
            "[::ffff:127.0.0.1]:7070",
        ] {
            assert!(addressed(None, &[host]), "Host: {host}");
            assert!(addressed(Some(host), &[]), ":authority {host}");
        }
        for host in [
            "attacker.example",
            "attacker.example:7070",
            "localhost.attacker.example",
            "0.0.0.0",
            "128.0.0.1",
            "[::2]",
            "[::ffff:10.0.0.1]",
            // Not a bracketed literal: no IPv6 without `[ ]`.
            "[::1",
            "",
            "local host",
        ] {
            assert!(!addressed(None, &[host]), "Host: {host}");
        }
        // Nothing to go by, or any of several names foreign.
        assert!(!addressed(None, &[]));
        assert!(!addressed(None, &["localhost", "attacker.example"]));
        assert!(!addressed(Some("attacker.example:7070"), &["localhost"]));
        assert!(!addressed(Some("localhost:7070"), &["attacker.example"]));
    }
}
