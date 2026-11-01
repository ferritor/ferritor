//! Waiting out a short rate limit: a call the server refused as
//! `RATE_LIMITED` with a retry time of at most [`MAX_WAIT`] is sent once
//! more after that time. Safe for every call, writes included: a rate-limited
//! request is refused before anything runs. A longer wait, or a second
//! refusal, goes to the caller, as a [`crate::ServerError`] with the limit
//! and the retry time.
//!
//! A layer under the generated clients, so every call gets it; the request
//! body is buffered to be sent again (calls are unary, and small).

use std::task::{Context, Poll};
use std::time::Duration;

use ferritor_core::messages::{self, reason};
use http_body_util::{BodyExt, Full};
use tonic::Status;
use tonic::body::Body;
use tonic::codegen::{BoxFuture, Service, StdError, http};
use tonic_types::StatusExt;

/// The longest wait worth sitting through; longer, the caller decides (the
/// CLI says when to retry).
pub const MAX_WAIT: Duration = Duration::from_secs(3);

/// Told before each wait: the limit that refused the call (`rate`,
/// `in_flight`, `denied`) and how long the wait is. The library writes
/// nothing itself: the CLI prints it, the agent logs it.
pub type WaitNotice = fn(limit: &str, wait: Duration);

#[derive(Clone, Debug)]
pub struct Retrying<S> {
    inner: S,
    notice: Option<WaitNotice>,
}

impl<S> Retrying<S> {
    pub fn new(inner: S, notice: Option<WaitNotice>) -> Self {
        Self { inner, notice }
    }
}

impl<S> Service<http::Request<Body>> for Retrying<S>
where
    S: Service<http::Request<Body>, Response = http::Response<Body>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Into<StdError>,
{
    type Response = http::Response<Body>;
    type Error = StdError;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        // The service polled ready makes the first call (tower's rule); a
        // fresh clone takes its place.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let notice = self.notice;
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let bytes = body.collect().await?.to_bytes();
            let request =
                |bytes| http::Request::from_parts(parts.clone(), Body::new(Full::new(bytes)));
            let response = inner
                .call(request(bytes.clone()))
                .await
                .map_err(Into::into)?;
            let Some((limit, wait)) = short_rate_limit(&response) else {
                return Ok(response);
            };
            if let Some(notice) = notice {
                notice(&limit, wait);
            }
            tokio::time::sleep(wait).await;
            std::future::poll_fn(|cx| inner.poll_ready(cx))
                .await
                .map_err(Into::into)?;
            inner.call(request(bytes)).await.map_err(Into::into)
        })
    }
}

/// The limit and the wait, if `response` is a `RATE_LIMITED` refusal worth
/// waiting out. Refusals come trailers-only (the status in the headers),
/// so the body needn't be read.
fn short_rate_limit(response: &http::Response<Body>) -> Option<(String, Duration)> {
    let details = Status::from_header_map(response.headers())?.get_error_details();
    let info = details
        .error_info()
        .filter(|info| info.domain == messages::DOMAIN && info.reason == reason::RATE_LIMITED)?;
    let wait = details.retry_info()?.retry_delay?;
    let limit = info.metadata.get("limit").cloned().unwrap_or_default();
    (wait <= MAX_WAIT).then_some((limit, wait))
}
