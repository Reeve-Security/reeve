//! Paginated client for the official MCP Registry API.
//!
//! The official endpoint is `GET https://registry.modelcontextprotocol.io/v0.1/servers`.
//! It returns `{ "servers": [...], "metadata": { "nextCursor": <id>|null, "count": <n> } }`.
//! Pagination follows `metadata.nextCursor` via `?cursor=<value>` and stops when the
//! cursor is null, absent, or empty.
//!
//! The paginator is split from its transport via [`PageFetcher`] so tests can inject
//! fixture pages and a scripted rate-limit sequence with zero network traffic. Live
//! network only runs through [`HttpPageFetcher`], which is wired into the
//! `mcp-registry-fetch` CLI subcommand.

use std::time::Duration;

use aibom_core::{canonicalize_json, sha256_hex};
use serde_json::{Value, json};

/// Honest User-Agent sent on live registry requests.
const USER_AGENT: &str = "Reeve MCP registry fetcher (https://github.com/Reeve-Security)";

/// Errors surfaced while paginating the registry.
#[derive(Debug)]
pub enum PaginationError {
    /// A transport-level failure (DNS, TLS, connection, non-retryable status).
    Transport(String),
    /// The response body was not valid JSON.
    Parse(String),
    /// The response JSON was missing a required field.
    Shape(String),
    /// Rate limiting persisted past `max_retries`.
    RateLimitExhausted { url: String, attempts: u32 },
    /// Canonicalizing the merged output failed.
    Canonicalization(String),
}

impl std::fmt::Display for PaginationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PaginationError::Transport(message) => write!(f, "registry transport error: {message}"),
            PaginationError::Parse(message) => {
                write!(f, "registry response parse error: {message}")
            }
            PaginationError::Shape(message) => {
                write!(f, "registry response shape error: {message}")
            }
            PaginationError::RateLimitExhausted { url, attempts } => write!(
                f,
                "registry rate limit not cleared after {attempts} retries for {url}"
            ),
            PaginationError::Canonicalization(message) => {
                write!(f, "merged registry canonicalization error: {message}")
            }
        }
    }
}

impl std::error::Error for PaginationError {}

/// Outcome of fetching a single URL.
pub enum FetchOutcome {
    /// A successful 2xx response with the raw body bytes.
    Body(Vec<u8>),
    /// A 429 response, with the parsed `Retry-After` delay when present.
    RateLimited { retry_after: Option<Duration> },
}

/// Transport abstraction so the paginator can be driven from fixtures in tests.
pub trait PageFetcher {
    fn fetch(&self, url: &str) -> Result<FetchOutcome, PaginationError>;
}

/// Live blocking HTTP fetcher against the real registry.
pub struct HttpPageFetcher {
    client: reqwest::blocking::Client,
}

impl HttpPageFetcher {
    pub fn new() -> Result<Self, PaginationError> {
        let client = reqwest::blocking::Client::builder()
            .user_agent(USER_AGENT)
            // Bounded so a stalled registry cannot hang a scheduled pull forever.
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|error| PaginationError::Transport(error.to_string()))?;
        Ok(Self { client })
    }
}

impl PageFetcher for HttpPageFetcher {
    fn fetch(&self, url: &str) -> Result<FetchOutcome, PaginationError> {
        let response = self
            .client
            .get(url)
            .send()
            .map_err(|error| PaginationError::Transport(error.to_string()))?;
        let status = response.status();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let retry_after = parse_retry_after(
                response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok()),
            );
            return Ok(FetchOutcome::RateLimited { retry_after });
        }
        if !status.is_success() {
            return Err(PaginationError::Transport(format!(
                "unexpected status {status} for {url}"
            )));
        }
        let bytes = response
            .bytes()
            .map_err(|error| PaginationError::Transport(error.to_string()))?;
        Ok(FetchOutcome::Body(bytes.to_vec()))
    }
}

/// Parse the `Retry-After` header value as a seconds count.
///
/// Only the delta-seconds form is handled; HTTP-date forms yield `None`, falling
/// back to the configured backoff.
fn parse_retry_after(raw: Option<&str>) -> Option<Duration> {
    raw.and_then(|value| value.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

/// Inputs governing a pagination run.
pub struct PaginatorConfig {
    pub base_url: String,
    pub limit: u32,
    pub updated_since: Option<String>,
    pub max_retries: u32,
    pub backoff_base: Duration,
}

/// One raw page exactly as fetched, with its content hash for provenance.
#[derive(Debug)]
pub struct RawPage {
    pub url: String,
    pub cursor: Option<String>,
    pub bytes: Vec<u8>,
    pub sha256: String,
}

/// The full result of paginating the registry.
#[derive(Debug)]
pub struct PaginationResult {
    pub pages: Vec<RawPage>,
    pub servers: Vec<Value>,
    /// `{"servers": [...], "metadata": {"count": <n>}}`, deterministic via JCS.
    pub merged: Value,
}

/// Build the request URL for one page, URL-encoding query parameters correctly.
///
/// The cursor contains `/` and `:` and MUST be percent-encoded; `Url::parse_with_params`
/// handles this rather than naive string concatenation.
fn build_page_url(cfg: &PaginatorConfig, cursor: Option<&str>) -> Result<String, PaginationError> {
    let limit = cfg.limit.to_string();
    let mut params: Vec<(&str, &str)> = vec![("limit", limit.as_str())];
    if let Some(updated_since) = cfg.updated_since.as_deref() {
        params.push(("updated_since", updated_since));
    }
    if let Some(cursor) = cursor {
        params.push(("cursor", cursor));
    }
    let url = reqwest::Url::parse_with_params(&cfg.base_url, &params)
        .map_err(|error| PaginationError::Transport(error.to_string()))?;
    Ok(url.to_string())
}

/// Read `metadata.nextCursor`, normalizing null / absent / empty to `None`.
fn next_cursor(page: &Value) -> Option<String> {
    page.pointer("/metadata/nextCursor")
        .and_then(Value::as_str)
        .filter(|cursor| !cursor.is_empty())
        .map(ToString::to_string)
}

/// Fetch one URL, transparently retrying past rate limits with exponential backoff.
///
/// `sleep` is injected so tests observe requested delays without waiting. Backoff
/// doubles each retry from `backoff_base`; a `Retry-After` header overrides the
/// computed backoff for that attempt. Exceeding `max_retries` is an error.
fn fetch_with_retry(
    cfg: &PaginatorConfig,
    fetcher: &dyn PageFetcher,
    sleep: &dyn Fn(Duration),
    url: &str,
) -> Result<Vec<u8>, PaginationError> {
    let mut attempt = 0u32;
    loop {
        match fetcher.fetch(url)? {
            FetchOutcome::Body(bytes) => return Ok(bytes),
            FetchOutcome::RateLimited { retry_after } => {
                if attempt >= cfg.max_retries {
                    return Err(PaginationError::RateLimitExhausted {
                        url: url.to_string(),
                        attempts: cfg.max_retries,
                    });
                }
                let backoff = cfg.backoff_base.saturating_mul(1u32 << attempt.min(16));
                sleep(retry_after.unwrap_or(backoff));
                attempt += 1;
            }
        }
    }
}

/// Politeness delay between successful page fetches.
const POLITENESS_GAP: Duration = Duration::from_millis(250);

/// Paginate the registry, following `nextCursor` until it is null/absent/empty.
///
/// `sleep` is injected so tests run with a no-op closure and real callers pass
/// [`std::thread::sleep`].
pub fn fetch_all(
    cfg: PaginatorConfig,
    fetcher: &dyn PageFetcher,
    sleep: &dyn Fn(Duration),
) -> Result<PaginationResult, PaginationError> {
    let mut pages = Vec::new();
    let mut servers = Vec::new();
    let mut cursor: Option<String> = None;

    loop {
        let url = build_page_url(&cfg, cursor.as_deref())?;
        let bytes = fetch_with_retry(&cfg, fetcher, sleep, &url)?;
        let page: Value = serde_json::from_slice(&bytes)
            .map_err(|error| PaginationError::Parse(error.to_string()))?;

        let page_servers = page
            .get("servers")
            .and_then(Value::as_array)
            .ok_or_else(|| PaginationError::Shape(format!("page {url} missing servers array")))?;
        servers.extend(page_servers.iter().cloned());

        pages.push(RawPage {
            url: url.clone(),
            cursor: cursor.clone(),
            sha256: sha256_hex(&bytes),
            bytes,
        });

        match next_cursor(&page) {
            Some(next) => {
                sleep(POLITENESS_GAP);
                cursor = Some(next);
            }
            None => break,
        }
    }

    let merged = json!({
        "servers": Value::Array(servers.clone()),
        "metadata": { "count": servers.len() }
    });
    // Surface canonicalization failures eagerly so callers writing `merged` to disk
    // can rely on it being JCS-stable.
    canonicalize_json(&merged)
        .map_err(|error| PaginationError::Canonicalization(error.to_string()))?;

    Ok(PaginationResult {
        pages,
        servers,
        merged,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    const PAGE_1: &[u8] = include_bytes!("../tests/data/mcp-registry/pagination/page-1.json");
    const PAGE_2: &[u8] = include_bytes!("../tests/data/mcp-registry/pagination/page-2.json");
    const PAGE_EMPTY: &[u8] =
        include_bytes!("../tests/data/mcp-registry/pagination/page-empty.json");

    /// One scripted response for a URL: either a body or a rate-limit (consumed in order).
    enum Scripted {
        Body(Vec<u8>),
        RateLimited(Option<Duration>),
    }

    /// Fixture fetcher mapping URL substrings to a queue of scripted responses.
    ///
    /// Matching is by the cursor query value (or "page-1" for the cursorless first
    /// request) so tests do not depend on exact percent-encoding of the URL.
    struct FixturePageFetcher {
        // key -> queue of responses (front consumed first)
        scripts: RefCell<HashMap<String, Vec<Scripted>>>,
        // every URL the paginator requested, in order
        requested: RefCell<Vec<String>>,
    }

    impl FixturePageFetcher {
        fn new() -> Self {
            Self {
                scripts: RefCell::new(HashMap::new()),
                requested: RefCell::new(Vec::new()),
            }
        }

        fn script(mut self, key: &str, responses: Vec<Scripted>) -> Self {
            self.scripts.get_mut().insert(key.to_string(), responses);
            self
        }

        /// Derive the routing key from a URL: the cursor value if present, else "page-1".
        fn key_for(url: &str) -> String {
            let parsed = reqwest::Url::parse(url).expect("paginator built an invalid url");
            parsed
                .query_pairs()
                .find(|(name, _)| name == "cursor")
                .map(|(_, value)| value.into_owned())
                .unwrap_or_else(|| "page-1".to_string())
        }
    }

    impl PageFetcher for FixturePageFetcher {
        fn fetch(&self, url: &str) -> Result<FetchOutcome, PaginationError> {
            self.requested.borrow_mut().push(url.to_string());
            let key = Self::key_for(url);
            let mut scripts = self.scripts.borrow_mut();
            let queue = scripts
                .get_mut(&key)
                .unwrap_or_else(|| panic!("no scripted response for key {key} (url {url})"));
            assert!(
                !queue.is_empty(),
                "scripted responses for key {key} exhausted"
            );
            match queue.remove(0) {
                Scripted::Body(bytes) => Ok(FetchOutcome::Body(bytes)),
                Scripted::RateLimited(retry_after) => Ok(FetchOutcome::RateLimited { retry_after }),
            }
        }
    }

    fn cfg() -> PaginatorConfig {
        PaginatorConfig {
            base_url: "https://registry.modelcontextprotocol.io/v0.1/servers".to_string(),
            limit: 100,
            updated_since: None,
            max_retries: 3,
            backoff_base: Duration::from_millis(100),
        }
    }

    fn no_sleep() -> impl Fn(Duration) {
        |_| {}
    }

    /// 1. Multi-page: page-1 -> page-2 -> page-empty, stops on null cursor.
    #[test]
    fn collects_all_pages_until_null_cursor() {
        // page-1 nextCursor -> "ac.inference.sh/mcp:1.0.1"
        // page-2 nextCursor -> "ac.tandem/docs-mcp:0.3.1"
        // page-empty nextCursor -> null
        let fetcher = FixturePageFetcher::new()
            .script("page-1", vec![Scripted::Body(PAGE_1.to_vec())])
            .script(
                "ac.inference.sh/mcp:1.0.1",
                vec![Scripted::Body(PAGE_2.to_vec())],
            )
            .script(
                "ac.tandem/docs-mcp:0.3.1",
                vec![Scripted::Body(PAGE_EMPTY.to_vec())],
            );

        let result = fetch_all(cfg(), &fetcher, &no_sleep()).expect("pagination succeeds");

        assert_eq!(result.pages.len(), 3, "three pages fetched");
        assert_eq!(result.servers.len(), 4, "2 + 2 + 0 servers collected");
        assert_eq!(
            result.merged["metadata"]["count"]
                .as_u64()
                .expect("count present"),
            4
        );
        // Cursors recorded per page: None, then page-1's cursor, then page-2's cursor.
        assert_eq!(result.pages[0].cursor, None);
        assert_eq!(
            result.pages[1].cursor.as_deref(),
            Some("ac.inference.sh/mcp:1.0.1")
        );
        assert_eq!(
            result.pages[2].cursor.as_deref(),
            Some("ac.tandem/docs-mcp:0.3.1")
        );
    }

    /// 2. updated_since + cursor are both present (and encoded) on the 2nd request.
    #[test]
    fn updated_since_and_cursor_appear_together() {
        let mut config = cfg();
        config.updated_since = Some("2026-04-01T00:00:00Z".to_string());

        let fetcher = FixturePageFetcher::new()
            .script("page-1", vec![Scripted::Body(PAGE_1.to_vec())])
            .script(
                "ac.inference.sh/mcp:1.0.1",
                vec![Scripted::Body(PAGE_EMPTY.to_vec())],
            );

        fetch_all(config, &fetcher, &no_sleep()).expect("pagination succeeds");

        let requested = fetcher.requested.borrow();
        assert_eq!(requested.len(), 2, "two requests issued");
        let second = &requested[1];
        // updated_since present on both; cursor only on the second, properly encoded.
        assert!(
            second.contains("updated_since=2026-04-01T00%3A00%3A00Z"),
            "second url should carry encoded updated_since: {second}"
        );
        assert!(
            second.contains("cursor=ac.inference.sh%2Fmcp%3A1.0.1"),
            "second url should carry the encoded cursor: {second}"
        );
        // First request carries updated_since but no cursor.
        assert!(requested[0].contains("updated_since="));
        assert!(!requested[0].contains("cursor="));
    }

    /// 3. Null/missing nextCursor stops the loop without looping forever.
    #[test]
    fn null_cursor_terminates_loop() {
        let fetcher =
            FixturePageFetcher::new().script("page-1", vec![Scripted::Body(PAGE_EMPTY.to_vec())]);
        let result = fetch_all(cfg(), &fetcher, &no_sleep()).expect("pagination succeeds");
        assert_eq!(result.pages.len(), 1);
        assert!(result.servers.is_empty());
    }

    /// 4a. 429 then success: the injected sleep observes the ~2s Retry-After delay.
    #[test]
    fn retries_after_rate_limit_and_records_delay() {
        let fetcher = FixturePageFetcher::new().script(
            "page-1",
            vec![
                Scripted::RateLimited(Some(Duration::from_secs(2))),
                Scripted::Body(PAGE_EMPTY.to_vec()),
            ],
        );

        let slept: RefCell<Vec<Duration>> = RefCell::new(Vec::new());
        let sleep = |delay: Duration| slept.borrow_mut().push(delay);

        let result = fetch_all(cfg(), &fetcher, &sleep).expect("pagination succeeds after retry");
        assert_eq!(result.pages.len(), 1, "page ultimately fetched");

        let delays = slept.borrow();
        assert_eq!(delays.len(), 1, "slept once for the rate limit");
        assert_eq!(delays[0], Duration::from_secs(2), "honored Retry-After");
    }

    /// 4b. Exceeding max_retries returns a RateLimitExhausted error.
    #[test]
    fn exceeding_max_retries_errors() {
        let mut config = cfg();
        config.max_retries = 2;
        let fetcher = FixturePageFetcher::new().script(
            "page-1",
            vec![
                Scripted::RateLimited(None),
                Scripted::RateLimited(None),
                Scripted::RateLimited(None),
            ],
        );

        let err = fetch_all(config, &fetcher, &no_sleep())
            .expect_err("rate limit should exhaust retries");
        match err {
            PaginationError::RateLimitExhausted { attempts, .. } => assert_eq!(attempts, 2),
            other => panic!("expected RateLimitExhausted, got {other}"),
        }
    }

    /// 4c. Backoff with no Retry-After is exponential from backoff_base.
    #[test]
    fn rate_limit_backoff_is_exponential() {
        let mut config = cfg();
        config.max_retries = 3;
        config.backoff_base = Duration::from_millis(100);
        let fetcher = FixturePageFetcher::new().script(
            "page-1",
            vec![
                Scripted::RateLimited(None),
                Scripted::RateLimited(None),
                Scripted::Body(PAGE_EMPTY.to_vec()),
            ],
        );

        let slept: RefCell<Vec<Duration>> = RefCell::new(Vec::new());
        let sleep = |delay: Duration| slept.borrow_mut().push(delay);

        fetch_all(config, &fetcher, &sleep).expect("succeeds after backoff");
        let delays = slept.borrow();
        assert_eq!(delays.len(), 2);
        assert_eq!(delays[0], Duration::from_millis(100));
        assert_eq!(delays[1], Duration::from_millis(200));
    }

    /// 5. Raw page sha matches sha256_hex(bytes) and is deterministic across runs.
    #[test]
    fn raw_page_sha_matches_and_is_deterministic() {
        let build = || {
            FixturePageFetcher::new()
                .script("page-1", vec![Scripted::Body(PAGE_1.to_vec())])
                .script(
                    "ac.inference.sh/mcp:1.0.1",
                    vec![Scripted::Body(PAGE_EMPTY.to_vec())],
                )
        };

        let first = fetch_all(cfg(), &build(), &no_sleep()).expect("first run");
        for page in &first.pages {
            assert_eq!(page.sha256, sha256_hex(&page.bytes));
        }
        let second = fetch_all(cfg(), &build(), &no_sleep()).expect("second run");
        let first_shas: Vec<_> = first.pages.iter().map(|p| p.sha256.clone()).collect();
        let second_shas: Vec<_> = second.pages.iter().map(|p| p.sha256.clone()).collect();
        assert_eq!(first_shas, second_shas, "page shas are deterministic");
    }

    /// 6. Merged output is byte-deterministic via canonicalize_json across runs.
    #[test]
    fn merged_output_is_deterministic() {
        let build = || {
            FixturePageFetcher::new()
                .script("page-1", vec![Scripted::Body(PAGE_1.to_vec())])
                .script(
                    "ac.inference.sh/mcp:1.0.1",
                    vec![Scripted::Body(PAGE_2.to_vec())],
                )
                .script(
                    "ac.tandem/docs-mcp:0.3.1",
                    vec![Scripted::Body(PAGE_EMPTY.to_vec())],
                )
        };

        let first = fetch_all(cfg(), &build(), &no_sleep()).expect("first run");
        let second = fetch_all(cfg(), &build(), &no_sleep()).expect("second run");
        let first_bytes = canonicalize_json(&first.merged).expect("canon first");
        let second_bytes = canonicalize_json(&second.merged).expect("canon second");
        assert_eq!(first_bytes, second_bytes, "merged JCS bytes are identical");
        // Shaped to feed the existing normalizer: top-level servers array.
        assert!(
            first
                .merged
                .get("servers")
                .and_then(Value::as_array)
                .is_some()
        );
    }

    /// 7. A lone empty page yields Ok with zero servers and `servers: []` in merged.
    #[test]
    fn empty_page_yields_empty_result() {
        let fetcher =
            FixturePageFetcher::new().script("page-1", vec![Scripted::Body(PAGE_EMPTY.to_vec())]);
        let result = fetch_all(cfg(), &fetcher, &no_sleep()).expect("empty page is ok");
        assert_eq!(result.servers.len(), 0);
        assert_eq!(
            result.merged["servers"]
                .as_array()
                .expect("servers array present")
                .len(),
            0
        );
        assert_eq!(result.merged["metadata"]["count"].as_u64(), Some(0));
    }
}
