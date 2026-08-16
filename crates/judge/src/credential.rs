//! Credential and endpoint resolution (plan D3, FR-411 through FR-415).
//!
//! # Why this file is longer than "read three environment variables"
//!
//! Several Anthropic credentials are commonly set at once, with a proxy endpoint. That is the **normal**
//! case rather than the edge case, because tools export their own and nothing cleans up after them. A real
//! Claude Code session, values never read:
//!
//! ```text
//! SET    ANTHROPIC_AUTH_TOKEN
//! SET    ANTHROPIC_API_KEY
//! SET    ANTHROPIC_BASE_URL
//! unset  CLAUDE_CODE_OAUTH_TOKEN
//! ```
//!
//! Two credentials live at once, they want different headers, and there is a non-default endpoint. So "use
//! whichever is set" does not resolve.
//!
//! # Picking wrong is a disclosure bug, not a compatibility bug
//!
//! `ANTHROPIC_AUTH_TOKEN` is first not because it is likelier to work but because the alternative sends the
//! wrong secret to the wrong host. In the session above, ordering `ANTHROPIC_API_KEY` first would take a
//! real Anthropic API key and send it as `x-api-key` to whatever `ANTHROPIC_BASE_URL` points at. A proxy the
//! user trusts to relay a *proxy token* has not thereby been trusted with their *upstream account
//! credential*, and the two are not interchangeable just because both authenticate.
//!
//! So the order encodes a preference for the **most specifically-scoped** credential available, and the
//! consequence of getting it wrong is disclosure rather than a 401.
//!
//! # Why the order is unconditional
//!
//! The tempting refinement is to prefer `ANTHROPIC_AUTH_TOKEN` *when `ANTHROPIC_BASE_URL` is also set*,
//! since together they describe a proxy. It reads well and it has a hole:
//!
//! | `AUTH_TOKEN` | `BASE_URL` | conditional rule | unconditional rule |
//! |---|---|---|---|
//! | set | set | use it | use it |
//! | set | unset | **falls through** | use it |
//! | set | unset, nothing else | **no credential at all** | use it |
//!
//! The third row is the hole: someone who exports one variable and expects it to be used gets a tool
//! claiming to be unauthenticated while holding a token. Avoiding that needs a fallback to `AUTH_TOKEN`
//! anyway, at which point the conditional rule has collapsed into the unconditional one everywhere except
//! row two — a bearer token with the default Anthropic endpoint, which is a credential going where it
//! belongs and costs at worst a 401 that [`Resolution::describe`] explains in one line.
//!
//! **Predictable beats clever for credential selection.** Unsetting a variable you do not want used is a
//! normal expectation; a tool silently declining to use one is not.

use std::fmt;

/// Environment variables consulted, in resolution order.
pub const AUTH_TOKEN: &str = "ANTHROPIC_AUTH_TOKEN";
pub const OAUTH_TOKEN: &str = "CLAUDE_CODE_OAUTH_TOKEN";
pub const API_KEY: &str = "ANTHROPIC_API_KEY";
pub const BASE_URL: &str = "ANTHROPIC_BASE_URL";
pub const MODEL: &str = "ANTHROPIC_MODEL";

/// Where a request goes when `ANTHROPIC_BASE_URL` says nothing.
pub const DEFAULT_ENDPOINT: &str = "https://api.anthropic.com";

/// The model used when `ANTHROPIC_MODEL` says nothing.
///
/// Pinned rather than "latest" because the resolved id is recorded in every judged verdict (FR-416, R3): a
/// verdict judged by one model is not evidence about another, and an alias that silently moves would make
/// old verdicts unattributable without anything appearing to change.
pub const DEFAULT_MODEL: &str = "claude-sonnet-4-5";

/// The API version header, sent on every request.
pub const API_VERSION: &str = "2023-06-01";

/// Which variable supplied a credential. **The only part that may ever be displayed.**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialSource {
    AuthToken,
    OauthToken,
    ApiKey,
}

impl CredentialSource {
    /// Resolution order, first match wins, unconditionally (FR-411, plan D3).
    pub const ORDER: [CredentialSource; 3] = [Self::AuthToken, Self::OauthToken, Self::ApiKey];

    pub fn variable(&self) -> &'static str {
        match self {
            Self::AuthToken => AUTH_TOKEN,
            Self::OauthToken => OAUTH_TOKEN,
            Self::ApiKey => API_KEY,
        }
    }

    /// The header this credential is sent in.
    ///
    /// A property of the *source*, not a choice made at request time. A bearer token in an `x-api-key`
    /// header is a 401 at best; deriving the header from the variable makes the pairing impossible to get
    /// wrong somewhere else.
    pub fn header(&self) -> &'static str {
        match self {
            Self::AuthToken | Self::OauthToken => "authorization",
            Self::ApiKey => "x-api-key",
        }
    }

    /// Whether the header value is prefixed with `Bearer `.
    pub fn is_bearer(&self) -> bool {
        matches!(self, Self::AuthToken | Self::OauthToken)
    }

    fn describe_header(&self) -> &'static str {
        match self {
            Self::AuthToken | Self::OauthToken => "Authorization: Bearer",
            Self::ApiKey => "x-api-key",
        }
    }
}

/// A resolved credential: the variable it came from, and a value that cannot be printed.
///
/// # The value is unreachable by every ordinary route
///
/// No `Display`. No `Serialize`. No public accessor. A hand-written [`fmt::Debug`] that prints the source
/// and nothing else — the same technique `Provenance` uses, and for the same reason: a **derived** `Debug`
/// on a credential is one `{:?}` away from a leak, and the `{:?}` will be added by someone debugging at 2am
/// who is not thinking about FR-413 at the time.
///
/// The one route in is [`Credential::header_value`], which exists because the request has to be built. It
/// is `pub(crate)`, so the value cannot leave this crate except inside an HTTP header.
#[derive(Clone)]
pub struct Credential {
    source: CredentialSource,
    // Read only by `header_value`, which is unused until T034 builds the request. See the note there.
    #[allow(dead_code)]
    value: String,
}

impl Credential {
    pub fn source(&self) -> CredentialSource {
        self.source
    }

    /// The header value to send. `pub(crate)` — the value's only exit.
    // Unused until T034 builds the request. Marked rather than left to warn, because a `-D warnings` build
    // that is red for a whole phase is a build people learn to run with `--cap-lints`. **Remove this
    // attribute when T034 lands**: if it survives past that, the credential is being resolved and never
    // sent, which is a bug that would otherwise present as a 401.
    #[allow(dead_code)]
    pub(crate) fn header_value(&self) -> String {
        if self.source.is_bearer() {
            format!("Bearer {}", self.value)
        } else {
            self.value.clone()
        }
    }
}

/// Prints the source. **Never the value** (FR-413, SC-404).
impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Not `f.debug_struct(..).field("value", &"<redacted>")` — that shape invites someone to "improve"
        // it later by showing a prefix, and a prefix of a secret is a secret. There is no field here to
        // fill in.
        write!(f, "Credential(from {})", self.source.variable())
    }
}

/// A variable that was set and passed over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ignored {
    pub source: CredentialSource,
    /// `false` when the variable was not set at all — reported so `--check` can list every variable it
    /// consulted rather than only the ones that happened to exist. "Why is it using that one" is a
    /// question about the whole list.
    pub was_set: bool,
}

/// The outcome of consulting the environment, computed **without making a request** (FR-414).
#[derive(Debug, Clone)]
pub struct Resolution {
    selected: Option<Credential>,
    ignored: Vec<Ignored>,
    endpoint: String,
    endpoint_from_env: bool,
    model: String,
    model_from_env: bool,
    warnings: Vec<String>,
}

impl Resolution {
    /// Resolve from the process environment.
    pub fn from_env() -> Self {
        Self::resolve(|name| std::env::var(name).ok())
    }

    /// Resolve from an arbitrary lookup.
    ///
    /// The real work, taking a closure so tests never touch the process environment. That is not only
    /// tidiness: `std::env::set_var` mutates state shared by every thread in the test binary, so a suite
    /// that sets variables to test precedence is a suite whose results depend on scheduling. The variable
    /// combinations in `tests/credential_resolution.rs` are exactly what must be deterministic.
    pub fn resolve(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let present: Vec<(CredentialSource, Option<String>)> = CredentialSource::ORDER
            .iter()
            .map(|source| {
                // An empty variable is treated as unset. `FOO=` is how a shell unsets something it cannot
                // `unset`, and sending an empty bearer token produces a 401 whose cause is invisible.
                let value = lookup(source.variable()).filter(|v| !v.trim().is_empty());
                (*source, value)
            })
            .collect();

        let mut selected: Option<Credential> = None;
        let mut ignored: Vec<Ignored> = Vec::new();
        for (source, value) in &present {
            match (&selected, value) {
                (None, Some(value)) => {
                    selected = Some(Credential {
                        source: *source,
                        value: value.clone(),
                    })
                }
                _ => ignored.push(Ignored {
                    source: *source,
                    was_set: value.is_some(),
                }),
            }
        }

        let endpoint_raw = lookup(BASE_URL).filter(|v| !v.trim().is_empty());
        let endpoint_from_env = endpoint_raw.is_some();
        let endpoint = endpoint_raw
            .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string())
            .trim_end_matches('/')
            .to_string();

        let model_raw = lookup(MODEL).filter(|v| !v.trim().is_empty());
        let model_from_env = model_raw.is_some();
        let model = model_raw.unwrap_or_else(|| DEFAULT_MODEL.to_string());

        let mut warnings = Vec::new();
        // FR-415. The endpoint is not Anthropic's and the only credential available is a bare API key, so
        // an upstream account credential is about to go to a third-party host. That may be entirely
        // intended — it is the user's proxy — but it should be a decision rather than a default, and it
        // costs one line on stderr.
        if endpoint != DEFAULT_ENDPOINT
            && selected
                .as_ref()
                .is_some_and(|c| c.source == CredentialSource::ApiKey)
        {
            warnings.push(format!(
                "{API_KEY} is being sent to {endpoint}, which is not {DEFAULT_ENDPOINT}. \
                 An Anthropic account credential is going to a third-party host. \
                 Set {AUTH_TOKEN} to a token scoped to that host instead."
            ));
        }

        Self {
            selected,
            ignored,
            endpoint,
            endpoint_from_env,
            model,
            model_from_env,
            warnings,
        }
    }

    pub fn credential(&self) -> Option<&Credential> {
        self.selected.as_ref()
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Every variable that was consulted and not chosen, whether or not it was set.
    pub fn ignored(&self) -> &[Ignored] {
        &self.ignored
    }

    /// The names of the credential variables consulted, for a failure message.
    ///
    /// FR-402's gap must say *which variables were consulted* when none yielded a credential. Naming them
    /// is the difference between "no credential" and an afternoon of guessing which of three the tool
    /// wanted.
    pub fn consulted() -> String {
        CredentialSource::ORDER
            .iter()
            .map(|s| s.variable())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// The `plz judge --check` report (FR-414).
    ///
    /// **No line contains a credential value**, and a suite-wide test asserts it (SC-404). The `ignored`
    /// column exists because several variables are commonly set at once — that is the normal case, and
    /// "why is it using that one" should not require reading the design document.
    pub fn describe(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "  endpoint   {:<38} ({})\n",
            self.endpoint,
            if self.endpoint_from_env {
                BASE_URL
            } else {
                "default; ANTHROPIC_BASE_URL unset"
            }
        ));
        out.push_str(&format!(
            "  model      {:<38} ({})\n",
            self.model,
            if self.model_from_env {
                MODEL
            } else {
                "default; ANTHROPIC_MODEL unset"
            }
        ));
        match &self.selected {
            Some(credential) => out.push_str(&format!(
                "  credential {:<38} →  {}\n",
                credential.source.variable(),
                credential.source.describe_header()
            )),
            None => out.push_str(&format!(
                "  credential none. Consulted: {}\n",
                Self::consulted()
            )),
        }
        for (index, ignored) in self.ignored.iter().enumerate() {
            let label = if index == 0 { "ignored" } else { "" };
            out.push_str(&format!(
                "  {label:<10} {:<38} ({})\n",
                ignored.source.variable(),
                if ignored.was_set {
                    "set; lower precedence"
                } else {
                    "unset"
                }
            ));
        }
        for warning in &self.warnings {
            out.push_str(&format!("\n  warning: {warning}\n"));
        }
        out
    }
}
