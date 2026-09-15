//! Resolution of the `[env]` section into the environment the guest sees.
//!
//! Every value template is substituted once through the project vault
//! (host env first, secret vault as fallback). Entries marked `mask = true`
//! additionally get a **surrogate**: a random alphanumeric string with the
//! same character count as the real value. The guest only ever receives the
//! surrogate; the real value stays on the host, where the network proxy can
//! swap it back into outbound HTTP headers for rules that `inject` it.

use std::collections::BTreeMap;
use std::fmt;

use rand::distr::{Alphanumeric, SampleString};

use crate::config::config::EnvVar;
use crate::vault::Vault;

/// Shortest value a network rule may inject. A surrogate this short
/// (random alphanumerics) would plausibly appear inside unrelated header
/// text and the byte-level rewrite would corrupt it.
pub const MIN_INJECT_LEN: usize = 8;

/// A problem with one `[env]` entry. Kept as its own type so `airlock
/// start` can recognise it as a configuration error (exit code 2) even
/// when it surfaces from deep inside project setup.
#[derive(Debug, thiserror::Error)]
#[error("env.{name}: {reason}")]
pub struct EnvError {
    pub name: String,
    pub reason: String,
}

impl EnvError {
    fn new(name: &str, reason: impl fmt::Display) -> Self {
        Self {
            name: name.to_string(),
            reason: reason.to_string(),
        }
    }
}

/// A masked `[env]` entry: the real value (host-only) and the surrogate the
/// guest sees in its place.
#[derive(Clone)]
pub struct MaskedSecret {
    pub name: String,
    pub real: String,
    pub surrogate: String,
}

// Manual Debug so a stray `{:?}` on a target or connection never prints the
// real value (or the surrogate, which is as good as the real one once the
// proxy is willing to swap it).
impl fmt::Debug for MaskedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MaskedSecret")
            .field("name", &self.name)
            .field("len", &self.real.chars().count())
            .finish_non_exhaustive()
    }
}

/// The resolved sandbox environment.
///
/// No `Debug`: the guest values include substituted secrets for unmasked
/// entries, and the masked map holds the real ones.
pub struct SandboxEnv {
    /// Every `[env]` entry in config order with the guest-visible value.
    guest: Vec<(String, String)>,
    /// The masked subset, keyed by variable name.
    masked: BTreeMap<String, MaskedSecret>,
}

impl SandboxEnv {
    /// Substitute every template and generate surrogates for masked entries.
    /// A template referencing an undefined host variable / vault secret is
    /// an [`EnvError`] naming the key.
    pub fn resolve(env: &BTreeMap<String, EnvVar>, vault: &Vault) -> Result<Self, EnvError> {
        let mut guest = Vec::with_capacity(env.len());
        let mut masked = BTreeMap::new();
        for (key, entry) in env {
            let real = vault
                .subst(&entry.value)
                .map_err(|e| EnvError::new(key, e))?;
            if entry.mask {
                let surrogate = surrogate_for(&real);
                guest.push((key.clone(), surrogate.clone()));
                masked.insert(
                    key.clone(),
                    MaskedSecret {
                        name: key.clone(),
                        real,
                        surrogate,
                    },
                );
            } else {
                guest.push((key.clone(), real));
            }
        }
        Ok(Self { guest, masked })
    }

    /// An environment with no entries. Used by the read-only project
    /// loader, which must never trigger secret resolution.
    pub fn empty() -> Self {
        Self {
            guest: Vec::new(),
            masked: BTreeMap::new(),
        }
    }

    /// Build an environment consisting solely of the given masked secrets.
    /// Test helper for the network harness.
    #[cfg(test)]
    pub fn from_secrets(secrets: Vec<MaskedSecret>) -> Self {
        let guest = secrets
            .iter()
            .map(|s| (s.name.clone(), s.surrogate.clone()))
            .collect();
        let masked = secrets.into_iter().map(|s| (s.name.clone(), s)).collect();
        Self { guest, masked }
    }

    /// The value the guest sees for `name` — the surrogate for masked
    /// entries, the substituted value otherwise.
    pub fn guest_value(&self, name: &str) -> Option<&str> {
        self.guest
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// `(KEY, guest-visible VALUE)` pairs in config order.
    pub fn guest_entries(&self) -> impl Iterator<Item = (&str, &str)> {
        self.guest.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// The masked entry for `name`, if it exists and is masked.
    pub fn masked(&self, name: &str) -> Option<&MaskedSecret> {
        self.masked.get(name)
    }

    /// Check that `name` can be injected into HTTP headers: it must be a
    /// masked entry, at least [`MIN_INJECT_LEN`] characters long, and a
    /// valid header value (a stray newline from a `.env` loader would
    /// otherwise pass startup and break every request with an opaque 502).
    pub fn check_injectable(&self, name: &str) -> Result<(), EnvError> {
        let Some(secret) = self.masked.get(name) else {
            return Err(EnvError::new(
                name,
                "must be defined in [env] with mask = true to be injected",
            ));
        };
        if secret.real.chars().count() < MIN_INJECT_LEN {
            return Err(EnvError::new(
                name,
                format!("injected value is shorter than {MIN_INJECT_LEN} characters"),
            ));
        }
        if hyper::header::HeaderValue::from_str(&secret.real).is_err() {
            return Err(EnvError::new(
                name,
                "injected value contains bytes that are not allowed in an HTTP header \
                 (a newline or control character, perhaps a trailing newline)",
            ));
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.guest.len()
    }

    pub fn is_empty(&self) -> bool {
        self.guest.is_empty()
    }

    pub fn masked_count(&self) -> usize {
        self.masked.len()
    }
}

/// A random `[A-Za-z0-9]` string with the same character count as `value`.
/// Same *character* count, not byte count: header rewriting works on bytes,
/// but the guest-facing contract ("looks like the real thing") is about
/// what a program sees, and non-ASCII secrets are rare enough that the byte
/// length mismatch is irrelevant.
fn surrogate_for(value: &str) -> String {
    Alphanumeric.sample_string(&mut rand::rng(), value.chars().count())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::vault::{DisabledStorage, VaultStorageType};

    fn vault(host_env: &[(&str, &str)]) -> Vault {
        Vault::new_with(
            Box::new(DisabledStorage),
            host_env
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect::<HashMap<_, _>>(),
            VaultStorageType::Disabled,
        )
    }

    fn env(entries: &[(&str, &str, bool)]) -> BTreeMap<String, EnvVar> {
        entries
            .iter()
            .map(|(k, v, mask)| {
                (
                    (*k).to_string(),
                    EnvVar {
                        value: (*v).to_string(),
                        mask: *mask,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn surrogate_has_same_char_count_and_is_alphanumeric() {
        for real in ["sk-ant-oat01-abcdefghijklmnop", "x", "ääkkönen-token"] {
            let s = surrogate_for(real);
            assert_eq!(s.chars().count(), real.chars().count(), "for {real}");
            assert!(s.chars().all(|c| c.is_ascii_alphanumeric()), "got {s}");
        }
    }

    #[test]
    fn surrogate_of_empty_is_empty() {
        assert_eq!(surrogate_for(""), "");
    }

    #[test]
    fn surrogate_differs_from_real_value() {
        let real = "sk-ant-oat01-abcdefghijklmnop";
        // The alphabet excludes `-`, so a collision is impossible here.
        assert_ne!(surrogate_for(real), real);
    }

    #[test]
    fn unmasked_entries_pass_through_substituted() {
        let v = vault(&[("HOST_TOKEN", "real-value-1234")]);
        let e = env(&[
            ("PLAIN", "static", false),
            ("SUBST", "${HOST_TOKEN}", false),
        ]);
        let resolved = SandboxEnv::resolve(&e, &v).unwrap();
        assert_eq!(resolved.guest_value("PLAIN"), Some("static"));
        assert_eq!(resolved.guest_value("SUBST"), Some("real-value-1234"));
        assert_eq!(resolved.masked_count(), 0);
        assert!(resolved.masked("SUBST").is_none());
    }

    #[test]
    fn masked_entry_is_substituted_then_masked() {
        let v = vault(&[("HOST_TOKEN", "real-value-1234")]);
        let e = env(&[("TOKEN", "${HOST_TOKEN}", true)]);
        let resolved = SandboxEnv::resolve(&e, &v).unwrap();
        let secret = resolved.masked("TOKEN").unwrap();
        assert_eq!(secret.real, "real-value-1234");
        assert_eq!(secret.surrogate.len(), "real-value-1234".len());
        assert_ne!(secret.surrogate, secret.real);
        // The guest sees the surrogate, never the real value.
        assert_eq!(
            resolved.guest_value("TOKEN"),
            Some(secret.surrogate.as_str())
        );
        let entries: Vec<_> = resolved.guest_entries().collect();
        assert_eq!(entries, vec![("TOKEN", secret.surrogate.as_str())]);
        assert_eq!(resolved.masked_count(), 1);
        assert_eq!(resolved.len(), 1);
    }

    #[test]
    fn missing_host_variable_errors_with_key_prefix() {
        let v = vault(&[]);
        let e = env(&[("TOKEN", "${NOPE}", true)]);
        let Err(err) = SandboxEnv::resolve(&e, &v) else {
            panic!("expected an error for an undefined host variable");
        };
        let err = err.to_string();
        assert!(err.starts_with("env.TOKEN:"), "got: {err}");
    }

    #[test]
    fn check_injectable_accepts_a_normal_masked_secret() {
        let v = vault(&[]);
        let e = env(&[("TOKEN", "sk-real-token-0123456789", true)]);
        let resolved = SandboxEnv::resolve(&e, &v).unwrap();
        resolved.check_injectable("TOKEN").unwrap();
    }

    #[test]
    fn check_injectable_rejects_unmasked_or_missing() {
        let v = vault(&[]);
        let e = env(&[("PLAIN", "sk-real-token-0123456789", false)]);
        let resolved = SandboxEnv::resolve(&e, &v).unwrap();
        let err = resolved.check_injectable("PLAIN").unwrap_err().to_string();
        assert!(err.starts_with("env.PLAIN:"), "got: {err}");
        assert!(err.contains("mask = true"), "got: {err}");
        let err = resolved.check_injectable("NOPE").unwrap_err().to_string();
        assert!(err.starts_with("env.NOPE:"), "got: {err}");
    }

    #[test]
    fn check_injectable_rejects_short_values() {
        let v = vault(&[]);
        let e = env(&[("TOKEN", "short", true)]);
        let resolved = SandboxEnv::resolve(&e, &v).unwrap();
        let err = resolved.check_injectable("TOKEN").unwrap_err().to_string();
        assert!(err.contains("shorter than"), "got: {err}");
        assert!(!err.contains("short\""), "value leaked: {err}");
    }

    #[test]
    fn non_ascii_value_masks_by_char_count_and_is_injectable() {
        // A 4-byte emoji counts as one character: the surrogate has the
        // same number of characters, fewer bytes. Non-ASCII bytes are
        // still legal header bytes, so the value stays injectable.
        let real = "🔑-secret-token";
        let v = vault(&[]);
        let e = env(&[("TOKEN", real, true)]);
        let resolved = SandboxEnv::resolve(&e, &v).unwrap();
        let secret = resolved.masked("TOKEN").unwrap();
        assert_eq!(secret.surrogate.chars().count(), real.chars().count());
        assert!(secret.surrogate.len() < real.len());
        assert!(secret.surrogate.is_ascii());
        resolved.check_injectable("TOKEN").unwrap();
    }

    #[test]
    fn check_injectable_rejects_invalid_header_bytes() {
        let v = vault(&[("T", "sk-real-token-0123456789\n")]);
        let e = env(&[("TOKEN", "${T}", true)]);
        let resolved = SandboxEnv::resolve(&e, &v).unwrap();
        let err = resolved.check_injectable("TOKEN").unwrap_err().to_string();
        assert!(err.contains("HTTP header"), "got: {err}");
        assert!(!err.contains("sk-real"), "value leaked: {err}");
    }

    #[test]
    fn debug_never_prints_values() {
        let s = MaskedSecret {
            name: "TOKEN".into(),
            real: "real-secret-value".into(),
            surrogate: "surrogate-value-x".into(),
        };
        let dbg = format!("{s:?}");
        assert!(dbg.contains("TOKEN"));
        assert!(!dbg.contains("real-secret-value"));
        assert!(!dbg.contains("surrogate-value-x"));
    }
}
