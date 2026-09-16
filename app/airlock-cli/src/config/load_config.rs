use std::collections::HashSet;
use std::path::{Path, PathBuf};

use smart_config::DescribeConfig;

use crate::config::de::format_error;
use crate::config::{Config, presets};
use crate::network::rules::parse_pattern;

pub(crate) const EXTENSIONS: &[&str] = &["toml", "json", "yaml", "yml"];

/// Load configuration from hierarchical config files.
///
/// Files are loaded in order (later overrides former):
/// 1. `~/.airlock/config.<ext>`
/// 2. `~/.airlock.<ext>`
/// 3. `<project_root>/airlock.<ext>`
/// 4. `<project_root>/airlock.local.<ext>`
///
/// Supported formats: TOML, JSON, YAML. For each slot the first matching
/// extension (`toml` → `json` → `yaml` → `yml`) wins.
///
/// If the merged config contains a `presets` array, the named
/// presets are applied as base layers before the user config.
pub fn load(project_root: &Path) -> anyhow::Result<Config> {
    let home = dirs::home_dir().unwrap_or_default();
    let bases: [PathBuf; 4] = [
        home.join(".airlock/config"),
        home.join(".airlock"),
        project_root.join("airlock"),
        project_root.join("airlock.local"),
    ];

    // 1. Create base config
    let base = serde_json::Value::Object(serde_json::Map::new());

    // 2. Load user config — for each slot, use the first extension found
    let mut user_config = serde_json::Value::Object(serde_json::Map::new());
    for base_path in &bases {
        if let Some((path, mut value)) = load_first(base_path)? {
            tracing::debug!("config: loaded {}", path.display());
            tracing::trace!("config: {}: {value}", path.display());
            normalize_env(&mut value);
            user_config = merge_json(user_config, value);
        }
    }

    // 3-5. Resolve presets and apply user config on top
    let merged = apply_with_presets(
        base,
        user_config,
        &presets::get,
        &mut vec![],
        &mut HashSet::new(),
    )?;

    tracing::trace!("config: merged result: {merged}");

    parse_config(merged)
}

/// Try each supported extension for `base` and parse the first file found.
pub(super) fn load_first(base: &Path) -> anyhow::Result<Option<(PathBuf, serde_json::Value)>> {
    for ext in EXTENSIONS {
        let path = PathBuf::from(format!("{}.{ext}", base.display()));
        let content = match std::fs::read_to_string(&path) {
            Ok(content) => content,
            // Only a genuinely absent file falls through to the next
            // extension. Any other error (permission, IO, a directory in
            // the file's place) means the config exists but can't be
            // read — fail closed so the sandbox never silently drops the
            // user's policy in favor of permissive defaults.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(anyhow::anyhow!("read config file {}: {e}", path.display()));
            }
        };
        let value = parse_file(&path, &content)?;
        return Ok(Some((path, value)));
    }
    Ok(None)
}

pub(crate) fn parse_file(path: &Path, content: &str) -> anyhow::Result<serde_json::Value> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("toml") => {
            toml::from_str(content).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))
        }
        Some("json") => {
            serde_json::from_str(content).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))
        }
        Some("yaml" | "yml") => {
            serde_yaml::from_str(content).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))
        }
        _ => anyhow::bail!("unsupported config format: {}", path.display()),
    }
}

/// Apply a config layer with preset resolution:
/// 1. Extract presets from the config
/// 2. Recursively apply each preset onto base
/// 3. Apply the config (without presets key) on top
pub(super) fn apply_with_presets(
    mut base: serde_json::Value,
    mut config: serde_json::Value,
    resolve: &dyn Fn(&str) -> Option<serde_json::Value>,
    chain: &mut Vec<String>,
    applied: &mut HashSet<String>,
) -> anyhow::Result<serde_json::Value> {
    let preset_names = extract_presets(&mut config);
    normalize_env(&mut config);

    for name in preset_names {
        if applied.contains(&name) {
            tracing::debug!("config: preset `{name}` already applied, skipping");
            continue;
        }
        if chain.contains(&name) {
            anyhow::bail!(
                "circular preset dependency: {} -> {name}",
                chain.join(" -> ")
            );
        }

        let mut preset_config =
            resolve(&name).ok_or_else(|| anyhow::anyhow!("unknown preset: `{name}`"))?;
        normalize_env(&mut preset_config);

        tracing::debug!("config: applying preset `{name}`");
        chain.push(name.clone());
        base = apply_with_presets(base, preset_config, resolve, chain, applied)?;
        chain.pop();
        applied.insert(name);
    }

    Ok(merge_json(base, config))
}

/// Rewrite every plain-string `[env]` entry of one config layer into its
/// object form `{ "value": "..." }` before layers are merged.
///
/// `merge_json` lets a primitive overlay replace an object wholesale, so
/// without this a `TOKEN = "${TOKEN}"` in `airlock.local.toml` would erase a
/// base layer's `{ value = "${TOKEN}", mask = true }` — silently un-masking
/// the secret. With both sides in object form the merge is field-wise: an
/// overlay string only replaces `value` and inherits the base's `mask`.
pub(super) fn normalize_env(layer: &mut serde_json::Value) {
    let Some(env) = layer
        .get_mut("env")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };
    for entry in env.values_mut() {
        if entry.is_string() {
            let value = std::mem::take(entry);
            *entry = serde_json::json!({ "value": value });
        }
    }
}

/// Extract and remove the `presets` array from a JSON value.
pub(super) fn extract_presets(value: &mut serde_json::Value) -> Vec<String> {
    let Some(obj) = value.as_object_mut() else {
        return vec![];
    };
    let Some(serde_json::Value::Array(arr)) = obj.remove("presets") else {
        return vec![];
    };
    arr.into_iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect()
}

pub(super) fn parse_config(merged: serde_json::Value) -> anyhow::Result<Config> {
    let serde_json::Value::Object(map) = merged else {
        anyhow::bail!("config must be a TOML table");
    };

    let schema = smart_config::ConfigSchema::new(&Config::DESCRIPTION, "");
    let source = smart_config::Json::new("merged config", map);
    let repo = smart_config::ConfigRepository::new(&schema).with(source);
    let parser = repo.single::<Config>()?;
    let config = match parser.parse() {
        Ok(config) => config,
        Err(errors) => {
            return Err(anyhow::anyhow!(format_error(
                "invalid configuration",
                errors,
            )));
        }
    };

    #[cfg(not(target_os = "linux"))]
    if config.vm.kvm {
        anyhow::bail!("kvm is only supported on Linux");
    }

    validate_network(&config)?;

    Ok(config)
}

/// Cross-field checks on `[network]` that the schema cannot express,
/// reported in the same shape as smart-config parse errors so the user sees
/// one consistent "invalid configuration" block.
///
/// Target patterns: every `allow`/`deny`/middleware `target` entry of an
/// enabled rule must have a port that is a number or `*` (or none). The
/// proxy would otherwise have to pick a meaning for `*:8O80`, and the only
/// safe one is "refuse to start" — treating it as "any port" turns a typo
/// into a wide-open allow under deny-by-default.
///
/// Inject: every name in an enabled rule's `inject` list must be an `[env]`
/// entry with `mask = true` — injecting an unmasked value would mean the
/// guest already holds the real secret, and injecting an undefined one is a
/// typo. An injecting rule also cannot be `passthrough` (injection needs
/// interception).
fn validate_network(config: &Config) -> anyhow::Result<()> {
    let mut problems: Vec<String> = Vec::new();
    for (rule_name, rule) in &config.network.rules {
        if !rule.enabled {
            continue;
        }
        for (field, patterns) in [("allow", &rule.allow), ("deny", &rule.deny)] {
            for pattern in patterns {
                if let Err(e) = parse_pattern(pattern) {
                    problems.push(format!("* `network.rules.{rule_name}.{field}` {e}"));
                }
            }
        }
        if rule.passthrough && !rule.inject.is_empty() {
            problems.push(format!(
                "* `network.rules.{rule_name}` inject cannot be combined with passthrough"
            ));
        }
        for var in &rule.inject {
            let masked = config.env.get(var).is_some_and(|e| e.mask);
            if !masked {
                problems.push(format!(
                    "* `network.rules.{rule_name}.inject` `{var}` must be defined in [env] with mask = true"
                ));
            }
        }
    }
    for (mw_name, mw) in &config.network.middleware {
        if !mw.enabled {
            continue;
        }
        for pattern in &mw.target {
            if let Err(e) = parse_pattern(pattern) {
                problems.push(format!("* `network.middleware.{mw_name}.target` {e}"));
            }
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("invalid configuration\n{}", problems.join("\n"));
    }
}

/// Merge two JSON values with custom rules:
/// - Null overlay: base wins (null never overwrites)
/// - Arrays: concatenate
/// - Objects: recursive merge
/// - Primitives: overlay wins
/// - Type mismatch: overlay wins
pub(super) fn merge_json(base: serde_json::Value, overlay: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match (base, overlay) {
        (base, Value::Null) => base,
        (Value::Object(mut base), Value::Object(overlay)) => {
            for (key, overlay_val) in overlay {
                let merged = match base.remove(&key) {
                    Some(base_val) => merge_json(base_val, overlay_val),
                    None => overlay_val,
                };
                base.insert(key, merged);
            }
            Value::Object(base)
        }
        (Value::Array(mut base), Value::Array(overlay)) => {
            base.extend(overlay);
            Value::Array(base)
        }
        (_, overlay) => overlay,
    }
}
