#!/usr/bin/env bats
# Tests for configuration file loading, parsing, and merging.
# Uses "airlock show" as entry point since it loads config without TTY gates.

load helpers

@test "invalid TOML syntax reports error" {
    write_config 'not [valid'
    run_airlock show
    assert_failure
    assert_output_matches "TOML|expected"
}

@test "unknown preset reports error" {
    write_config 'presets = ["nonexistent"]'
    run_airlock show
    assert_failure
    assert_output_contains "unknown preset"
}

@test "valid debian preset loads without config error" {
    write_config 'presets = ["debian"]'
    run_airlock show
    # Should fail on missing sandbox, not on config
    assert_failure
    assert_output_not_contains "Config error"
    assert_output_not_contains "unknown preset"
}

@test "valid rust preset loads without config error" {
    write_config 'presets = ["rust"]'
    run_airlock show
    assert_failure
    assert_output_not_contains "Config error"
}

@test "multiple presets load without config error" {
    write_config 'presets = ["debian", "rust", "claude-code"]'
    run_airlock show
    assert_failure
    assert_output_not_contains "Config error"
}

@test "empty config loads with defaults" {
    write_config ''
    run_airlock show
    assert_failure
    assert_output_not_contains "Config error"
}

@test "no config file loads with defaults" {
    run_airlock show
    assert_failure
    assert_output_not_contains "Config error"
}

@test "config merging: local env vars are included" {
    write_config '[env]
A = "from-base"'
    write_local_config '[env]
B = "from-local"'
    # Config loads successfully (fails later on missing sandbox)
    run_airlock show
    assert_failure
    assert_output_not_contains "Config error"
}

@test "config merging: local overrides base values" {
    write_config '[vm]
image = "base:1"'
    write_local_config '[vm]
image = "local:2"'
    run_airlock show
    assert_failure
    assert_output_not_contains "Config error"
}

@test "airlock.local.toml is loaded (regression)" {
    # This is a regression test for the Path::with_extension bug
    # where airlock.local.toml was silently skipped.
    write_config '[vm]'
    write_local_config '[env]
TEST_LOCAL_VAR = "loaded"'
    run_airlock show
    assert_failure
    assert_output_not_contains "Config error"
}

@test "masked env table form loads without config error" {
    write_config '[env]
TOKEN = { value = "static-token-value", mask = true }'
    run_airlock show
    assert_failure
    assert_output_not_contains "invalid configuration"
}

@test "inject of masked env var loads without config error" {
    write_config '[env]
TOKEN = { value = "static-token-value", mask = true }

[network.rules.api]
allow = ["api.example.com:443"]
inject = ["TOKEN"]'
    run_airlock show
    assert_failure
    assert_output_not_contains "must be defined in [env] with mask = true"
}

@test "inject of unmasked env var reports config error" {
    write_config '[env]
TOKEN = "plain"

[network.rules.api]
allow = ["api.example.com:443"]
inject = ["TOKEN"]'
    run_airlock show
    assert_failure
    assert_output_contains "network.rules.api.inject"
    assert_output_contains "TOKEN"
    assert_output_contains "must be defined in [env] with mask = true"
}

@test "inject of undefined env var reports config error" {
    write_config '[network.rules.api]
allow = ["api.example.com:443"]
inject = ["NOPE"]'
    run_airlock show
    assert_failure
    assert_output_contains "NOPE"
    assert_output_contains "must be defined in [env] with mask = true"
}

@test "masked env entry with unknown key reports config error" {
    write_config '[env]
TOKEN = { value = "x", masked = true }'
    run_airlock show
    assert_failure
    assert_output_contains "invalid configuration"
}
