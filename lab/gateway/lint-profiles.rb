#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Structural lint for the Ferrum Anvil gateway lab profiles (ferrum-edge v0.9.5).
#
# Why this exists: `ferrum-edge validate` rejects unknown keys on GatewayConfig, Proxy,
# Consumer, PluginConfig and Upstream (serde deny_unknown_fields), and every plugin used here
# rejects unknown `config` keys. But circuit_breaker, retry, health_checks(.active/.passive)
# and upstream targets are LENIENT: a misspelled key there is silently ignored and the lab
# silently misconfigures. This script checks every key against field lists copied from the
# v0.9.5 source, plus proxy/plugin association rules and resource_counts.
#
# Field lists: src/config/types.rs @ v0.9.5 (structs Proxy 2609, Consumer 3025,
# PluginConfig 3053, Upstream 1826, UpstreamTarget 1204, ActiveHealthCheck 1448,
# PassiveHealthCheck 1527, CircuitBreakerConfig 2225, RetryConfig 2294, GatewayConfig 3200).
#
# Usage: ruby lab/gateway/lint-profiles.rb [profile.yaml ...]   (default: all *.yaml here)
# Exit status 1 on any finding. `{{TOKEN}}` placeholders are tolerated.

require 'yaml'

GATEWAY = %w[version resource_counts proxies consumers plugin_configs upstreams loaded_at known_namespaces
             frontend_tls_cert_path frontend_tls_key_path frontend_tls_source_namespace
             frontend_tls_certificate_sources trust_bundles mesh http_tls_listen_ports].freeze
PROXY = %w[labels id name namespace hosts listen_path backend_scheme backend_host backend_port backend_path
           strip_listen_path preserve_host_header backend_connect_timeout_ms backend_read_timeout_ms
           backend_write_timeout_ms backend_tls_client_cert_path backend_tls_client_key_path
           backend_tls_verify_server_cert backend_tls_server_ca_cert_path dns_override dns_cache_ttl_seconds
           auth_mode plugins pool_idle_timeout_seconds pool_enable_http_keep_alive pool_enable_http2
           pool_tcp_keepalive_seconds pool_http2_keep_alive_interval_seconds pool_http2_keep_alive_timeout_seconds
           pool_http2_initial_stream_window_size pool_http2_initial_connection_window_size
           pool_http2_adaptive_window pool_http2_max_frame_size pool_http2_max_concurrent_streams
           pool_http3_connections_per_backend pool_max_requests_per_connection upstream_id upstream_subset
           api_spec_id circuit_breaker retry response_body_mode listen_port frontend_tls passthrough
           udp_idle_timeout_seconds udp_max_response_amplification_factor tcp_idle_timeout_seconds
           stream_proxy_protocol backend_proxy_protocol stream_match websocket_idle_timeout_seconds
           allowed_methods allowed_ws_origins created_at updated_at].freeze
CONSUMER = %w[labels id username namespace custom_id credentials acl_groups created_at updated_at].freeze
PLUGIN_CONFIG = %w[labels id plugin_name namespace config scope proxy_id enabled priority_override trigger
                   api_spec_id created_at updated_at].freeze
UPSTREAM = %w[labels id name namespace targets algorithm hash_on hash_on_cookie_config health_checks
              service_discovery subsets port_overrides source_locality source_labels locality_lb_strict
              locality_lb_setting backend_tls_client_cert_path backend_tls_client_key_path
              backend_tls_verify_server_cert backend_tls_server_ca_cert_path backend_tls_sni
              backend_tls_san_allow_list api_spec_id created_at updated_at].freeze
TARGET = %w[host port weight tags locality path].freeze
HEALTH = %w[active passive].freeze
ACTIVE = %w[http_path interval_seconds timeout_ms healthy_threshold unhealthy_threshold healthy_status_codes
            use_tls probe_type udp_probe_payload grpc_service_name].freeze
PASSIVE = %w[unhealthy_status_codes unhealthy_threshold unhealthy_window_seconds healthy_after_seconds
             max_ejection_percent gateway_error_codes split_external_local_origin_errors
             consecutive_error_mode consecutive_5xx_ejection_disabled].freeze
BREAKER = %w[failure_threshold success_threshold timeout_seconds cooldown_seconds failure_status_codes
             half_open_max_requests trip_on_connection_errors].freeze
RETRY = %w[max_retries retryable_status_codes retryable_methods backoff retry_on_connect_failure].freeze
SCHEMES = %w[http https tcp tcps udp dtls].freeze
ALGORITHMS = %w[round_robin weighted_round_robin least_connections least_latency consistent_hashing random
                passthrough].freeze
CREDENTIAL_TYPES = { 'keyauth' => %w[key], 'basicauth' => %w[password_hash], 'jwt' => %w[secret],
                     'hmac_auth' => %w[secret], 'mtls_auth' => %w[identity] }.freeze

# Plugin config key sets (closed sets from each plugin's source @ v0.9.5).
REDIS = %w[sync_mode redis_url redis_tls redis_key_prefix redis_pool_size redis_connect_timeout_seconds
           redis_health_check_interval_seconds redis_username redis_password].freeze
PLUGIN_KEYS = {
  'stdout_logging' => %w[filter schema schema_ref],                                   # stdout_logging.rs:64-66
  'key_auth' => %w[key_location hide_credentials],                                    # key_auth.rs:55-66
  'basic_auth' => %w[hide_credentials],                                               # basic_auth.rs:72-93
  'jwt_auth' => %w[token_lookup consumer_claim_field require_exp require_nbf expected_issuer
                   expected_issuers audiences leeway_secs],                           # jwt_auth.rs:170-187
  'hmac_auth' => %w[clock_skew_seconds signing_profile allow_unsafe_replayable_v1 replay_scope
                    replay_max_entries] + REDIS,                                      # hmac_auth.rs:177-183
  'jwks_auth' => %w[providers scope_claim role_claim consumer_identity_claim consumer_header_claim
                    claim_headers claim_headers_separator emit_mesh_request_principal_metadata require_exp
                    jwks_refresh_interval_secs jwks_max_stale_seconds
                    kid_miss_refresh_cooldown_seconds] + REDIS,                       # jwks_auth.rs:256-280
  'access_control' => %w[allowed_consumers disallowed_consumers allowed_groups disallowed_groups
                         allow_authenticated_identity],                               # access_control.rs:293-307
  'request_size_limiting' => %w[max_bytes],                                           # request_size_limiting.rs:34
  'response_size_limiting' => %w[max_bytes require_buffered_check],                   # response_size_limiting.rs:45
  'response_transformer' => %w[rules apply_route_overrides runtime_overlay_scope default_enabled],
  'adaptive_concurrency' => %w[key_by max_tracked_keys min_limit initial_limit max_limit min_samples
                               target_latency_multiplier decrease_ratio increase_step shadow_mode
                               expose_headers],                                       # adaptive_concurrency.rs:141-153
  'ip_restriction' => %w[allow deny mode],                                            # ip_restriction.rs:23
  'opa' => %w[opa_host policy_path headers timeout_ms max_response_bytes fail_open fail_closed deny_status
              deny_body deny_headers fail_closed_status fail_closed_body fail_closed_headers
              decision_pointer include_method include_path include_query include_query_credentials
              include_headers include_body max_body_bytes include_consumer include_client_ip
              include_service query_ambiguity_policy redact_headers redact_query_keys],  # opa.rs:40-67 (prefix)
  'waf' => %w[mode default_rule_action paranoia_level request_inspection request_body_inspection
              response_inspection response_body_inspection log_to_metadata log_to_stdout scan_budget_ms
              max_scan_bytes on_scan_timeout on_body_too_large include_default_rules disabled_default_rules
              rule_modes rule_overrides custom_rules scoring global_exemptions body_methods
              body_content_types inspect_multipart inspect_binary_body disallowed_methods
              reject_status_code reject_content_type reject_body stream],             # waf/mod.rs:62-92
  'openapi_validator' => %w[enforcement_mode validate_request validate_response fail_on_unknown_operation
                            fail_on_missing_response_schema max_body_bytes request_content_types
                            response_content_types schema_draft operations bypass error_response
                            error_truncate_chars],                                    # openapi_validator.rs:144-158
  'ai_request_guard' => %w[max_tokens_limit enforce_max_tokens default_max_tokens supported_schema
                           strict_schema allowed_models blocked_models require_model_for_model_policy
                           require_user_field max_messages max_prompt_characters temperature_range
                           block_system_prompts system_prompt_aliases required_metadata_fields
                           fail_on_uninspectable_body],                               # ai_request_guard.rs:94-110 (prefix)
  'ai_rate_limiter' => %w[token_limit window_seconds count_mode limit_by expose_headers provider
                          on_unmetered_response redis_failure_policy] + REDIS,         # ai_rate_limiter.rs:351-370
  # Added for the policy profile; accepted by `ferrum-edge validate` v0.9.5 (live-checked).
  'bot_detection' => %w[blocked_patterns allow_list allow_missing_user_agent custom_response_code],
  'rate_limiting' => %w[limit_by expose_headers limits redis_failure_policy] + REDIS,
  'ai_response_guard' => %w[action pii_patterns custom_pii_patterns blocked_phrases blocked_patterns
                            scan_fields redaction_placeholder max_scan_bytes require_json
                            required_fields max_completion_length grpc]
}.freeze
NESTED = {
  %w[response_transformer rules] => %w[operation target key value new_key],           # response_transformer.rs:156
  %w[waf custom_rules] => %w[id name category severity target match_kind pattern action fp_filters
                             paranoia_min score conditions],                          # waf/rules.rs:11-24
  %w[jwks_auth providers] => %w[jwks_uri discovery_url jwks issuer audience audiences from_headers
                                from_params forward_original_token require_exp required_scopes
                                required_roles scope_claim role_claim consumer_identity_claim
                                consumer_header_claim claim_headers claim_headers_separator
                                output_claim_headers require_mtls_binding require_dpop dpop_clock_skew_secs
                                dpop_replay_scope dpop_replay_max_entries jwks_max_stale_seconds], # jwks_auth.rs:282-308
  %w[openapi_validator operations] => %w[method path_template path_regex operation_label request_required
                                         request_body responses]                      # openapi_validator.rs:159-167
}.freeze

$errors = []
def err(file, msg)
  $errors << "#{file}: #{msg}"
end

def count_by(list)
  list.each_with_object(Hash.new(0)) { |x, h| h[x] += 1 }
end

def check_keys(file, where, hash, allowed)
  return err(file, "#{where}: expected a mapping, got #{hash.class}") unless hash.is_a?(Hash)

  (hash.keys - allowed).each { |k| err(file, "#{where}: unknown key '#{k}'") }
end

def lint(file)
  doc = YAML.safe_load(File.read(file), aliases: false)
  return err(file, 'not a mapping') unless doc.is_a?(Hash)

  check_keys(file, 'top-level', doc, GATEWAY)
  %w[version proxies plugin_configs].each { |k| err(file, "missing required top-level '#{k}'") unless doc.key?(k) }
  proxies = doc['proxies'] || []
  plugins = doc['plugin_configs'] || []
  consumers = doc['consumers'] || []
  upstreams = doc['upstreams'] || []

  if (rc = doc['resource_counts'])
    { 'proxies' => proxies, 'consumers' => consumers, 'plugin_configs' => plugins, 'upstreams' => upstreams }.each do |k, v|
      err(file, "resource_counts.#{k}=#{rc[k]} but found #{v.size}") if rc.key?(k) && rc[k] != v.size
    end
  end

  count_by(proxies.map { |p| p['id'] }).each { |id, n| err(file, "duplicate proxy id #{id}") if n > 1 }
  count_by(plugins.map { |p| p['id'] }).each { |id, n| err(file, "duplicate plugin_config id #{id}") if n > 1 }
  count_by(proxies.map { |p| p['listen_path'] }.compact).each { |lp, n| err(file, "duplicate listen_path #{lp}") if n > 1 }
  count_by(proxies.map { |p| p['listen_port'] }.compact).each { |lp, n| err(file, "duplicate listen_port #{lp}") if n > 1 }

  by_plugin_id = plugins.to_h { |p| [p['id'], p] }
  upstream_ids = upstreams.map { |u| u['id'] }

  proxies.each do |p|
    w = "proxy #{p['id']}"
    check_keys(file, w, p, PROXY)
    scheme = p['backend_scheme']
    err(file, "#{w}: backend_scheme '#{scheme}' invalid") if scheme && !SCHEMES.include?(scheme)
    stream = p.key?('listen_port') && %w[tcp tcps udp dtls].include?(scheme)
    if p.key?('listen_port') && scheme.nil?
      err(file, "#{w}: listen_port set but backend_scheme missing")
    end
    if stream
      err(file, "#{w}: stream proxy must not set listen_path") if p.key?('listen_path')
    else
      err(file, "#{w}: HTTP proxy needs listen_path or hosts") unless p.key?('listen_path') || p.key?('hosts')
      err(file, "#{w}: omit backend_scheme defaults to https - set it explicitly") if scheme.nil?
    end
    if %w[http tcp udp].include?(scheme)
      %w[backend_tls_client_cert_path backend_tls_client_key_path backend_tls_verify_server_cert
         backend_tls_server_ca_cert_path].each do |k|
        err(file, "#{w}: #{k} is rejected for backend_scheme #{scheme}") if p.key?(k)
      end
    end
    if p['upstream_id']
      err(file, "#{w}: upstream_id '#{p['upstream_id']}' not defined") unless upstream_ids.include?(p['upstream_id'])
    else
      err(file, "#{w}: backend_host/backend_port required without upstream_id") unless p['backend_host'] && p['backend_port']
    end
    check_keys(file, "#{w}.circuit_breaker", p['circuit_breaker'], BREAKER) if p.key?('circuit_breaker')
    check_keys(file, "#{w}.retry", p['retry'], RETRY) if p.key?('retry')
    (p['plugins'] || []).each do |a|
      check_keys(file, "#{w}.plugins[]", a, %w[plugin_config_id])
      pc = by_plugin_id[a['plugin_config_id']]
      if pc.nil?
        err(file, "#{w}: references missing plugin_config #{a['plugin_config_id']}")
      elsif pc['scope'] == 'global'
        err(file, "#{w}: references global plugin #{pc['id']}")
      elsif pc['scope'] == 'proxy' && pc['proxy_id'] != p['id']
        err(file, "#{w}: references plugin #{pc['id']} targeted at #{pc['proxy_id']}")
      end
    end
  end

  plugins.each do |pc|
    w = "plugin_config #{pc['id']}"
    check_keys(file, w, pc, PLUGIN_CONFIG)
    err(file, "#{w}: config must be a mapping (null config fails most plugins)") unless pc['config'].is_a?(Hash)
    case pc['scope']
    when 'global' then err(file, "#{w}: global scope must not set proxy_id") if pc.key?('proxy_id')
    when 'proxy'
      owner = proxies.find { |p| p['id'] == pc['proxy_id'] }
      if owner.nil?
        err(file, "#{w}: proxy_id #{pc['proxy_id']} not found")
      elsif (owner['plugins'] || []).none? { |a| a['plugin_config_id'] == pc['id'] }
        err(file, "#{w}: proxy #{owner['id']} does not list it under plugins (it would never run)")
      end
    when 'proxy_group' then err(file, "#{w}: proxy_group must not set proxy_id") if pc.key?('proxy_id')
    else err(file, "#{w}: invalid scope #{pc['scope'].inspect}")
    end
    allowed = PLUGIN_KEYS[pc['plugin_name']]
    if allowed.nil?
      err(file, "#{w}: plugin '#{pc['plugin_name']}' has no key list in this lint (add one from source)")
    elsif pc['config'].is_a?(Hash)
      check_keys(file, "#{w}.config", pc['config'], allowed)
      NESTED.each do |(plugin, field), keys|
        next unless plugin == pc['plugin_name'] && pc['config'][field].is_a?(Array)

        pc['config'][field].each_with_index { |item, i| check_keys(file, "#{w}.config.#{field}[#{i}]", item, keys) }
      end
    end
  end

  consumers.each do |c|
    w = "consumer #{c['id']}"
    check_keys(file, w, c, CONSUMER)
    (c['credentials'] || {}).each do |type, entries|
      allowed = CREDENTIAL_TYPES[type]
      next err(file, "#{w}: unknown credential type #{type}") if allowed.nil?
      next err(file, "#{w}: credentials.#{type} must be an array of objects") unless entries.is_a?(Array)

      entries.each { |e| check_keys(file, "#{w}.credentials.#{type}[]", e, allowed) }
    end
  end

  upstreams.each do |u|
    w = "upstream #{u['id']}"
    check_keys(file, w, u, UPSTREAM)
    err(file, "#{w}: port_overrides cannot be set in file mode (types.rs:9548)") if u.key?('port_overrides')
    err(file, "#{w}: unknown algorithm #{u['algorithm']}") if u['algorithm'] && !ALGORITHMS.include?(u['algorithm'])
    (u['targets'] || []).each_with_index { |t, i| check_keys(file, "#{w}.targets[#{i}]", t, TARGET) }
    next unless (hc = u['health_checks'])

    check_keys(file, "#{w}.health_checks", hc, HEALTH)
    check_keys(file, "#{w}.health_checks.active", hc['active'], ACTIVE) if hc['active']
    check_keys(file, "#{w}.health_checks.passive", hc['passive'], PASSIVE) if hc['passive']
  end
rescue Psych::Exception => e
  err(file, "YAML error: #{e.message}")
end

files = ARGV.empty? ? Dir[File.join(__dir__, '*.yaml')].sort : ARGV
files.each { |f| lint(f) }
if $errors.empty?
  puts "OK: #{files.size} profile(s) passed structural lint"
else
  puts $errors
  exit 1
end
