<?php
/*
	Plugin Name: Secure Owl Firewall
	Plugin URI: https://sajbersove.rs
	Description: Secure Owl Firewall is a smart rule-based protection that blocks threats and secures your site from attacks.
	Tags: firewall, security, waf, protection
	Author: Sajber Sove
	Requires at least: 5.0
	Tested up to: 6.9
	Stable tag: 1.0.0
	Version:    1.0.0
	Requires PHP: 7.4
	Text Domain: secure-owl-firewall
	License: GPLv2 or later
*/

if (!defined('ABSPATH')) die();

// ── Constants ────────────────────────────────────────────────────────────────

if (!defined('SSWAF_VERSION'))   define('SSWAF_VERSION', '1.0.0');
if (!defined('SSWAF_FILE'))      define('SSWAF_FILE', __FILE__);
if (!defined('SSWAF_BASE_FILE')) define('SSWAF_BASE_FILE', plugin_basename(__FILE__));
if (!defined('SSWAF_DIR'))       define('SSWAF_DIR', plugin_dir_path(__FILE__));
if (!defined('SSWAF_URL'))       define('SSWAF_URL', plugins_url('/', __FILE__));
if (!defined('SSWAF_RULES'))     define('SSWAF_RULES', SSWAF_DIR . 'sswaf-rules.json');
if (!defined('SSWAF_LOG_MAX'))   define('SSWAF_LOG_MAX', 2 * 1024 * 1024); // 2 MB
if (!defined('SSWAF_MU_FILE'))   define('SSWAF_MU_FILE', WPMU_PLUGIN_DIR . '/sswaf-loader.php');

// ── Transformation Functions ─────────────────────────────────────────────────

function sswaf_t_lowercase($input) {
	return function_exists('mb_strtolower') ? mb_strtolower($input, 'UTF-8') : strtolower($input);
}

function sswaf_t_url_decode($input) {
	$prev = '';
	$current = $input;
	// Recursive decode to catch double/triple encoding
	while ($prev !== $current) {
		$prev = $current;
		$current = rawurldecode($current);
	}
	return $current;
}

function sswaf_t_trim($input) {
	return trim($input);
}

function sswaf_t_normalize_path($input) {
	// Remove redundant slashes
	$input = preg_replace('#/{2,}#', '/', $input);
	// Remove self-references
	$input = preg_replace('#/\./#', '/', $input);
	// Resolve parent references
	$count = 1;
	while ($count > 0) {
		$input = preg_replace('#/[^/]+/\.\.(?=/|$)#', '', $input, -1, $count);
	}
	// Remove trailing /. sequences
	$input = preg_replace('#/\.$#', '/', $input);
	return $input;
}

function sswaf_t_remove_whitespace($input) {
	return preg_replace('/\s+/', '', $input);
}

function sswaf_t_html_entity_decode($input) {
	return html_entity_decode($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

// ── Transformation Pipeline ──────────────────────────────────────────────────

function sswaf_apply_transforms($input, $transformations) {

	static $map = null;

	if ($map === null) {
		$map = array(
			'lowercase'        => 'sswaf_t_lowercase',
			'urlDecode'        => 'sswaf_t_url_decode',
			'urldecode'        => 'sswaf_t_url_decode',
			'trim'             => 'sswaf_t_trim',
			'normalizePath'    => 'sswaf_t_normalize_path',
			'normalizepath'    => 'sswaf_t_normalize_path',
			'removeWhitespace' => 'sswaf_t_remove_whitespace',
			'removewhitespace' => 'sswaf_t_remove_whitespace',
			'htmlEntityDecode' => 'sswaf_t_html_entity_decode',
			'htmlentitydecode'  => 'sswaf_t_html_entity_decode',
		);
	}

	foreach ($transformations as $t) {
		$key = isset($map[$t]) ? $t : strtolower($t);
		if (isset($map[$key])) {
			$input = call_user_func($map[$key], $input);
		}
	}

	return $input;
}

// ── Rule Loader ──────────────────────────────────────────────────────────────

function sswaf_load_rules() {

	static $rules = null;

	if ($rules !== null) return $rules;

	$rules_file = apply_filters('sswaf_rules_file', SSWAF_RULES);

	if (!file_exists($rules_file) || !is_readable($rules_file)) {
		if (defined('WP_DEBUG') && WP_DEBUG) {
			error_log('SecureOwl: Rules file not found or not readable: ' . $rules_file); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- intentional debug logging
		}
		$rules = array('settings' => array(), 'rules' => array());
		return $rules;
	}

	$json = file_get_contents($rules_file);
	$data = json_decode($json, true);

	if (json_last_error() !== JSON_ERROR_NONE) {
		if (defined('WP_DEBUG') && WP_DEBUG) {
			error_log('SecureOwl: JSON parse error: ' . json_last_error_msg()); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- intentional debug logging
		}
		$rules = array('settings' => array(), 'rules' => array());
		return $rules;
	}

	// Filter to enabled rules that have an ID, respecting user overrides
	$disabled_ids = get_option('sswaf_disabled_rules', array());
	if (!is_array($disabled_ids)) $disabled_ids = array();

	$enabled_rules = array();
	if (isset($data['rules']) && is_array($data['rules'])) {
		foreach ($data['rules'] as $rule) {
			if (!isset($rule['id'], $rule['enabled'])) continue;
			if ($rule['enabled'] !== true) continue;
			if (in_array($rule['id'], $disabled_ids, true)) continue;
			$enabled_rules[] = $rule;
		}
	}

	$rules = array(
		'settings' => isset($data['settings']) ? $data['settings'] : array(),
		'rules'    => $enabled_rules,
	);

	return $rules;
}

function sswaf_load_all_rules() {

	$rules_file = apply_filters('sswaf_rules_file', SSWAF_RULES);

	if (!file_exists($rules_file) || !is_readable($rules_file)) return array();

	$json = file_get_contents($rules_file);
	$data = json_decode($json, true);

	if (json_last_error() !== JSON_ERROR_NONE) return array();

	$all = array();
	if (isset($data['rules']) && is_array($data['rules'])) {
		foreach ($data['rules'] as $rule) {
			if (isset($rule['id'])) {
				$all[] = $rule;
			}
		}
	}
	return $all;
}

// ── Target Resolver ──────────────────────────────────────────────────────────

function sswaf_get_target_value($target) {

	// phpcs:disable WordPress.Security.ValidatedSanitizedInput -- WAF intentionally inspects raw unsanitized input
	switch ($target) {
		case 'REQUEST_URI':
			return isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
		case 'QUERY_STRING':
			return isset($_SERVER['QUERY_STRING']) ? $_SERVER['QUERY_STRING'] : '';
		case 'USER_AGENT':
			return isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
		case 'REFERER':
			return isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '';
		case 'COOKIE':
			return isset($_SERVER['HTTP_COOKIE']) ? $_SERVER['HTTP_COOKIE'] : '';
		case 'POST':
			return null; // Handled separately in the engine
		default:
			return '';
	}
	// phpcs:enable WordPress.Security.ValidatedSanitizedInput
}

// ── POST Data Flattener ──────────────────────────────────────────────────────

function sswaf_flatten_post($data, $depth = 0) {

	$values = array();

	// Prevent deep recursion abuse
	if ($depth > 10) return $values;

	if (!is_array($data)) {
		if (is_string($data) && $data !== '') {
			$values[] = $data;
		}
		return $values;
	}

	foreach ($data as $value) {
		if (is_array($value)) {
			$values = array_merge($values, sswaf_flatten_post($value, $depth + 1));
		} elseif (is_string($value) && $value !== '') {
			$values[] = $value;
		}
	}

	return $values;
}

// ── Log Directory & Path ─────────────────────────────────────────────────────

function sswaf_log_dir() {
	$upload = wp_upload_dir();
	return $upload['basedir'] . '/secure-owl-firewall/';
}

function sswaf_init_log_dir() {

	$log_dir = apply_filters('sswaf_log_dir', sswaf_log_dir());

	if (!is_dir($log_dir)) {
		wp_mkdir_p($log_dir);
	}

	// Blank index.php — prevents directory listing
	$index = $log_dir . 'index.php';
	if (!file_exists($index)) {
		@file_put_contents($index, "<?php\n// Silence is golden.\n");
	}

	// Generate a randomized log filename (.php) if not set
	if (get_option('sswaf_log_filename') === false) {
		$random = bin2hex(random_bytes(8));
		$filename = 'sswaf-' . $random . '.php';
		add_option('sswaf_log_filename', $filename);

		// Write the die guard as the very first line
		$log_path = $log_dir . $filename;
		@file_put_contents($log_path, "<?php if ( ! defined( 'ABSPATH' ) ) exit; ?>\n", LOCK_EX);
	}
}

function sswaf_get_log_path() {

	static $path = null;
	if ($path !== null) return $path;

	$log_dir  = apply_filters('sswaf_log_dir', sswaf_log_dir());
	$filename = get_option('sswaf_log_filename', '');

	// Fallback if option is missing (shouldn't happen after activation)
	if (empty($filename)) {
		$filename = 'sswaf-fallback.php';
	}

	$path = $log_dir . $filename;
	return $path;
}

/**
 * The die guard that sits on line 1 of every log file.
 * When accessed via browser/wget, PHP executes and dies.
 * When read by our plugin, we strip this line.
 */
function sswaf_get_log_guard() {
	return "<?php if ( ! defined( 'ABSPATH' ) ) exit; ?>\n";
}

// ── Logging ──────────────────────────────────────────────────────────────────

function sswaf_log($rule, $match, $target, $remote_addr) {

	$logging = get_option('sswaf_enable_logging', false);
	if (!$logging) return;

	$log_file = apply_filters('sswaf_log_file', sswaf_get_log_path());
	$max_size = apply_filters('sswaf_log_max_size', SSWAF_LOG_MAX);

	// Ensure log directory exists (handles edge case: logging enabled before activation ran)
	$log_dir = dirname($log_file);
	if (!is_dir($log_dir)) {
		sswaf_init_log_dir();
	}

	// Ensure die guard is present (new file or was cleared)
	if (!file_exists($log_file) || filesize($log_file) === 0) {
		@file_put_contents($log_file, sswaf_get_log_guard(), LOCK_EX);
	}

	// Rotate: if log exceeds max size, truncate to keep the last half
	if (file_exists($log_file) && filesize($log_file) >= $max_size) {
		sswaf_rotate_log($log_file, $max_size);
	}

	$timestamp = gmdate('Y-m-d H:i:s');
	$rule_id   = isset($rule['id']) ? $rule['id'] : 0;
	$message   = isset($rule['message']) ? $rule['message'] : 'Unknown';
	$severity  = isset($rule['severity']) ? $rule['severity'] : 0;
	$match_str = is_array($match) && isset($match[0]) ? $match[0] : (string) $match;
	$uri       = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '-'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- logging raw URI for forensics

	// Sanitize for log injection
	$match_str = str_replace(array("\r", "\n"), array('\\r', '\\n'), $match_str);
	$uri       = str_replace(array("\r", "\n"), array('\\r', '\\n'), $uri);
	$remote_addr = str_replace(array("\r", "\n"), '', $remote_addr);

	$entry = sprintf(
		"[%s] [severity:%d] [rule:%d] [ip:%s] [target:%s] [match:%s] [uri:%s] %s\n",
		$timestamp,
		$severity,
		$rule_id,
		$remote_addr,
		$target,
		$match_str,
		$uri,
		$message
	);

	@file_put_contents($log_file, $entry, FILE_APPEND | LOCK_EX);
}

function sswaf_rotate_log($log_file, $max_size) {

	$content = @file_get_contents($log_file);
	if ($content === false) return;

	// Strip the die guard before processing
	$guard = sswaf_get_log_guard();
	$guard_len = strlen($guard);
	if (substr($content, 0, $guard_len) === $guard) {
		$content = substr($content, $guard_len);
	}

	// Keep the last half of the file
	$half = (int) ($max_size / 2);
	$content = substr($content, -$half);

	// Find the first complete line
	$newline_pos = strpos($content, "\n");
	if ($newline_pos !== false) {
		$content = substr($content, $newline_pos + 1);
	}

	// Write back with die guard restored
	@file_put_contents($log_file, $guard . $content, LOCK_EX);
}

// ── Response Handler ─────────────────────────────────────────────────────────

function sswaf_block_request($rule, $matches, $target, $remote_addr) {

	do_action('sswaf_before_block', $rule, $matches, $target, $remote_addr);

	sswaf_log($rule, $matches, $target, $remote_addr);

	// Track hit for rate limiting (if enabled)
	sswaf_rate_limit_record($remote_addr, $rule);

	$header_status = apply_filters('sswaf_header_status', 'HTTP/1.1 403 Forbidden');
	$header_connection = apply_filters('sswaf_header_connection', 'Connection: Close');

	header($header_status);
	header('Status: 403 Forbidden');
	header($header_connection);

	exit();
}

// ── Rate Limiting (optional module) ──────────────────────────────────────────

function sswaf_rate_limit_enabled() {
	return (bool) get_option('sswaf_rate_limiting', false);
}

function sswaf_rate_limit_ip_key($ip) {
	return 'sswaf_hits_' . md5($ip);
}

function sswaf_rate_limit_ban_key($ip) {
	return 'sswaf_ban_' . md5($ip);
}

function sswaf_rate_limit_subnet_key($ip) {
	// Extract /24 subnet for IPv4, /64 prefix for IPv6
	$subnet = sswaf_get_subnet($ip);
	return 'sswaf_sub_' . md5($subnet);
}

function sswaf_rate_limit_subnet_ban_key($ip) {
	$subnet = sswaf_get_subnet($ip);
	return 'sswaf_sban_' . md5($subnet);
}

function sswaf_get_subnet($ip) {
	if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
		// /64 prefix: first 4 groups
		$expanded = inet_pton($ip);
		if ($expanded !== false) {
			return substr(bin2hex($expanded), 0, 16);
		}
	}
	// IPv4 /24: first 3 octets
	$parts = explode('.', $ip);
	if (count($parts) === 4) {
		return $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.0';
	}
	return $ip;
}

/**
 * Check if an IP is currently banned by rate limiter.
 * Returns true if banned (caller should block immediately).
 */
function sswaf_rate_limit_check($remote_addr) {

	if (!sswaf_rate_limit_enabled()) return false;

	// Check IP ban
	if (get_transient(sswaf_rate_limit_ban_key($remote_addr))) {
		return true;
	}

	// Check subnet ban (if enabled)
	$subnet_enabled = (bool) get_option('sswaf_rate_limit_subnet', false);
	if ($subnet_enabled && get_transient(sswaf_rate_limit_subnet_ban_key($remote_addr))) {
		return true;
	}

	return false;
}

/**
 * Record a block event for rate limiting. Increment counters, apply bans.
 */
function sswaf_rate_limit_record($remote_addr, $rule) {

	if (!sswaf_rate_limit_enabled()) return;

	$ip_threshold  = (int) apply_filters('sswaf_rate_limit_ip_threshold', get_option('sswaf_rate_limit_ip_threshold', 10));
	$ip_duration   = (int) apply_filters('sswaf_rate_limit_ip_duration', get_option('sswaf_rate_limit_ip_duration', 10));
	$ip_window     = (int) apply_filters('sswaf_rate_limit_ip_window', get_option('sswaf_rate_limit_ip_window', 60));

	// ── IP-level tracking ────────────────────────────────────────────────

	$hits_key = sswaf_rate_limit_ip_key($remote_addr);
	$hits = get_transient($hits_key);

	if ($hits === false) {
		$hits = 0;
	}

	$hits++;
	set_transient($hits_key, $hits, $ip_window);

	if ($hits >= $ip_threshold) {
		$ban_key = sswaf_rate_limit_ban_key($remote_addr);
		set_transient($ban_key, true, $ip_duration);

		// Log the ban event
		sswaf_log(
			array('id' => 0, 'severity' => 2, 'message' => sprintf('Rate limit: IP banned for %ds (%d hits in %ds)', $ip_duration, $hits, $ip_window)),
			array($remote_addr),
			'RATE_LIMIT',
			$remote_addr
		);

		// Reset counter after ban
		delete_transient($hits_key);
	}

	// ── Subnet-level tracking ────────────────────────────────────────────

	$subnet_enabled   = (bool) get_option('sswaf_rate_limit_subnet', false);
	if (!$subnet_enabled) return;

	$sub_threshold = (int) apply_filters('sswaf_rate_limit_subnet_threshold', get_option('sswaf_rate_limit_subnet_threshold', 30));
	$sub_duration  = (int) apply_filters('sswaf_rate_limit_subnet_duration', get_option('sswaf_rate_limit_subnet_duration', 10));
	$sub_window    = (int) apply_filters('sswaf_rate_limit_subnet_window', get_option('sswaf_rate_limit_subnet_window', 120));

	$sub_hits_key = sswaf_rate_limit_subnet_key($remote_addr);
	$sub_hits = get_transient($sub_hits_key);

	if ($sub_hits === false) {
		$sub_hits = 0;
	}

	$sub_hits++;
	set_transient($sub_hits_key, $sub_hits, $sub_window);

	if ($sub_hits >= $sub_threshold) {
		$sub_ban_key = sswaf_rate_limit_subnet_ban_key($remote_addr);
		set_transient($sub_ban_key, true, $sub_duration);

		$subnet = sswaf_get_subnet($remote_addr);
		sswaf_log(
			array('id' => 0, 'severity' => 2, 'message' => sprintf('Rate limit: subnet %s banned for %ds (%d hits in %ds)', $subnet, $sub_duration, $sub_hits, $sub_window)),
			array($subnet),
			'RATE_LIMIT_SUBNET',
			$remote_addr
		);

		delete_transient($sub_hits_key);
	}
}

// ── Get Remote IP ────────────────────────────────────────────────────────────

function sswaf_get_remote_addr() {

	// phpcs:disable WordPress.Security.ValidatedSanitizedInput -- WAF reads raw server variables for IP resolution
	// Respect common proxy headers if trusted
	$trusted_proxies = apply_filters('sswaf_trusted_proxies', array());
	$remote_addr = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '0.0.0.0';

	if (!empty($trusted_proxies) && in_array($remote_addr, $trusted_proxies, true)) {
		if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
			$ips = explode(',', sanitize_text_field(wp_unslash($_SERVER['HTTP_X_FORWARDED_FOR'])));
			$candidate = trim($ips[0]);
			if (filter_var($candidate, FILTER_VALIDATE_IP)) {
				$remote_addr = $candidate;
			}
		} elseif (!empty($_SERVER['HTTP_X_REAL_IP'])) {
			$candidate = sanitize_text_field(wp_unslash($_SERVER['HTTP_X_REAL_IP']));
			if (filter_var($candidate, FILTER_VALIDATE_IP)) {
				$remote_addr = $candidate;
			}
		}
	}
	// phpcs:enable WordPress.Security.ValidatedSanitizedInput

	return $remote_addr;
}

// ── Core Engine ──────────────────────────────────────────────────────────────

function sswaf_core() {

	$data     = sswaf_load_rules();
	$settings = $data['settings'];
	$rules    = $data['rules'];

	if (empty($rules)) return;

	$remote_addr = sswaf_get_remote_addr();

	// ── Whitelist check ──────────────────────────────────────────────────

	$whitelist = apply_filters('sswaf_ip_whitelist', array());
	if (!empty($whitelist) && in_array($remote_addr, $whitelist, true)) {
		return;
	}

	// ── Rate limit ban check (short-circuits all rule processing) ────────

	if (sswaf_rate_limit_check($remote_addr)) {
		$ban_rule = array(
			'id'       => 0,
			'severity' => 2,
			'message'  => 'Request blocked by rate limiter',
		);
		sswaf_log($ban_rule, array('rate_limited'), 'RATE_LIMIT', $remote_addr);

		$header_status = apply_filters('sswaf_header_status', 'HTTP/1.1 403 Forbidden');
		header($header_status);
		header('Status: 403 Forbidden');
		header('Connection: Close');
		exit();
	}

	// ── Long request check ───────────────────────────────────────────────

	$block_long     = isset($settings['block_long_requests']) ? $settings['block_long_requests'] : true;
	$max_req_length = isset($settings['max_request_length']) ? (int) $settings['max_request_length'] : 1000;
	$max_ref_length = isset($settings['max_referrer_length']) ? (int) $settings['max_referrer_length'] : 1000;

	// phpcs:disable WordPress.Security.ValidatedSanitizedInput -- WAF inspects raw request data
	$request_uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
	$referrer    = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '';
	// phpcs:enable WordPress.Security.ValidatedSanitizedInput

	if ($block_long) {
		if (strlen($request_uri) > $max_req_length || strlen($referrer) > $max_ref_length) {
			$long_rule = array(
				'id'       => 0,
				'severity' => 3,
				'message'  => 'Request exceeded maximum length',
			);
			sswaf_block_request($long_rule, array('length_exceeded'), 'REQUEST_LENGTH', $remote_addr);
		}
	}

	// ── Group rules by target for efficiency ─────────────────────────────

	$grouped = array();
	foreach ($rules as $rule) {
		$target = isset($rule['target']) ? $rule['target'] : '';
		if (!isset($grouped[$target])) {
			$grouped[$target] = array();
		}
		$grouped[$target][] = $rule;
	}

	// ── Check non-POST targets ───────────────────────────────────────────

	$non_post_targets = array('REQUEST_URI', 'QUERY_STRING', 'USER_AGENT', 'REFERER', 'COOKIE');

	foreach ($non_post_targets as $target) {
		if (!isset($grouped[$target])) continue;

		$raw_value = sswaf_get_target_value($target);
		if ($raw_value === '' || $raw_value === null) continue;

		foreach ($grouped[$target] as $rule) {
			$pattern = isset($rule['pattern']) ? $rule['pattern'] : '';
			if ($pattern === '') continue;

			$transforms = isset($rule['transformations']) ? $rule['transformations'] : array();
			$value = sswaf_apply_transforms($raw_value, $transforms);

			$matches = array();
			// Use PCRE with error suppression for malformed patterns
			if (@preg_match('/' . $pattern . '/i', $value, $matches)) {
				sswaf_block_request($rule, $matches, $target, $remote_addr);
			}
		}
	}

	// ── Check POST target ────────────────────────────────────────────────

	$post_scanning = apply_filters('sswaf_post_scanning', true);

	// phpcs:disable WordPress.Security.NonceVerification.Missing -- WAF inspects all POST data for malicious content, nonce not applicable
	if ($post_scanning && isset($grouped['POST']) && !empty($_POST)) {

		$post_values = sswaf_flatten_post($_POST);
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		foreach ($grouped['POST'] as $rule) {
			$pattern = isset($rule['pattern']) ? $rule['pattern'] : '';
			if ($pattern === '') continue;

			$transforms = isset($rule['transformations']) ? $rule['transformations'] : array();

			foreach ($post_values as $post_value) {
				$value = sswaf_apply_transforms($post_value, $transforms);

				$matches = array();
				if (@preg_match('/' . $pattern . '/i', $value, $matches)) {
					sswaf_block_request($rule, $matches, 'POST', $remote_addr);
				}
			}
		}
	}
}
// ── Core Hook (mu-plugin aware) ──────────────────────────────────────────────

if (defined('SSWAF_MU_LOADED') && SSWAF_MU_LOADED) {
	// Loaded early by mu-plugin loader — hook on muplugins_loaded
	// (fires after all mu-plugins are included, before regular plugins)
	add_action('muplugins_loaded', 'sswaf_core', 0);
} else {
	// Fallback: loaded as regular plugin (mu-loader missing or failed)
	add_action('plugins_loaded', 'sswaf_core', 0);
}

// ── Admin Settings ───────────────────────────────────────────────────────────

if (is_admin()) {
	$sswaf_settings_file = SSWAF_DIR . 'sswaf-settings.php';
	if (file_exists($sswaf_settings_file)) {
		require_once $sswaf_settings_file;
	}
}

// ── MU-Plugin Loader Management ──────────────────────────────────────────────

function sswaf_get_mu_loader_content() {

	// The loader is minimal: check that the main plugin exists, then require it.
	// SSWAF_MU_LOADED constant tells the engine to hook on muplugins_loaded.
	$plugin_file = str_replace("'", "\\'", SSWAF_DIR . 'sswaf.php');

	$content  = "<?php\n";
	$content .= "/*\n";
	$content .= "\tSSWAF MU-Plugin Loader\n";
	$content .= "\tAuto-generated by Secure Owl Firewall. Do not edit.\n";
	$content .= "\tLoads the firewall engine before regular plugins for earliest protection.\n";
	$content .= "*/\n";
	$content .= "if (!defined('ABSPATH')) die();\n\n";
	$content .= "\$sswaf_plugin = '" . $plugin_file . "';\n\n";
	$content .= "if (file_exists(\$sswaf_plugin)) {\n";
	$content .= "\tdefine('SSWAF_MU_LOADED', true);\n";
	$content .= "\trequire_once \$sswaf_plugin;\n";
	$content .= "}\n";

	return $content;
}

function sswaf_install_mu_loader() {

	$mu_dir = WPMU_PLUGIN_DIR;

	// Create mu-plugins directory if it doesn't exist
	if (!is_dir($mu_dir)) {
		$created = wp_mkdir_p($mu_dir);
		if (!$created) return false;
	}

	$result = @file_put_contents(SSWAF_MU_FILE, sswaf_get_mu_loader_content(), LOCK_EX);
	return $result !== false;
}

function sswaf_remove_mu_loader() {

	if (file_exists(SSWAF_MU_FILE)) {
		return wp_delete_file(SSWAF_MU_FILE);
	}
	return true;
}

function sswaf_mu_loader_active() {
	return file_exists(SSWAF_MU_FILE);
}

// ── Activation / Deactivation ────────────────────────────────────────────────

register_activation_hook(__FILE__, 'sswaf_activate');
function sswaf_activate() {
	// Set default options
	if (get_option('sswaf_enable_logging') === false) {
		add_option('sswaf_enable_logging', false);
	}
	if (get_option('sswaf_disabled_rules') === false) {
		add_option('sswaf_disabled_rules', array());
	}
	// Rate limiting defaults (module off by default)
	if (get_option('sswaf_rate_limiting') === false) {
		add_option('sswaf_rate_limiting', false);
		add_option('sswaf_rate_limit_ip_threshold', 10);
		add_option('sswaf_rate_limit_ip_duration', 10);
		add_option('sswaf_rate_limit_ip_window', 60);
		add_option('sswaf_rate_limit_subnet', false);
		add_option('sswaf_rate_limit_subnet_threshold', 30);
		add_option('sswaf_rate_limit_subnet_duration', 10);
		add_option('sswaf_rate_limit_subnet_window', 120);
	}
	// Create log directory with protections and randomized filename
	sswaf_init_log_dir();
	// Install mu-plugin loader for early execution
	sswaf_install_mu_loader();
}

register_deactivation_hook(__FILE__, 'sswaf_deactivate');
function sswaf_deactivate() {
	// Remove mu-plugin loader
	sswaf_remove_mu_loader();
	// Cleanup is intentionally minimal - keep options and log
	// for potential reactivation. Full cleanup in uninstall.php.
}
