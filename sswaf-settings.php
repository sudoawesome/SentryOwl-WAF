<?php
/*
	Secure Owl Firewall - Admin Settings
	Handles the settings page, logging toggle, and log viewer.
*/

if (!defined('ABSPATH')) die();

// ── Menu & Page Registration ─────────────────────────────────────────────────

add_action('admin_menu', 'sswaf_admin_menu');
function sswaf_admin_menu() {
	add_options_page(
		'Secure Owl Firewall',
		'Secure Owl Firewall',
		'manage_options',
		'sswaf-settings',
		'sswaf_settings_page'
	);
}

add_filter('plugin_action_links_' . SSWAF_BASE_FILE, 'sswaf_action_links');
function sswaf_action_links($links) {
	$settings_link = '<a href="' . admin_url('options-general.php?page=sswaf-settings') . '">' . __('Settings', 'secure-owl-firewall') . '</a>';
	array_unshift($links, $settings_link);
	return $links;
}

add_action('admin_enqueue_scripts', 'sswaf_admin_enqueue');
function sswaf_admin_enqueue($hook) {
	if ('settings_page_sswaf-settings' !== $hook) return;
	wp_enqueue_script(
		'sswaf-admin-js',
		plugins_url('sswaf-admin.js', __FILE__),
		array(),
		SSWAF_VERSION,
		true
	);
	wp_localize_script('sswaf-admin-js', 'sswaf_admin', array(
		'nonce'    => wp_create_nonce('sswaf_toggle_rule_nonce'),
		'ajax_url' => admin_url('admin-ajax.php'),
	));
}

// ── Settings Registration ────────────────────────────────────────────────────

add_action('admin_init', 'sswaf_register_settings');
function sswaf_register_settings() {
	register_setting('sswaf_options', 'sswaf_enable_logging', array(
		'type'              => 'boolean',
		'sanitize_callback' => 'rest_sanitize_boolean',
		'default'           => false,
	));
	register_setting('sswaf_options', 'sswaf_rate_limiting', array(
		'type'              => 'boolean',
		'sanitize_callback' => 'rest_sanitize_boolean',
		'default'           => false,
	));
	register_setting('sswaf_options', 'sswaf_rate_limit_ip_threshold', array(
		'type'              => 'integer',
		'sanitize_callback' => 'absint',
		'default'           => 10,
	));
	register_setting('sswaf_options', 'sswaf_rate_limit_ip_duration', array(
		'type'              => 'integer',
		'sanitize_callback' => 'absint',
		'default'           => 10,
	));
	register_setting('sswaf_options', 'sswaf_rate_limit_ip_window', array(
		'type'              => 'integer',
		'sanitize_callback' => 'absint',
		'default'           => 60,
	));
	register_setting('sswaf_options', 'sswaf_rate_limit_subnet', array(
		'type'              => 'boolean',
		'sanitize_callback' => 'rest_sanitize_boolean',
		'default'           => false,
	));
	register_setting('sswaf_options', 'sswaf_rate_limit_subnet_threshold', array(
		'type'              => 'integer',
		'sanitize_callback' => 'absint',
		'default'           => 30,
	));
	register_setting('sswaf_options', 'sswaf_rate_limit_subnet_duration', array(
		'type'              => 'integer',
		'sanitize_callback' => 'absint',
		'default'           => 10,
	));
	register_setting('sswaf_options', 'sswaf_rate_limit_subnet_window', array(
		'type'              => 'integer',
		'sanitize_callback' => 'absint',
		'default'           => 120,
	));
}

// ── Admin POST Handlers ──────────────────────────────────────────────────────

add_action('admin_init', 'sswaf_handle_actions');
function sswaf_handle_actions() {
	
	if (!current_user_can('manage_options')) return;
	
	// Clear log
	if (isset($_POST['sswaf_clear_log'])) {
		check_admin_referer('sswaf_clear_log_action');
		$log_file = apply_filters('sswaf_log_file', sswaf_get_log_path());
		if (file_exists($log_file)) {
			@file_put_contents($log_file, sswaf_get_log_guard(), LOCK_EX);
		}
		wp_safe_redirect(add_query_arg(array('page' => 'sswaf-settings', 'cleared' => '1'), admin_url('options-general.php')));
		exit;
	}
	
	// Download log (served through PHP — never directly accessible)
	if (isset($_GET['sswaf_download_log']) && $_GET['sswaf_download_log'] === '1') {
		if (!isset($_GET['_wpnonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_GET['_wpnonce'])), 'sswaf_download_log_action')) {
			wp_die('Security check failed.');
		}
		$log_file = apply_filters('sswaf_log_file', sswaf_get_log_path());
		if (file_exists($log_file) && filesize($log_file) > 0) {
			$content = file_get_contents($log_file);
			// Strip die guard before serving
			$guard = sswaf_get_log_guard();
			if (substr($content, 0, strlen($guard)) === $guard) {
				$content = substr($content, strlen($guard));
			}
			header('Content-Type: text/plain');
			header('Content-Disposition: attachment; filename="sswaf-' . gmdate('Y-m-d') . '.log"');
			header('Content-Length: ' . strlen($content));
			echo esc_html($content);
			exit;
		}
		wp_safe_redirect(add_query_arg(array('page' => 'sswaf-settings'), admin_url('options-general.php')));
		exit;
	}
	
	// Repair / reinstall MU-Plugin loader
	if (isset($_POST['sswaf_repair_mu'])) {
		check_admin_referer('sswaf_repair_mu_action');
		$installed = sswaf_install_mu_loader();
		$status = $installed ? 'mu_installed' : 'mu_failed';
		wp_safe_redirect(add_query_arg(array('page' => 'sswaf-settings', $status => '1'), admin_url('options-general.php')));
		exit;
	}
}

// ── AJAX: Rule Toggle ────────────────────────────────────────────────────────

add_action('wp_ajax_sswaf_toggle_rule', 'sswaf_ajax_toggle_rule');
function sswaf_ajax_toggle_rule() {
	
	if (!current_user_can('manage_options')) {
		wp_send_json_error('Unauthorized', 403);
	}
	
	check_ajax_referer('sswaf_toggle_rule_nonce', 'nonce');
	
	$rule_id = isset($_POST['rule_id']) ? (int) $_POST['rule_id'] : 0;
	$action  = isset($_POST['toggle_action']) ? sanitize_text_field(wp_unslash($_POST['toggle_action'])) : '';
	
	if ($rule_id < 1 || !in_array($action, array('enable', 'disable'), true)) {
		wp_send_json_error('Invalid request');
	}
	
	$disabled = get_option('sswaf_disabled_rules', array());
	if (!is_array($disabled)) $disabled = array();
	
	if ($action === 'disable') {
		if (!in_array($rule_id, $disabled, true)) {
			$disabled[] = $rule_id;
		}
	} else {
		$disabled = array_values(array_diff($disabled, array($rule_id)));
	}
	
	update_option('sswaf_disabled_rules', $disabled);
	
	wp_send_json_success(array(
		'rule_id' => $rule_id,
		'action'  => $action,
		'disabled_count' => count($disabled),
	));
}

// ── Helper: Get Rule Stats ───────────────────────────────────────────────────

function sswaf_get_rule_stats() {
	
	$rules_file = apply_filters('sswaf_rules_file', SSWAF_RULES);
	$stats = array(
		'file_exists' => false,
		'total'       => 0,
		'enabled'     => 0,
		'disabled'    => 0,
		'by_target'   => array(),
		'version'     => '-',
		'updated'     => '-',
	);
	
	if (!file_exists($rules_file) || !is_readable($rules_file)) return $stats;
	
	$json = file_get_contents($rules_file);
	$data = json_decode($json, true);
	if (json_last_error() !== JSON_ERROR_NONE) return $stats;
	
	$stats['file_exists'] = true;
	
	if (isset($data['metadata']['version'])) $stats['version'] = $data['metadata']['version'];
	if (isset($data['metadata']['updated'])) $stats['updated'] = $data['metadata']['updated'];
	
	$disabled_ids = get_option('sswaf_disabled_rules', array());
	if (!is_array($disabled_ids)) $disabled_ids = array();
	
	if (isset($data['rules']) && is_array($data['rules'])) {
		foreach ($data['rules'] as $rule) {
			if (!isset($rule['id'])) continue;
			$stats['total']++;
			
			$in_json   = isset($rule['enabled']) && $rule['enabled'] === true;
			$user_off  = in_array($rule['id'], $disabled_ids, true);
			$effective = $in_json && !$user_off;
			
			if ($effective) {
				$stats['enabled']++;
			} else {
				$stats['disabled']++;
			}
			
			$target = isset($rule['target']) ? $rule['target'] : 'UNKNOWN';
			if (!isset($stats['by_target'][$target])) {
				$stats['by_target'][$target] = array('enabled' => 0, 'disabled' => 0);
			}
			if ($effective) {
				$stats['by_target'][$target]['enabled']++;
			} else {
				$stats['by_target'][$target]['disabled']++;
			}
		}
	}
	
	return $stats;
}

// ── Helper: Read Recent Log Entries ──────────────────────────────────────────

function sswaf_get_recent_log_entries($count = 50) {
	
	$log_file = apply_filters('sswaf_log_file', sswaf_get_log_path());
	$guard = trim(sswaf_get_log_guard());
	
	if (!file_exists($log_file) || filesize($log_file) === 0) return array();
	
	// File contains only the die guard — no actual entries
	$guard_size = strlen(sswaf_get_log_guard());
	if (filesize($log_file) <= $guard_size) return array();
	
	// Read file contents using WP_Filesystem-compatible approach
	$content = file_get_contents($log_file); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- reading local log file
	if ($content === false) return array();
	
	$lines = explode("\n", trim($content));
	
	// Filter out die guard and empty lines
	$lines = array_filter($lines, function($line) use ($guard) {
		return $line !== '' && $line !== $guard;
	});
	
	$lines = array_slice($lines, -$count);
	return array_reverse($lines);
}

// ── Settings Page Output ─────────────────────────────────────────────────────

function sswaf_settings_page() {
	
	if (!current_user_can('manage_options')) return;
	
	$logging_enabled = get_option('sswaf_enable_logging', false);
	$rule_stats      = sswaf_get_rule_stats();
	$log_file        = apply_filters('sswaf_log_file', sswaf_get_log_path());
	$log_size        = file_exists($log_file) ? filesize($log_file) : 0;
	$log_entries     = $logging_enabled ? sswaf_get_recent_log_entries(50) : array();
	// phpcs:disable WordPress.Security.NonceVerification.Recommended -- display-only status flags, no data processing
	$cleared         = isset($_GET['cleared']) && $_GET['cleared'] === '1';
	$mu_installed    = isset($_GET['mu_installed']) && $_GET['mu_installed'] === '1';
	$mu_failed       = isset($_GET['mu_failed']) && $_GET['mu_failed'] === '1';
	// phpcs:enable WordPress.Security.NonceVerification.Recommended
	
	?>
	<div class="wrap">
		<h1>Secure Owl Firewall</h1>
		<p>Smart rule-based protection that blocks threats and secures your site from attacks.</p>
		
		<?php if ($cleared) : ?>
			<div class="notice notice-success is-dismissible"><p>Log cleared successfully.</p></div>
		<?php endif; ?>
		
		<?php if ($mu_installed) : ?>
			<div class="notice notice-success is-dismissible"><p>MU-Plugin loader installed successfully. The firewall will run at earliest priority on the next request.</p></div>
		<?php endif; ?>
		
		<?php if ($mu_failed) : ?>
			<div class="notice notice-error is-dismissible"><p>Failed to install MU-Plugin loader. Check that <code><?php echo esc_html(WPMU_PLUGIN_DIR); ?></code> is writable.</p></div>
		<?php endif; ?>
		
		<?php if (!$rule_stats['file_exists']) : ?>
			<div class="notice notice-error"><p><strong>Warning:</strong> Rules file not found. The firewall is not active. Expected location: <code><?php echo esc_html(SSWAF_RULES); ?></code></p></div>
		<?php endif; ?>
		
		<!-- Rule Stats -->
		<div class="card" style="max-width:720px;">
			<h2>Rule Statistics</h2>
			<table class="widefat striped" style="max-width:680px;">
				<tbody>
					<tr>
						<td><strong>Ruleset version</strong></td>
						<td><?php echo esc_html($rule_stats['version']); ?> (<?php echo esc_html($rule_stats['updated']); ?>)</td>
					</tr>
					<tr>
						<td><strong>Total rules</strong></td>
						<td><?php echo (int) $rule_stats['total']; ?> (<?php echo (int) $rule_stats['enabled']; ?> enabled, <?php echo (int) $rule_stats['disabled']; ?> disabled)</td>
					</tr>
					<?php foreach ($rule_stats['by_target'] as $target => $counts) : ?>
						<tr>
							<td>&nbsp;&nbsp;&nbsp;<?php echo esc_html($target); ?></td>
							<td><?php echo (int) $counts['enabled']; ?> enabled<?php if ($counts['disabled'] > 0) echo ', ' . (int) $counts['disabled'] . ' disabled'; ?></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		
		<br>
		
		<!-- Settings Form -->
		<div class="card" style="max-width:720px;">
			<h2>Settings</h2>
			<form method="post" action="options.php">
				<?php settings_fields('sswaf_options'); ?>
				<?php
				$rate_enabled     = get_option('sswaf_rate_limiting', false);
				$ip_threshold     = get_option('sswaf_rate_limit_ip_threshold', 10);
				$ip_duration      = get_option('sswaf_rate_limit_ip_duration', 10);
				$ip_window        = get_option('sswaf_rate_limit_ip_window', 60);
				$subnet_enabled   = get_option('sswaf_rate_limit_subnet', false);
				$subnet_threshold = get_option('sswaf_rate_limit_subnet_threshold', 30);
				$subnet_duration  = get_option('sswaf_rate_limit_subnet_duration', 10);
				$subnet_window    = get_option('sswaf_rate_limit_subnet_window', 120);
				?>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row">Enable logging</th>
						<td>
							<label>
								<input type="checkbox" name="sswaf_enable_logging" value="1" <?php checked($logging_enabled); ?>>
								Log blocked requests to <code><?php echo esc_html($log_file); ?></code>
							</label>
							<p class="description">Max log size: <?php echo esc_html(size_format(SSWAF_LOG_MAX)); ?>. Auto-rotated when exceeded.</p>
						</td>
					</tr>
					<tr>
						<th scope="row">Rate limiting</th>
						<td>
							<label>
								<input type="checkbox" name="sswaf_rate_limiting" value="1" <?php checked($rate_enabled); ?> id="sswaf-rate-toggle">
								Temporarily ban IPs that trigger too many blocks
							</label>
							<p class="description">Uses transients for storage. Zero overhead when disabled. With object cache (Redis/Memcached), checks are in-memory.</p>
						</td>
					</tr>
				</table>
				
				<div id="sswaf-rate-settings" style="<?php if (!$rate_enabled) echo 'display:none;'; ?> margin-left:10px; padding:12px 16px; border-left:3px solid #2271b1; background:#f6f7f7;">
					<h4 style="margin-top:0;">IP Rate Limiting</h4>
					<table class="form-table" role="presentation" style="margin-top:0;">
						<tr>
							<th scope="row">Threshold</th>
							<td>
								<input type="number" name="sswaf_rate_limit_ip_threshold" value="<?php echo (int) $ip_threshold; ?>" min="3" max="100" style="width:70px;">
								blocks within
								<input type="number" name="sswaf_rate_limit_ip_window" value="<?php echo (int) $ip_window; ?>" min="10" max="3600" style="width:70px;">
								seconds
								<p class="description">How many blocks before the IP gets banned.</p>
							</td>
						</tr>
						<tr>
							<th scope="row">Ban duration</th>
							<td>
								<input type="number" name="sswaf_rate_limit_ip_duration" value="<?php echo (int) $ip_duration; ?>" min="5" max="86400" style="width:70px;">
								seconds
								<p class="description">How long the IP stays banned. During ban, all requests are rejected without running rules (performance win).</p>
							</td>
						</tr>
					</table>
					
					<h4>Subnet Rate Limiting</h4>
					<table class="form-table" role="presentation" style="margin-top:0;">
						<tr>
							<th scope="row">Enable</th>
							<td>
								<label>
									<input type="checkbox" name="sswaf_rate_limit_subnet" value="1" <?php checked($subnet_enabled); ?>>
									Also track /24 subnets (IPv4) and /64 prefixes (IPv6)
								</label>
								<p class="description">Higher risk of false positives on shared hosting or mobile networks. Use with caution.</p>
							</td>
						</tr>
						<tr>
							<th scope="row">Threshold</th>
							<td>
								<input type="number" name="sswaf_rate_limit_subnet_threshold" value="<?php echo (int) $subnet_threshold; ?>" min="10" max="500" style="width:70px;">
								blocks within
								<input type="number" name="sswaf_rate_limit_subnet_window" value="<?php echo (int) $subnet_window; ?>" min="30" max="7200" style="width:70px;">
								seconds
							</td>
						</tr>
						<tr>
							<th scope="row">Ban duration</th>
							<td>
								<input type="number" name="sswaf_rate_limit_subnet_duration" value="<?php echo (int) $subnet_duration; ?>" min="5" max="86400" style="width:70px;">
								seconds
							</td>
						</tr>
					</table>
				</div>
				
				<?php submit_button('Save Settings'); ?>
			</form>
		</div>
		
		<br>
		
		<!-- Rule Management -->
		<div class="card" style="max-width:960px;">
			<h2>Rule Management</h2>
			<p>Toggle individual rules on/off. Changes take effect immediately. Disabled rules are stored separately and survive rule file updates.</p>
			
			<?php
			$all_rules   = sswaf_load_all_rules();
			$disabled_ids = get_option('sswaf_disabled_rules', array());
			if (!is_array($disabled_ids)) $disabled_ids = array();
			
			// Collect unique targets for filter
			$targets = array();
			foreach ($all_rules as $r) {
				$t = isset($r['target']) ? $r['target'] : '';
				if ($t && !in_array($t, $targets, true)) $targets[] = $t;
			}
			sort($targets);
			?>
			
			<div style="display:flex; gap:10px; margin-bottom:12px; align-items:center; flex-wrap:wrap;">
				<input type="text" id="sswaf-rule-search" placeholder="Search rules (ID, message, tag)..." style="width:300px;">
				<select id="sswaf-rule-filter-target">
					<option value="">All targets</option>
					<?php foreach ($targets as $t) : ?>
						<option value="<?php echo esc_attr($t); ?>"><?php echo esc_html($t); ?></option>
					<?php endforeach; ?>
				</select>
				<select id="sswaf-rule-filter-status">
					<option value="">All statuses</option>
					<option value="enabled">Enabled only</option>
					<option value="disabled">Disabled only</option>
				</select>
				<span id="sswaf-rule-count" style="color:#646970; font-size:13px;"></span>
			</div>
			
			<div style="max-height:500px; overflow-y:auto; border:1px solid #c3c4c7; border-radius:4px;">
				<table class="widefat striped" id="sswaf-rules-table" style="margin:0;">
					<thead style="position:sticky; top:0; background:#f0f0f1; z-index:1;">
						<tr>
							<th style="width:60px;">Status</th>
							<th style="width:50px;">ID</th>
							<th style="width:110px;">Target</th>
							<th style="width:50px;">Sev.</th>
							<th>Message</th>
							<th style="width:140px;">Tags</th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ($all_rules as $rule) :
							$rid        = (int) $rule['id'];
							$in_json    = isset($rule['enabled']) && $rule['enabled'] === true;
							$user_off   = in_array($rid, $disabled_ids, true);
							$effective  = $in_json && !$user_off;
							$can_toggle = $in_json; // Only JSON-enabled rules can be toggled
							$tags_str   = isset($rule['tags']) ? implode(', ', $rule['tags']) : '';
							$severity   = isset($rule['severity']) ? (int) $rule['severity'] : 0;
							$message    = isset($rule['message']) ? $rule['message'] : '';
							$target     = isset($rule['target']) ? $rule['target'] : '';
						?>
						<tr class="sswaf-rule-row" 
						    data-id="<?php echo intval($rid); ?>" 
						    data-target="<?php echo esc_attr($target); ?>" 
						    data-status="<?php echo $effective ? 'enabled' : 'disabled'; ?>"
						    data-search="<?php echo esc_attr($rid . ' ' . strtolower($message . ' ' . $tags_str . ' ' . $target)); ?>"
						    style="<?php if (!$effective) echo 'opacity:0.6;'; ?>">
							<td>
								<?php if ($can_toggle) : ?>
									<button type="button" 
									        class="sswaf-toggle button button-small"
									        data-rule-id="<?php echo intval($rid); ?>"
									        data-action="<?php echo $effective ? 'disable' : 'enable'; ?>"
									        style="min-width:54px; color:<?php echo $effective ? '#00a32a' : '#dc3232'; ?>;">
										<?php echo $effective ? '&#10003; On' : '&#10007; Off'; ?>
									</button>
								<?php else : ?>
									<span style="color:#646970; font-size:12px;">Off (JSON)</span>
								<?php endif; ?>
							</td>
							<td><code><?php echo intval($rid); ?></code></td>
							<td><code style="font-size:11px;"><?php echo esc_html($target); ?></code></td>
							<td>
								<?php
								$sev_colors = array(1 => '#dc3232', 2 => '#d63638', 3 => '#dba617', 4 => '#72aee6', 5 => '#a7aaad');
								$sev_color = isset($sev_colors[$severity]) ? $sev_colors[$severity] : '#a7aaad';
								?>
								<span style="color:<?php echo esc_attr($sev_color); ?>; font-weight:600;"><?php echo intval($severity); ?></span>
							</td>
							<td><?php echo esc_html($message); ?></td>
							<td><span style="font-size:11px; color:#646970;"><?php echo esc_html($tags_str); ?></span></td>
						</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
			
			<?php if (!empty($disabled_ids)) : ?>
				<p style="margin-top:10px; color:#646970;">
					<strong><?php echo intval(count($disabled_ids)); ?></strong> rule(s) disabled by user:
					<code><?php echo esc_html(implode(', ', $disabled_ids)); ?></code>
				</p>
			<?php endif; ?>
		</div>
		
		<br>
		
		<!-- Log Viewer -->
		<div class="card" style="max-width:720px;">
			<h2>Firewall Log</h2>
			
			<?php if (!$logging_enabled) : ?>
				<p>Logging is currently disabled. Enable it above to start recording blocked requests.</p>
			<?php else : ?>
				<p>
					Log size: <strong><?php echo esc_html(size_format($log_size)); ?></strong> / <?php echo esc_html(size_format(SSWAF_LOG_MAX)); ?>
					<?php if ($log_size > 0) : ?>
						&nbsp;&mdash;&nbsp;showing last <?php echo intval(count($log_entries)); ?> entries (newest first)
					<?php endif; ?>
				</p>
				
				<div style="display:flex; gap:8px; margin-bottom:12px;">
					<?php if ($log_size > 0) : ?>
						<form method="post" style="display:inline;">
							<?php wp_nonce_field('sswaf_clear_log_action'); ?>
							<input type="submit" name="sswaf_clear_log" class="button" value="Clear Log" onclick="return confirm('Clear the entire log?');">
						</form>
						<?php
						$download_url = wp_nonce_url(
							add_query_arg(array('page' => 'sswaf-settings', 'sswaf_download_log' => '1'), admin_url('options-general.php')),
							'sswaf_download_log_action'
						);
						?>
						<a href="<?php echo esc_url($download_url); ?>" class="button">Download Log</a>
					<?php endif; ?>
				</div>
				
				<?php if (!empty($log_entries)) : ?>
					<?php $allowed_log_html = array('span' => array('style' => array())); ?>
					<div style="max-height:420px; overflow-y:auto; background:#1d2327; padding:10px 14px; border-radius:4px;">
						<pre style="color:#c3c4c7; font-size:12px; line-height:1.6; margin:0; white-space:pre-wrap; word-break:break-all;"><?php
							foreach ($log_entries as $entry) {
								$entry = esc_html($entry);
								// Highlight severity
								$entry = preg_replace('/\[severity:([12])\]/', '<span style="color:#dc3232;">[severity:$1]</span>', $entry);
								$entry = preg_replace('/\[severity:3\]/', '<span style="color:#dba617;">[severity:3]</span>', $entry);
								$entry = preg_replace('/\[severity:[45]\]/', '<span style="color:#72aee6;">[severity:$1]</span>', $entry);
								echo wp_kses($entry, $allowed_log_html) . "\n";
							}
						?></pre>
					</div>
				<?php elseif ($log_size === 0) : ?>
					<p><em>No entries yet. Blocked requests will appear here.</em></p>
				<?php endif; ?>
				
			<?php endif; ?>
		</div>
		
		<br>
		
		<!-- Plugin Info -->
		<div class="card" style="max-width:720px;">
			<h2>Plugin Info</h2>
			<?php
			$mu_active = sswaf_mu_loader_active();
			$mu_loaded = defined('SSWAF_MU_LOADED') && SSWAF_MU_LOADED;
			?>
			<table class="widefat striped" style="max-width:680px;">
				<tbody>
					<tr><td><strong>Version</strong></td><td><?php echo esc_html(SSWAF_VERSION); ?></td></tr>
					<tr>
						<td><strong>MU-Plugin loader</strong></td>
						<td>
							<?php if ($mu_active && $mu_loaded) : ?>
								<span style="color:#00a32a;">&#10003; Active</span> &mdash; engine runs on <code>muplugins_loaded</code> (earliest)
							<?php elseif ($mu_active && !$mu_loaded) : ?>
								<span style="color:#dba617;">&#9888; Installed but not loaded</span> &mdash; may require a page reload
							<?php else : ?>
								<span style="color:#dc3232;">&#10007; Not installed</span> &mdash; engine falls back to <code>plugins_loaded</code>
							<?php endif; ?>
						</td>
					</tr>
					<?php if (!$mu_active) : ?>
					<tr>
						<td></td>
						<td>
							<form method="post" style="display:inline;">
								<?php wp_nonce_field('sswaf_repair_mu_action'); ?>
								<input type="submit" name="sswaf_repair_mu" class="button button-small" value="Install MU-Plugin Loader">
							</form>
							<p class="description">Installs the loader to <code><?php echo esc_html(SSWAF_MU_FILE); ?></code></p>
						</td>
					</tr>
					<?php endif; ?>
					<tr><td><strong>Rules file</strong></td><td><code><?php echo esc_html(SSWAF_RULES); ?></code></td></tr>
					<tr><td><strong>Log file</strong></td><td><code><?php echo esc_html($log_file); ?></code></td></tr>
					<tr><td><strong>POST scanning</strong></td><td><?php echo apply_filters('sswaf_post_scanning', true) ? 'Enabled (default)' : 'Disabled'; ?></td></tr>
					<tr><td><strong>Rate limiting</strong></td><td><?php
						if (sswaf_rate_limit_enabled()) {
							$rl_ip = get_option('sswaf_rate_limit_ip_threshold', 10) . ' hits/' . get_option('sswaf_rate_limit_ip_window', 60) . 's → ban ' . get_option('sswaf_rate_limit_ip_duration', 10) . 's';
							echo 'Enabled (IP: ' . esc_html($rl_ip) . ')';
							if (get_option('sswaf_rate_limit_subnet', false)) {
								$rl_sub = get_option('sswaf_rate_limit_subnet_threshold', 30) . ' hits/' . get_option('sswaf_rate_limit_subnet_window', 120) . 's → ban ' . get_option('sswaf_rate_limit_subnet_duration', 10) . 's';
								echo ' + Subnet: ' . esc_html($rl_sub);
							}
						} else {
							echo 'Disabled';
						}
					?></td></tr>
					<tr><td><strong>IP whitelist</strong></td><td><?php $wl = apply_filters('sswaf_ip_whitelist', array()); echo !empty($wl) ? count($wl) . ' IPs whitelisted' : 'None'; ?></td></tr>
				</tbody>
			</table>
		</div>
		
	</div>
	<?php
}
