<?php
/*
	SentryOwl Firewall - Uninstall
	Removes all plugin data when the plugin is deleted.
*/

if (!defined('WP_UNINSTALL_PLUGIN')) die();

// Remove options
delete_option('sswaf_enable_logging');
delete_option('sswaf_disabled_rules');
delete_option('sswaf_log_filename');
delete_option('sswaf_rate_limiting');
delete_option('sswaf_rate_limit_ip_threshold');
delete_option('sswaf_rate_limit_ip_duration');
delete_option('sswaf_rate_limit_ip_window');
delete_option('sswaf_rate_limit_subnet');
delete_option('sswaf_rate_limit_subnet_threshold');
delete_option('sswaf_rate_limit_subnet_duration');
delete_option('sswaf_rate_limit_subnet_window');

// Remove mu-plugin loader
$sswaf_mu_file = WPMU_PLUGIN_DIR . '/sswaf-loader.php';
if (file_exists($sswaf_mu_file)) {
	wp_delete_file($sswaf_mu_file);
}

// Remove log directory (inside plugin dir — may already be gone)
$sswaf_log_dir = plugin_dir_path(__FILE__) . 'logs/';
if (is_dir($sswaf_log_dir)) {
	$sswaf_files = glob($sswaf_log_dir . '*');
	if ($sswaf_files) {
		foreach ($sswaf_files as $sswaf_file) {
			wp_delete_file($sswaf_file);
		}
	}
	global $wp_filesystem;
	if (empty($wp_filesystem)) {
		require_once ABSPATH . 'wp-admin/includes/file.php';
		WP_Filesystem();
	}
	if ($wp_filesystem) {
		$wp_filesystem->rmdir($sswaf_log_dir);
	}
}

// Clean up transients (rate limiting)
global $wpdb;
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- one-time bulk cleanup during uninstall, no single-key API available
$wpdb->query($wpdb->prepare("DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s", '_transient_sswaf_%', '_transient_timeout_sswaf_%'));
