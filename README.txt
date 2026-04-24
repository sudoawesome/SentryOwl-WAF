=== Secure Owl Firewall ===
Contributors: sajbersove
Tags: firewall, security, waf, protection
Requires at least: 5.0
Tested up to: 6.9
Stable tag: 1.0.7
Requires PHP: 7.4
License: GPLv2 or later

Secure Owl Firewall is a smart rule-based protection that blocks threats and secures your site from attacks.

== Description ==

Secure Owl Firewall is a fast, lightweight firewall plugin with an advanced rule engine featuring PCRE pattern matching, a transformation pipeline, and JSON-based rule configuration.

Key features:

* JSON-based rules — 100+ default rules covering SQLi, XSS, RCE, LFI, SSRF, Log4Shell, and more
* Transformation pipeline — URL decode, lowercase, normalize path, remove whitespace, HTML entity decode, trim
* Inspection targets — REQUEST_URI, QUERY_STRING, USER_AGENT, REFERER, COOKIE, and POST
* MU-Plugin loader — runs before regular plugins for earliest protection
* Rate limiting — optional transient-based IP and subnet banning
* Login protection — PIN field and honeypot to block brute-force attacks
* IP whitelist — CIDR/subnet support for both IPv4 and IPv6
* Per-rule toggle — disable individual rules from the admin panel without editing files
* File-based logging — 64MB cap with auto-rotation and protected storage
* Log retention — configurable policy for GDPR compliance
* IP anonymization — masks user IP addresses for enhanced privacy and GDPR compliance

== Installation ==

1. Upload the `secure-owl-firewall` folder to `/wp-content/plugins/`
2. Activate through the Plugins menu
3. The MU-Plugin loader is installed automatically for early execution
4. Configure settings under Settings > Secure Owl Firewall

== Filter Hooks ==

* `sswaf_ip_whitelist` — array of IPs to bypass the firewall
* `sswaf_trusted_proxies` — array of trusted proxy IPs for X-Forwarded-For
* `sswaf_post_scanning` — enable POST data inspection (default: true)
* `sswaf_rules_file` — path to the rules JSON file
* `sswaf_log_file` — path to the log file
* `sswaf_log_max_size` — maximum log size in bytes
* `sswaf_header_status` — HTTP status header for blocked requests
* `sswaf_before_block` — action hook fired before blocking a request
* `sswaf_rate_limit_ip_threshold` — override IP hit threshold
* `sswaf_rate_limit_ip_duration` — override IP ban duration
* `sswaf_rate_limit_ip_window` — override IP counting window

== Changelog ==

= 1.0.0 =
* Initial release.

= 1.0.1 =
* Updated security rules.
* Updated log file cap to 24MB.

= 1.0.2 =
* Added IP whitelist with CIDR/subnet support (IPv4 + IPv6).
* File-based storage for zero database overhead.
* Settings UI with validation.

= 1.0.3 =
* Removed metadata from a JSON rules file.
* Small CSS admin tweak.

= 1.0.4 =
* Added configurable log retention policy to automatically purge old data for GDPR compliance.
* Added option to anonymize user IP addresses, enhancing privacy and GDPR compliance.
* Rework plugin update mechanism.
* Improved coding standards to align better with WordPress guidelines.

= 1.0.5 =
* Updated log file cap to 64MB.
* Fixed a small bug in admin panel log viewer.

= 1.0.6 =
* Added rate-limited PIN authentication to the login page to mitigate brute-force attacks.
* Added a honeypot trap to the login form to catch unsophisticated bots.

= 1.0.7 =
* Removed a few overly aggressive rules.
