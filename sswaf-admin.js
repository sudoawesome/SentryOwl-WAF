/**
 * Secure Owl Firewall - Admin Settings JS
 * Handles rate limiting toggle, rule filtering, and AJAX rule toggling.
 */
(function() {
	'use strict';

	// Rate limiting settings toggle
	var rateToggle = document.getElementById('sswaf-rate-toggle');
	var rateSettings = document.getElementById('sswaf-rate-settings');
	if (rateToggle && rateSettings) {
		rateToggle.addEventListener('change', function() {
			rateSettings.style.display = this.checked ? '' : 'none';
		});
	}

	// Rule toggle handler (AJAX)
	var toggleButtons = document.querySelectorAll('.sswaf-toggle');
	if (toggleButtons.length && typeof sswaf_admin !== 'undefined') {
		toggleButtons.forEach(function(btn) {
			btn.addEventListener('click', function() {
				var button = this;
				var ruleId = button.getAttribute('data-rule-id');
				var action = button.getAttribute('data-action');
				var row = button.closest('tr');

				button.disabled = true;
				button.textContent = '...';

				var formData = new FormData();
				formData.append('action', 'sswaf_toggle_rule');
				formData.append('nonce', sswaf_admin.nonce);
				formData.append('rule_id', ruleId);
				formData.append('toggle_action', action);

				fetch(sswaf_admin.ajax_url, { method: 'POST', body: formData })
					.then(function(r) { return r.json(); })
					.then(function(resp) {
						if (resp.success) {
							var isOn = (action === 'enable');
							button.innerHTML = isOn ? '&#10003; On' : '&#10007; Off';
							button.style.color = isOn ? '#00a32a' : '#dc3232';
							button.setAttribute('data-action', isOn ? 'disable' : 'enable');
							row.style.opacity = isOn ? '1' : '0.6';
							row.setAttribute('data-status', isOn ? 'enabled' : 'disabled');
							updateCount();
						} else {
							button.textContent = 'Error';
						}
						button.disabled = false;
					})
					.catch(function() {
						button.textContent = 'Error';
						button.disabled = false;
					});
			});
		});
	}

	// Rule filtering
	var searchInput = document.getElementById('sswaf-rule-search');
	var filterTarget = document.getElementById('sswaf-rule-filter-target');
	var filterStatus = document.getElementById('sswaf-rule-filter-status');

	function filterRules() {
		var search = searchInput.value.toLowerCase();
		var target = filterTarget.value;
		var status = filterStatus.value;
		var rows = document.querySelectorAll('.sswaf-rule-row');

		rows.forEach(function(row) {
			var matchSearch = !search || row.getAttribute('data-search').indexOf(search) !== -1;
			var matchTarget = !target || row.getAttribute('data-target') === target;
			var matchStatus = !status || row.getAttribute('data-status') === status;
			row.style.display = (matchSearch && matchTarget && matchStatus) ? '' : 'none';
		});
		updateCount();
	}

	function updateCount() {
		var total = document.querySelectorAll('.sswaf-rule-row').length;
		var visible = document.querySelectorAll('.sswaf-rule-row:not([style*="display: none"])').length;
		var el = document.getElementById('sswaf-rule-count');
		if (el) {
			el.textContent = visible < total ? visible + ' of ' + total + ' rules' : total + ' rules';
		}
	}

	if (searchInput) {
		searchInput.addEventListener('input', filterRules);
		filterTarget.addEventListener('change', filterRules);
		filterStatus.addEventListener('change', filterRules);
		updateCount();
	}
})();
