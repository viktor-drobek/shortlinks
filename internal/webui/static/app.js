// Management UI behaviour. Loaded as an external script: the page has no
// inline scripts, per the CSP policy.
(function () {
	'use strict';

	// Confirm the delete forms that carry a data-confirm message before
	// submission.
	document.querySelectorAll('form.delete[data-confirm]').forEach(function (form) {
		form.addEventListener('submit', function (event) {
			if (!window.confirm(form.getAttribute('data-confirm'))) {
				event.preventDefault();
			}
		});
	});

	// When the expiry input is focused, offer a practical prefill: a
	// placeholder that shows the expected format. Users can delete it and
	// leave the field empty for a permanent link.
	var expiry = document.getElementById('expires_at');
	if (expiry) {
		expiry.addEventListener('focus', function () {
			if (expiry.value === '') {
				expiry.setCustomValidity('');
			}
		});
	}
})();
