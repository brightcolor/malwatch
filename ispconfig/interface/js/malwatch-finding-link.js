/*
 * malwatch: opens the page of a finding from a link in a mail.
 *
 * The panel has no address for its inner pages; everything loads by AJAX.
 * A mail therefore links to index.php#malwatch-finding-<id>, and this script
 * (loaded by the panel from js/js.d on every start) opens that page once the
 * panel has finished loading its own start page, then takes the mark out of
 * the address so a reload does not open it again.
 *
 * A reader who is not logged in lands on the login first; the panel forgets
 * the mark there and opens its usual start page.
 */
(function () {
	'use strict';
	var match = /^#malwatch-finding-(\d{1,9})$/.exec(window.location.hash || '');
	if (!match) {
		return;
	}
	var page = 'security/malwatch_finding_show.php?id=' + match[1];
	var opened = false;
	var open = function () {
		if (opened || !window.ISPConfig || typeof window.ISPConfig.capp !== 'function') {
			return;
		}
		opened = true;
		if (window.history && window.history.replaceState) {
			window.history.replaceState(null, '', window.location.pathname + window.location.search);
		}
		window.ISPConfig.capp('security', page);
	};
	var start = function () {
		var $ = window.jQuery;
		if ($) {
			// After the panel's own requests for the start page and the menus;
			// opened before them, the start page would load over it.
			$(document).one('ajaxStop', function () {
				window.setTimeout(open, 50);
			});
		}
		// Fallback for a start without any request.
		window.setTimeout(open, 3000);
	};
	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', start);
	} else {
		start();
	}
})();
