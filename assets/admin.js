/**
 * MLT Schema Audit admin: keeps a manual audit moving while its screen is
 * open. Writes text only (textContent), never markup.
 */
( function () {
	'use strict';
	var panel = document.getElementById( 'mltsa-progress' );
	if ( ! panel || ! window.mltsaAdmin || ! window.fetch ) {
		return;
	}
	var text = document.getElementById( 'mltsa-progress-text' );
	var bar = document.getElementById( 'mltsa-bar-fill' );
	var failures = 0;

	function step() {
		var body = new window.URLSearchParams();
		body.append( 'action', 'mltsa_step' );
		body.append( 'nonce', window.mltsaAdmin.nonce );
		window.fetch( window.mltsaAdmin.ajaxUrl, { method: 'POST', credentials: 'same-origin', body: body } )
			.then( function ( response ) {
				return response.json();
			} )
			.then( function ( json ) {
				failures = 0;
				var s = json && json.data ? json.data : {};
				if ( 'queued' === s.state || 'running' === s.state ) {
					var total = Math.max( 1, parseInt( s.total, 10 ) || 0 );
					var done = parseInt( s.done, 10 ) || 0;
					text.textContent = done + ' of ' + ( parseInt( s.total, 10 ) || 0 ) + ' pages, phase: ' + String( s.phase || '' );
					bar.style.width = Math.min( 100, Math.floor( ( 100 * done ) / total ) ) + '%';
					window.setTimeout( step, 'locked' === s.note ? 5000 : 500 );
				} else {
					text.textContent = 'Finished. Reloading.';
					window.location.reload();
				}
			} )
			.catch( function () {
				failures++;
				text.textContent = 'Waiting for the server.';
				if ( failures < 20 ) {
					window.setTimeout( step, 5000 );
				}
			} );
	}
	window.setTimeout( step, 500 );
}() );
