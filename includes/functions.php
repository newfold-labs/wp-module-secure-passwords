<?php
/**
 * General, global namespace module functions.
 *
 * @package Newfold\Secure_Passwords
 */

use Newfold\Secure_Passwords\Have_I_Been_Pwned_API;

/**
 * Checks if a user's password has been flagged as insecure.
 *
 * @param int $user_id Optional. User ID to check.
 * @return bool true if password is insecure, false if not.
 */
function bh_is_user_password_insecure( $user_id = 0 ) {
	if ( empty( $user_id ) ) {
		$user_id = get_current_user_id();
	}

	return (bool) get_user_meta( $user_id, 'insecure_password', true );
}

/**
 * Checks if a password is insecure.
 *
 * When a user ID is provided, the Have_I_Been_Pwned_API::user_login property will be checked
 * for a match. This is required when checking a password on login to ensure the pre-authenticated
 * user matches the actual authenticated one.
 *
 * @param string $password Optional. The password to check. Can be a SHA1 hash or plain text.
 * @param int    $user_id Optional. The ID of the user the password belongs to.
 * @return WP_Error|bool Whether the password is secure. WP_Error on failure.
 */
function bh_is_password_secure( $password = '', $user_id = 0 ) {
	$password_checker = Have_I_Been_Pwned_API::init();

	if ( ! empty( $user_id ) ) {
		$user = new WP_User( $user_id );

		if ( $password_checker->user_login !== $user->user_login ) {
			return new WP_Error(
				'',
				''
			);
		}
	}

	$leaked = $password_checker->check_password_for_leak( $password );

	if ( is_wp_error( $leaked ) ) {
		return $leaked;
	}

	return ! (bool) $leaked;
}

/**
 * Marks a user's password as insecure.
 *
 * @param int $user_id User ID.
 */
function sp_mark_password_insecure( $user_id ) {
	update_user_meta( $user_id, 'insecure_password', true );
	sp_mark_password_checked( $user_id );
}

/**
 * Marks a user's password as secure.
 *
 * @param int $user_id User ID.
 */
function sp_mark_password_secure( $user_id ) {
	delete_user_meta( $user_id, 'insecure_password' );
	sp_mark_password_checked( $user_id );
}

/**
 * Updates the last password check timestamp in user meta.
 *
 * @param int $user_id User ID.
 */
function sp_mark_password_checked( $user_id ) {
	update_user_meta( $user_id, 'last_password_check', time() );
}

/**
 * Determine if a password should be checked.
 *
 * User passwords are checked against the Have I Been Pwned API once every 30 days.
 *
 * @param int $user_id User ID.
 * @return bool
 */
function sp_should_check_password( $user_id ) {
	// Password is not currently marked as insecure. Check every 30 days.
	$last_check = (int) get_user_meta( $user_id, 'last_password_check', true );

	// Only check for password compromises every 30 days.
	if ( $last_check < time() - DAY_IN_SECONDS * 30 ) {
		return true;
	}

	return false;
}

/**
 * Checks if the insecure password screen has been snoozed.
 *
 * When a user has clicked "Remind me later" on the insecure password screen,
 * the screen will be hidden for 90 days.
 *
 * @param int $user_id User ID.
 * @return bool Whether the insecure password screen has been snoozed.
 */
function sp_is_insecure_password_screen_snoozed( $user_id ) {
	$next_notice = (int) get_user_meta( $user_id, 'sp_snooze_end', true );

	// Not time to display the screen again.
	if ( time() < $next_notice ) {
		return true;
	}

	return false;
}

/**
 * Redirects a user to the insecure password page.
 */
function sp_show_insecure_password_screen() {
	if ( ! empty( $_REQUEST['redirect_to'] ) ) {
		$redirect_to = $_REQUEST['redirect_to'];
	} else {
		$redirect_to = admin_url();
	}

	wp_safe_redirect(
		add_query_arg(
			'action',
			'sp_insecure_password',
			wp_login_url( $redirect_to )
		)
	);
	exit;
}
