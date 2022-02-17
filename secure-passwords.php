<?php
/**
 * Secure password module.
 *
 * @package Newfold\Secure_Passwords
 */

namespace Newfold\Secure_Passwords;

use WP_User;

if ( ! defined( 'NFD_SECURE_PASSWORD_MODULE_VERSION' ) ) {
	define( 'NFD_SECURE_PASSWORD_MODULE_VERSION', '1.0.0' );
}

if ( ! defined( 'SP_REMIND_INTERVAL' ) ) {
	define( 'SP_REMIND_INTERVAL', DAY_IN_SECONDS * 90 );
}

require_once 'includes/functions.php';
require_once 'includes/class-have-i-been-pwned-api.php';

/**
 * Begin a secure password check when a user attempts to authenticate.
 *
 * This is the last action hook where the password entered is available.
 * This hashes and stores the entered login information for use later in the
 * request if the credentials are correct and authentication is successful.
 *
 * @since 1.0.0
 *
 * @param string $user_login    User login.
 * @param string $user_password User password.
 */
function wp_authenticate( $user_login, $user_password ) {
	/*
	 * The wp_authenticate hook is triggered by default on all login screen loads.
	 * Checks should only happen when credentials are present and a login is
	 * being attempted.
	 */
	if ( empty( $user_login ) || empty( $user_password ) ) {
		return;
	}

	$password_checker = Have_I_Been_Pwned_API::init();
	$password_checker->store_hash( $user_password );
	$password_checker->store_user_login( $user_login );
}
add_action( 'wp_authenticate', __NAMESPACE__ . '\wp_authenticate', 10, 2 );

/**
 * Checks a user account for a leaked password on login.
 *
 * @param string  $user_login Username.
 * @param WP_User $user       WP_User object of the logged-in user.
 */
function wp_login( $user_login, $user ) {
	// Display the insecure password screen for insecure passwords when enough time has passed.
	if ( bh_is_user_password_insecure( $user->ID ) && ! sp_is_insecure_password_screen_snoozed( $user->ID ) ) {
		sp_show_insecure_password_screen();
	}

	// See if it's time to recheck the password.
	if ( ! sp_should_check_password( $user->ID ) ) {
		return;
	}

	/*
	 * When checking passwords on the wp_login action, the password is not available, but
	 * has already been stored in the Have_I_Been_Pwned class on the `wp_authenticate` action.
	 */
	$is_secure = bh_is_password_secure( '', $user->ID );

	if ( is_wp_error( $is_secure ) ) {
		return;
	}

	if ( $is_secure ) {
		sp_mark_password_secure( $user->ID );
	} else {
		sp_mark_password_insecure( $user->ID );
		sp_show_insecure_password_screen( $user->ID );
	}
}
add_action( 'wp_login', __NAMESPACE__ . '\wp_login', 10, 2 );

/**
 * Handles the display and processing of the insecure password login interstitial.
 */
function login_form_sp_insecure_password() {
	/*
	 * Note that `is_user_logged_in()` will return false immediately after logging in
	 * as the current user is not set, see wp-includes/pluggable.php.
	 * However this action runs on a redirect after logging in.
	 */
	if ( ! is_user_logged_in() ) {
		wp_safe_redirect( wp_login_url() );
		exit;
	}

	if ( ! empty( $_REQUEST['redirect_to'] ) ) {
		$redirect_to = $_REQUEST['redirect_to'];
	} else {
		$redirect_to = admin_url();
	}

	if ( ! empty( $_GET['sp_remind_later'] ) ) {
		if ( ! wp_verify_nonce( $_GET['sp_remind_later'], 'sp_remind_later_nonce' ) ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		update_user_meta( get_current_user_id(), 'sp_snooze_end', time() + SP_REMIND_INTERVAL );

		$redirect_to = add_query_arg( 'sp_snoozed', 1, $redirect_to );
		wp_safe_redirect( $redirect_to );
		exit;
	}

	require_once 'includes/insecure-password-screen.php';
}
add_action( 'login_form_sp_insecure_password', __NAMESPACE__ . '\login_form_sp_insecure_password' );

/**
 * Displays an admin notice when the insecure password page is dismissed.
 */
function admin_notices() {
	if ( ! isset( $_GET['sp_snoozed'] ) ) {
		return;
	}

	?>
	<div class="notice notice-success is-dismissible">
		<p>
			<?php
			printf(
				/* translators: %s: Human-readable time interval. */
				esc_html__( 'The insecure password warning has been dismissed for %s.' ),
				human_time_diff( time() + SP_REMIND_INTERVAL )
			);
			?>
		</p>
	</div>
	<?php
}
add_action( 'admin_notices', __NAMESPACE__ . '\admin_notices' );

/**
 * Remove related query args after processing.
 *
 * @param string[] $removable_query_args An array of query variable names to remove from a URL.
 * @return string[] An adjusted array of query variable names to remove from the URL.
 */
function removable_query_args( $removable_query_args ) {
	$removable_args[] = 'sp_snoozed';

	return $removable_args;
}
add_filter( 'removable_query_args', __NAMESPACE__ . '\removable_query_args' );

/**
 * Loads the scripts and styles for the insecure password screen.
 */
function login_enqueue_scripts() {
	wp_enqueue_style( 'sp-login', plugins_url( '/assets/css/login.css', __FILE__ ), array(), NFD_SECURE_PASSWORD_MODULE_VERSION );
}
add_action( 'login_enqueue_scripts', __NAMESPACE__ . '\login_enqueue_scripts' );
