<?php
/**
 * Secure password module.
 *
 * @package Newfold\WP\Module\Secure_Passwords
 */

namespace Newfold\WP\Module\Secure_Passwords;

use stdClass;
use WP_User;
use WP_Error;

if ( ! defined( 'NFD_SECURE_PASSWORD_MODULE_VERSION' ) ) {
	define( 'NFD_SECURE_PASSWORD_MODULE_VERSION', '1.0.0' );
}

if ( ! defined( 'NFD_REMIND_INTERVAL' ) ) {
	define( 'NFD_REMIND_INTERVAL', DAY_IN_SECONDS * 90 );
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
	if ( nfd_sp_is_user_password_insecure( $user->ID ) && ! nfd_sp_is_insecure_password_screen_snoozed( $user->ID ) ) {
		nfd_sp_show_insecure_password_screen();
	}

	// See if it's time to recheck the password.
	if ( ! nfd_sp_should_check_password( $user->ID ) ) {
		return;
	}

	/*
	 * When checking passwords on the wp_login action, the password is not available, but
	 * has already been stored in the Have_I_Been_Pwned class on the `wp_authenticate` action.
	 */
	$is_secure = nfd_sp_is_password_secure( '', $user->ID );

	if ( is_wp_error( $is_secure ) ) {
		return;
	}

	if ( $is_secure ) {
		nfd_sp_mark_password_secure( $user->ID );
	} else {
		nfd_sp_mark_password_insecure( $user->ID );
		nfd_sp_show_insecure_password_screen( $user->ID );
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

		update_user_meta( get_current_user_id(), 'nfd_sp_snooze_end', time() + NFD_REMIND_INTERVAL );

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
				human_time_diff( time() + NFD_REMIND_INTERVAL )
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

/**
 * Confirms a password is secure before changing a user's password.
 *
 * @param WP_Error $errors WP_Error object (passed by reference).
 * @param bool     $update Whether this is a user update.
 * @param stdClass $user   User object (passed by reference).
 */
function user_profile_update_errors( $errors, $update, $user ) {
	if ( empty( $user->user_pass ) ) {
		return;
	}

	if ( ! nfd_sp_is_password_secure( $user->user_pass ) ) {
		$errors->add( 'nfd_sp_insecure_password', __( 'The entered password was found in a database of insecure passwords. Please choose a different one.', 'newfold' ) );
	}
}
add_action( 'user_profile_update_errors', __NAMESPACE__ . '\user_profile_update_errors', 10, 3 );

/**
 * Enforce secure passwords when performing a password reset.
 *
 * @param WP_User $user     The user.
 * @param string  $new_pass New user password.
 */
function reset_password( $user, $new_pass ) {
	if ( ! nfd_sp_is_password_secure( $new_pass ) ) {
		wp_safe_redirect( add_query_arg( array( 'nfd_sp_insecure_password', 1 ) ) );
		exit;
	}
}
add_action( 'reset_password', __NAMESPACE__ . '\reset_password', 10, 2 );

/**
 * Performs a secure password check on Ajax request.
 */
function ajax_sp_is_password_secure() {
	if ( ! isset( $_GET['password'] ) || empty( $_GET['password'] ) ) {
		wp_send_json( new WP_Error() );
	}

	$is_secure = nfd_sp_is_password_secure( wp_unslash( $_GET['password'] ) );

	if ( is_wp_error( $is_secure ) ) {
		wp_send_json_error( $is_secure );
	}

	wp_send_json_success( $is_secure );
}
add_action( 'wp_ajax_sp-is-password-secure', __NAMESPACE__ . '\ajax_sp_is_password_secure' );
add_action( 'wp_ajax_nopriv_sp-is-password-secure', __NAMESPACE__ . '\ajax_sp_is_password_secure' );

/**
 * Ensures generated passwords are secure.
 *
 * To prevent excessive requests and infinite loops, the maximum number of
 * attempts is limited to 3.
 *
 * @param string $password            The generated password.
 * @param int    $length              The length of password to generate.
 * @param bool   $special_chars       Whether to include standard special characters.
 * @param bool   $extra_special_chars Whether to include other special characters.
 */
function random_password( $password, $length, $special_chars, $extra_special_chars ) {
	static $count = 1;

	$is_secure = nfd_sp_is_password_secure( $password );

	// If 3 attempts have been made, use the generated password.
	if ( $count > 3 || $is_secure ) {
		return $password;
	}

	$count++;

	return wp_generate_password( $length, $special_chars, $extra_special_chars );
}
add_filter( 'random_password', __NAMESPACE__ . '\random_password', 10, 4 );

add_action( 'admin_print_scripts', function() {
	?>
		<style>
			.sp-insecure-password-notice td {
				padding: 0 10px;
			}
		</style>
	<script>
		<?php echo file_get_contents( __DIR__ . '/assets/js/secure-passwords.js' ); ?>
	</script>
	<?php
});
