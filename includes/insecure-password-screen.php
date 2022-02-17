<?php
/**
 * Displays the insecure password warning screen when a user logs in
 * if their password has been flagged as leaked.
 *
 * @package Newfold\Secure_Passwords
 */

$errors = new WP_Error();

if ( ! empty( $_REQUEST['redirect_to'] ) ) {
	$redirect_to = $_REQUEST['redirect_to'];
} else {
	$redirect_to = admin_url();
}

login_header( esc_html__( 'Insecure password detected', 'newfold' ), '', $errors );

?>
	<style>
		.login-action-sp_insecure_password #login {
			width: 60vw;
			max-width: 650px;
			margin-top: -2vh;
		}

		.login .sp-insecure-password-screen .submit {
			text-align: center;
		}

		@media screen and (max-width: 782px) {
			.login-action-insecure_password #login {
				box-sizing: border-box;
				margin-top: 0;
				padding-left: 4vw;
				padding-right: 4vw;
				width: 100vw;
			}
		}
	</style>

	<form class="sp-insecure-password-form" name="sp-insecure-password-form" action="<?php echo esc_url( get_edit_user_link() ); ?>" method="post">
		<input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redirect_to ); ?>" />

		<h1 class="admin-email__heading">
			<?php esc_html_e( 'Insecure password detected', 'newfold' ); ?>
		</h1>

		<p class="admin-email__details">
			<strong><?php esc_html_e( 'This does not mean your user account or WordPress site has been compromised.', 'newfold' ); ?></strong>
		</p>

		<p class="admin-email__details">
			<?php esc_html_e( 'Your password was found in a database of potentially insecure passwords.', 'newfold' ); ?>
		</p>

		<p class="admin-email__details">
			<?php esc_html_e( 'When data breaches occur on the internet, security researchers compile leaked data securely and anonymously for informational purposes.', 'newfold' ); ?>
		</p>

		<p class="admin-email__details">
			<?php esc_html_e( 'Your password has previously been leaked in a data breach and should be considered insecure.', 'newfold' ); ?>
		</p>

		<p class="admin-email__details">
			<strong><?php esc_html_e( 'It is strongly recommended that you change your password.', 'newfold' ); ?></strong>
		</p>

		<div class="admin-email__actions">
			<div class="admin-email__actions-primary">
				<input type="submit" name="update-password" id="update-password" class="button button-primary button-large" value="<?php esc_attr_e( 'Change password', 'newfold' ); ?>" />
			</div>

			<div class="admin-email__actions-secondary">
				<?php

				$remind_me_link = wp_login_url( $redirect_to );
				$remind_me_link = add_query_arg(
					array(
						'action'          => 'sp_insecure_password',
						'sp_remind_later' => wp_create_nonce( 'sp_remind_later_nonce' ),
					),
					$remind_me_link
				);

				?>
				<a href="<?php echo esc_url( $remind_me_link ); ?>"><?php esc_html_e( 'Remind me later', 'newfold' ); ?></a>
			</div>
		</div>
	</form>

<?php

login_footer();

exit;
