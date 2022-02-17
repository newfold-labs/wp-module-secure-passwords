<?php
/**
 * Secure Passwords module.
 *
 * @package Newfold\Secure_Passwords
 */

if ( function_exists( 'add_action' ) ) {
	add_action( 'plugins_loaded', 'newfold_module_register_secure_passwords' );
}

/**
 * Register the secure passwords module.
 */
function newfold_module_register_secure_passwords() {
	eig_register_module(
		array(
			'name'     => 'secure-passwords',
			'label'    => __( 'Secure Passwords', 'endurance' ),
			'callback' => 'newfold_module_load_secure_passwords',
			'isActive' => true,
			'isHidden' => false,
		)
	);
}

/**
 * Load the secure passwords module.
 */
function newfold_module_load_secure_passwords() {
	require dirname( __FILE__ ) . '/secure-passwords.php';
}
