<?php

namespace Newfold\WP\Module\Secure_Passwords;

/**
 * Module loading wpunit tests.
 *
 * @coversNothing
 */
class ModuleLoadingWPUnitTest extends \lucatume\WPBrowser\TestCase\WPTestCase {

	/**
	 * Verify WordPress factory is available.
	 *
	 * @return void
	 */
	public function test_wordpress_factory_available() {
		$this->assertTrue( function_exists( 'get_option' ) );
		$this->assertNotEmpty( get_option( 'blogname' ) );
	}

	/**
	 * Verify add_action exists (bootstrap uses it).
	 *
	 * @return void
	 */
	public function test_wordpress_hooks_available() {
		$this->assertTrue( function_exists( 'add_action' ) );
		$this->assertTrue( function_exists( 'add_filter' ) );
	}

	/**
	 * Verify Secure Passwords module functions exist.
	 *
	 * @return void
	 */
	public function test_secure_passwords_functions_exist() {
		$this->assertTrue( function_exists( __NAMESPACE__ . '\is_user_password_secure' ) );
		$this->assertTrue( function_exists( __NAMESPACE__ . '\is_password_secure' ) );
		$this->assertTrue( function_exists( __NAMESPACE__ . '\mark_password_secure' ) );
		$this->assertTrue( function_exists( __NAMESPACE__ . '\mark_password_insecure' ) );
		$this->assertTrue( function_exists( __NAMESPACE__ . '\clear_user_meta' ) );
		$this->assertTrue( function_exists( __NAMESPACE__ . '\should_check_password' ) );
		$this->assertTrue( function_exists( __NAMESPACE__ . '\show_insecure_password_screen' ) );
	}

	/**
	 * Verify Have_I_Been_Pwned_API class exists.
	 *
	 * @return void
	 */
	public function test_have_i_been_pwned_api_class_exists() {
		$this->assertTrue( class_exists( __NAMESPACE__ . '\Have_I_Been_Pwned_API' ) );
	}

	/**
	 * Verify module constants are defined.
	 *
	 * @return void
	 */
	public function test_module_constants_defined() {
		$this->assertTrue( defined( 'NFD_SECURE_PASSWORD_MODULE_VERSION' ) );
		$this->assertTrue( defined( 'NFD_REMIND_INTERVAL' ) );
		$this->assertTrue( defined( 'NFD_CHECK_INTERVAL' ) );
	}
}
