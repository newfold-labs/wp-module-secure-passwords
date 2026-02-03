<?php

namespace Newfold\WP\Module\Secure_Passwords;

/**
 * Tests for Secure Passwords module functions.
 *
 * @covers \Newfold\WP\Module\Secure_Passwords\is_user_password_secure
 * @covers \Newfold\WP\Module\Secure_Passwords\mark_password_secure
 * @covers \Newfold\WP\Module\Secure_Passwords\mark_password_insecure
 * @covers \Newfold\WP\Module\Secure_Passwords\clear_user_meta
 * @covers \Newfold\WP\Module\Secure_Passwords\record_password_check
 * @covers \Newfold\WP\Module\Secure_Passwords\show_insecure_password_screen
 * @covers \Newfold\WP\Module\Secure_Passwords\removable_query_args
 */
class FunctionsWPUnitTest extends \lucatume\WPBrowser\TestCase\WPTestCase {

	/**
	 * @var int
	 */
	private $user_id;

	/**
	 * Set up test user.
	 *
	 * @return void
	 */
	public function setUp(): void {
		parent::setUp();
		$this->user_id = $this->factory()->user->create( [ 'user_login' => 'securepw_user' ] );
	}

	/**
	 * Reset Have_I_Been_Pwned_API singleton between tests.
	 *
	 * @return void
	 */
	public function tearDown(): void {
		$api = Have_I_Been_Pwned_API::init();
		$ref = new \ReflectionClass( $api );
		$prop = $ref->getProperty( 'instance' );
		$prop->setAccessible( true );
		$prop->setValue( null );
		parent::tearDown();
	}

	/**
	 * Verifies is_user_password_secure returns true when user has no insecure meta.
	 *
	 * @return void
	 */
	public function test_is_user_password_secure_default_secure() {
		$this->assertTrue( is_user_password_secure( $this->user_id ) );
	}

	/**
	 * Verifies is_user_password_secure returns false when user is marked insecure.
	 *
	 * @return void
	 */
	public function test_is_user_password_secure_after_mark_insecure() {
		mark_password_insecure( $this->user_id );
		$this->assertFalse( is_user_password_secure( $this->user_id ) );
	}

	/**
	 * Verifies mark_password_secure removes insecure meta.
	 *
	 * @return void
	 */
	public function test_mark_password_secure_clears_insecure_meta() {
		mark_password_insecure( $this->user_id );
		$this->assertFalse( is_user_password_secure( $this->user_id ) );
		mark_password_secure( $this->user_id );
		$this->assertTrue( is_user_password_secure( $this->user_id ) );
	}

	/**
	 * Verifies mark_password_secure and mark_password_insecure update last check meta.
	 *
	 * @return void
	 */
	public function test_mark_password_secure_records_check_time() {
		mark_password_secure( $this->user_id );
		$last = (int) get_user_meta( $this->user_id, 'nfd_sp_last_check', true );
		$this->assertGreaterThan( 0, $last );
	}

	/**
	 * Verifies clear_user_meta removes all module meta.
	 *
	 * @return void
	 */
	public function test_clear_user_meta_removes_all_meta() {
		mark_password_insecure( $this->user_id );
		update_user_meta( $this->user_id, 'nfd_sp_last_check', time() );
		update_user_meta( $this->user_id, 'nfd_sp_next_notice', time() + 100 );
		clear_user_meta( $this->user_id );
		$this->assertTrue( is_user_password_secure( $this->user_id ) );
		$this->assertEmpty( get_user_meta( $this->user_id, 'nfd_sp_last_check', true ) );
		$this->assertEmpty( get_user_meta( $this->user_id, 'nfd_sp_next_notice', true ) );
	}

	/**
	 * Verifies show_insecure_password_screen returns false when next notice is in future.
	 *
	 * @return void
	 */
	public function test_show_insecure_password_screen_false_when_snoozed() {
		update_user_meta( $this->user_id, 'nfd_sp_next_notice', time() + 3600 );
		$this->assertFalse( show_insecure_password_screen( $this->user_id ) );
	}

	/**
	 * Verifies show_insecure_password_screen returns true when past next notice time.
	 *
	 * @return void
	 */
	public function test_show_insecure_password_screen_true_when_past_notice() {
		update_user_meta( $this->user_id, 'nfd_sp_next_notice', time() - 1 );
		$this->assertTrue( show_insecure_password_screen( $this->user_id ) );
	}

	/**
	 * Verifies removable_query_args adds nfd_sp_dismissed.
	 *
	 * @return void
	 */
	public function test_removable_query_args_adds_dismissed_arg() {
		$args = removable_query_args( [] );
		$this->assertContains( 'nfd_sp_dismissed', $args );
	}

	/**
	 * Verifies should_check_password returns false in local environment.
	 *
	 * @return void
	 */
	public function test_should_check_password_returns_false_in_local() {
		$this->assertFalse( should_check_password( $this->user_id ) );
	}
}
