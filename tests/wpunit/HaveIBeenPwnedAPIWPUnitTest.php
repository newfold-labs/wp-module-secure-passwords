<?php

namespace Newfold\WP\Module\Secure_Passwords;

/**
 * Tests for Have_I_Been_Pwned_API (non-network behavior).
 *
 * @covers \Newfold\WP\Module\Secure_Passwords\Have_I_Been_Pwned_API::store_hash
 * @covers \Newfold\WP\Module\Secure_Passwords\Have_I_Been_Pwned_API::store_user_login
 * @covers \Newfold\WP\Module\Secure_Passwords\Have_I_Been_Pwned_API::scan_for_match
 * @covers \Newfold\WP\Module\Secure_Passwords\Have_I_Been_Pwned_API::filter_padded_entries
 * @covers \Newfold\WP\Module\Secure_Passwords\Have_I_Been_Pwned_API::map_remove_counts
 */
class HaveIBeenPwnedAPIWPUnitTest extends \lucatume\WPBrowser\TestCase\WPTestCase {

	/**
	 * Reset singleton between tests.
	 *
	 * @return void
	 */
	public function tearDown(): void {
		$api = Have_I_Been_Pwned_API::init();
		$ref  = new \ReflectionClass( $api );
		$prop = $ref->getProperty( 'instance' );
		$prop->setAccessible( true );
		$prop->setValue( null );
		parent::tearDown();
	}

	/**
	 * Verifies init returns singleton.
	 *
	 * @return void
	 */
	public function test_init_returns_singleton() {
		$a = Have_I_Been_Pwned_API::init();
		$b = Have_I_Been_Pwned_API::init();
		$this->assertSame( $a, $b );
	}

	/**
	 * Verifies store_user_login sets user_login.
	 *
	 * @return void
	 */
	public function test_store_user_login_sets_property() {
		$api = Have_I_Been_Pwned_API::init();
		$api->store_user_login( 'testuser' );
		$this->assertSame( 'testuser', $api->user_login );
	}

	/**
	 * Verifies store_hash stores uppercase SHA1 and ignores empty password.
	 *
	 * @return void
	 */
	public function test_store_hash_uppercase_sha1() {
		$api = Have_I_Been_Pwned_API::init();
		$api->store_hash( 'hello' );
		$ref  = new \ReflectionClass( $api );
		$prop = $ref->getProperty( 'password_hash' );
		$prop->setAccessible( true );
		$hash = $prop->getValue( $api );
		$this->assertSame( strtoupper( sha1( 'hello' ) ), $hash );
	}

	/**
	 * Verifies scan_for_match finds full hash in list of suffixes.
	 *
	 * @return void
	 */
	public function test_scan_for_match_finds_match() {
		$api = Have_I_Been_Pwned_API::init();
		$api->store_hash( 'password123' );
		$suffix = substr( strtoupper( sha1( 'password123' ) ), 5 );
		$list   = [ 'OTHER', $suffix, 'ANOTHER' ];
		$this->assertTrue( $api->scan_for_match( $list ) );
	}

	/**
	 * Verifies scan_for_match returns false when no match.
	 *
	 * @return void
	 */
	public function test_scan_for_match_no_match() {
		$api = Have_I_Been_Pwned_API::init();
		$api->store_hash( 'password123' );
		$list = [ 'OTHER', 'ANOTHER' ];
		$this->assertFalse( $api->scan_for_match( $list ) );
	}

	/**
	 * Verifies scan_for_match returns false for empty array.
	 *
	 * @return void
	 */
	public function test_scan_for_match_empty_returns_false() {
		$api = Have_I_Been_Pwned_API::init();
		$api->store_hash( 'x' );
		$this->assertFalse( $api->scan_for_match( [] ) );
	}

	/**
	 * Verifies filter_padded_entries excludes entries containing :0.
	 *
	 * @return void
	 */
	public function test_filter_padded_entries_excludes_padding() {
		$api   = Have_I_Been_Pwned_API::init();
		$this->assertFalse( $api->filter_padded_entries( 'ABCDEF:0' ) );
		$this->assertTrue( $api->filter_padded_entries( 'ABCDEF:123' ) );
	}

	/**
	 * Verifies map_remove_counts returns first 35 characters.
	 *
	 * @return void
	 */
	public function test_map_remove_counts_strips_count() {
		$api = Have_I_Been_Pwned_API::init();
		$out = $api->map_remove_counts( 'ABCDEF123456789012345678901234567:42' );
		$this->assertSame( 'ABCDEF123456789012345678901234567', $out );
	}
}
