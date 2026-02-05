<?php
/**
 * Bootstrap file for wpunit tests.
 *
 * @package Newfold\WP\Module\Secure_Passwords
 */

$module_root = dirname( dirname( __DIR__ ) );

require_once $module_root . '/vendor/autoload.php';

// Load module so classes and functions are available in tests.
require_once $module_root . '/secure-passwords.php';
