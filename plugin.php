<?php
/**
 * Plugin Name: KAGG Wordfence to Fail2ban
 * Plugin URI:
 * Description: Get IPs collected by Wordfence and send them to Fail2ban
 * Author: KAGG Design
 * Version: 1.0.0
 * Author URI: https://kagg.eu/en/
 * Requires at least: 4.4
 * Tested up to: 5.8
 *
 * Text Domain: kagg-w2f
 * Domain Path: /languages/
 *
 * @package kagg/w2f
 * @author  KAGG Design
 */

namespace KAGG\W2F;

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

if ( defined( 'KAGG_W2F_VERSION' ) ) {
	return;
}

/**
 * Plugin version
 */
define( 'KAGG_W2F_VERSION', '1.0.0' );

/**
 * Path to the plugin dir.
 */
define( 'KAGG_W2F_PATH', __DIR__ );

/**
 * Plugin dir url.
 */
define( 'KAGG_W2F_URL', untrailingslashit( plugin_dir_url( __FILE__ ) ) );

/**
 * Plugin main file.
 */
define( 'KAGG_W2F_FILE', __FILE__ );

/**
 * Init plugin on plugin load.
 */
require_once constant( 'KAGG_W2F_PATH' ) . '/vendor/autoload.php';

new Main();
