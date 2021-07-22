<?php
/**
 * Main class file.
 *
 * @package kagg/w2f
 */

namespace KAGG\W2F;

use wfUtils;

/**
 * Class Main
 */
class Main {
	private const UPDATE_BAN_HOOK = 'kagg_w2f_update_ban';

	/**
	 * Interval days.
	 *
	 * @var int
	 */
	private int $interval_days = 1;

	/**
	 * Main constructor.
	 */
	public function __construct() {
		$this->init();
	}

	/**
	 * Init class.
	 */
	public function init(): void {
		// Register activation hook to schedule event in wp_cron().
		register_activation_hook( KAGG_W2F_FILE, [ $this, 'activate_ban' ] );

		// Register deactivation hook to remove event from wp_cron().
		register_deactivation_hook( KAGG_W2F_FILE, [ $this, 'deactivate_ban' ] );

		add_action( self::UPDATE_BAN_HOOK, [ $this, 'update_ban_action' ] );
	}

	/**
	 * Add event to WP-Cron and check local files.
	 */
	public function activate_ban(): void {
		if ( ! wp_next_scheduled( self::UPDATE_BAN_HOOK ) ) {
			wp_schedule_event( time(), 'daily', self::UPDATE_BAN_HOOK );
			do_action( self::UPDATE_BAN_HOOK );
		}
	}

	/**
	 * Remove event from WP-Cron.
	 */
	public function deactivate_ban(): void {
		if ( wp_next_scheduled( self::UPDATE_BAN_HOOK ) ) {
			wp_clear_scheduled_hook( self::UPDATE_BAN_HOOK );
		}
	}

	/**
	 * Ban IPs collected by Wordfence and transfer them to Fail2ban.
	 */
	public function update_ban_action(): void {
		global $wpdb;

		if ( ! is_plugin_active( 'wordfence/wordfence.php' ) ) {
			return;
		}

		// Get info on last interval_days.
		$unix_day = (int) ( gmdate( 'U' ) / DAY_IN_SECONDS ) - $this->interval_days;

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results(
			$wpdb->prepare( "SELECT * FROM {$wpdb->base_prefix}wfBlockedIPLog WHERE unixday > %s", $unix_day )
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.NoCaching
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery

		if ( ! $rows ) {
			return;
		}

		$ban_commands = [];

		foreach ( $rows as $row ) {
			// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
			$ip = wfUtils::inet_ntop( $row->IP );

			$ban_commands[] = 'fail2ban-client set ssh-iptables banip ' . $ip;
		}

		$ban_commands   = array_unique( $ban_commands );
		$ban_commands[] = 'iptables-save | uniq | iptables-restore';

		$cmd_filename     = wp_tempnam();
		$cmd_file_content = implode( PHP_EOL, $ban_commands );

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_read_file_put_contents
		file_put_contents( $cmd_filename, $cmd_file_content );

		chmod( $cmd_filename, 0755 );

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_exec
		exec( $cmd_filename );

		unlink( $cmd_filename );
	}
}
