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
	private const NGINX_CONF      = '/etc/nginx/conf.d/block-ip-kagg-w2f.conf';

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
		// Register deactivation hook to remove event from wp_cron().
		register_deactivation_hook( KAGG_W2F_FILE, [ $this, 'deactivate_ban' ] );

		if ( 'Linux' !== PHP_OS_FAMILY ) {
			return;
		}

		// Register activation hook to schedule event in wp_cron().
		register_activation_hook( KAGG_W2F_FILE, [ $this, 'activate_ban' ] );

		add_action( self::UPDATE_BAN_HOOK, [ $this, 'update_ban_action' ] );
	}

	/**
	 * Add event to WP-Cron and check local files.
	 */
	public function activate_ban(): void {
		if ( ! wp_next_scheduled( self::UPDATE_BAN_HOOK ) ) {
			wp_schedule_event( time(), 'hourly', self::UPDATE_BAN_HOOK );
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
	 * Ban IPs collected by Wordfence and send them to Fail2ban and Nginx.
	 */
	public function update_ban_action(): void {
		$blocked_ips = $this->get_blocked_ips();

		if ( ! $blocked_ips ) {
			return;
		}

		$this->update_fail2ban( $blocked_ips );
		$this->update_nginx( $blocked_ips );
	}

	/**
	 * Ban IPs collected by Wordfence and send them to Fail2ban.
	 *
	 * @param array $blocked_ips Blocked IPs.
	 */
	public function update_fail2ban( array $blocked_ips ): void {
		$ban_commands = array_map(
			static function ( $blocked_ip ) {
				return 'sudo fail2ban-client set ssh-iptables banip ' . $blocked_ip;
			},
			$blocked_ips
		);

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

	/**
	 * Ban IPs collected by Wordfence and send them to Nginx.
	 *
	 * @param array $blocked_ips Blocked IPs.
	 */
	public function update_nginx( array $blocked_ips ): void {
		$nginx_blocked_ips = [];

		if ( ! is_file( self::NGINX_CONF ) ) {
			return;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$config                  = (string) file_get_contents( self::NGINX_CONF );
		$nginx_blocked_ips_found = preg_match(
			'/(map \$real_ip \$allow {\n\tdefault true;\n)(.+?)}/s',
			$config,
			$matches
		);

		if ( $nginx_blocked_ips_found ) {
			$nginx_blocked_ips = explode( "\n", $matches[2] );
			$nginx_blocked_ips = array_map(
				static function ( $nginx_blocked_ip ) {
					return trim( str_replace( 'false', '', $nginx_blocked_ip ) );
				},
				$nginx_blocked_ips
			);

		}

		$blocked_ips = array_unique( array_merge( $blocked_ips, $nginx_blocked_ips ) );

		$ban_lines = implode(
			"\n",
			array_map(
				static function ( $blocked_ip ) {
					return "\t" . $blocked_ip . ' false;';
				},
				$blocked_ips
			)
		);

		$config = 'map $http_x_forwarded_for $remote_ip {
	default $http_x_forwarded_for;
	"" $remote_addr;
}

map $remote_ip $real_ip {
    default "";
    "~^(?<first>.*),.*$"  $first;
}

map $real_ip $allow {
    default true;
' . $ban_lines . '
}
';

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_read_file_put_contents
		file_put_contents( self::NGINX_CONF, $config );

		// phpcs:disable WordPress.PHP.DiscouragedPHPFunctions.system_calls_exec
		$output = null;
		exec( 'sudo nginx -t', $output, $result );

		if ( $result ) {
			exec( 'sudo systemctl restart nginx' );
		}
		// phpcs:enable WordPress.PHP.DiscouragedPHPFunctions.system_calls_exec
	}

	/**
	 * Get blocked IPs from Wordfence.
	 *
	 * @return array
	 */
	private function get_blocked_ips(): array {
		global $wpdb;

		if ( ! is_plugin_active( 'wordfence/wordfence.php' ) ) {
			return [];
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
			return [];
		}

		return array_map(
			static function ( $row ) {
				// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
				return wfUtils::inet_ntop( $row->IP );
			},
			$rows
		);
	}
}
