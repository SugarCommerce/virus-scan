<?php
/**
 * A VirusTotal lookup by digest.
 *
 * @package   SugarCommerce\VirusScan
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\VirusScan;

use SugarCommerce\HttpClient\Client;

/**
 * Class VirusTotal
 *
 * Asks whether anybody has already scanned these exact bytes. The file is
 * never sent, only its SHA-256, so a seller's unreleased album does not end
 * up in a third party's corpus. That makes it blind to anything new: a file
 * VirusTotal has never seen is unknown, which is not the same as infected
 * and is never treated as such.
 *
 * Works at any size, which is why it is the check for files too big to
 * stream to clamd.
 *
 * It judges the digest it is given. Give it one computed from the bytes
 * (Subject::digest()), never the one an upload arrived with: known malware
 * under a made-up digest is a file VirusTotal has "never seen".
 *
 * @since 1.0.0
 */
final readonly class VirusTotal implements Scanner {

	/**
	 * Engines that must agree before a file counts as malware.
	 *
	 * Two, not one. A single engine flagging a legitimate installer is
	 * common enough that one vote would block honest software; two
	 * independent engines agreeing rarely happens by accident.
	 */
	public const int ENGINES = 2;

	/**
	 * The files endpoint.
	 */
	public const string ENDPOINT = 'https://www.virustotal.com/api/v3/files/';

	/**
	 * Hold the key, and how many engines must agree.
	 *
	 * @since 1.0.0
	 *
	 * @param string $key     VirusTotal API key.
	 * @param Client $http    HTTP client. A fake in tests: nothing in a
	 *                        test suite should reach VirusTotal.
	 * @param int    $engines Engines that must agree. At least one.
	 * @param int    $timeout Seconds to wait.
	 */
	public function __construct(
		#[\SensitiveParameter]
		private string $key,
		private Client $http = new Client(),
		private int $engines = self::ENGINES,
		private int $timeout = 20,
	) {}

	/**
	 * {@inheritDoc}
	 *
	 * @since 1.0.0
	 */
	public function name(): string {
		return 'virustotal';
	}

	/**
	 * What var_dump() and print_r() show: the settings, with the key redacted.
	 *
	 * @since 1.1.0
	 *
	 * @return array<string, mixed>
	 */
	public function __debugInfo(): array {
		return array(
			'key'     => '' === $this->key ? '' : '[redacted]',
			'engines' => $this->engines,
			'timeout' => $this->timeout,
		);
	}

	/**
	 * {@inheritDoc}
	 *
	 * @since 1.0.0
	 */
	public function accepts( int $bytes ): bool {
		return true;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @since 1.0.0
	 */
	public function scan( Subject $subject ): Verdict {
		if ( '' === $subject->sha256 ) {
			return Verdict::unknown( 'no whole-file digest to look up' );
		}

		$response = $this->http->with_timeout( $this->timeout )->get(
			self::ENDPOINT . $subject->sha256,
			array( 'x-apikey' => $this->key, 'Accept' => 'application/json' )
		);

		return match ( true ) {
			404 === $response->status => Verdict::unknown( 'VirusTotal has not seen this file' ),
			$response->ok             => self::judge( is_array( $body = $response->json() ) ? $body : array(), $this->engines ),
			default                   => Verdict::error( sprintf( 'VirusTotal answered %d %s', $response->status, $response->error ) ),
		};
	}

	/**
	 * What the last analysis said.
	 *
	 * Clean only when some engine looked: an analysis in which every engine
	 * timed out, failed or could not read the type has no opinion, and is
	 * unknown — not a pass.
	 *
	 * @since 1.0.0
	 *
	 * @param array<mixed> $body    The /files/{id} answer.
	 * @param int          $engines Engines that must agree.
	 *
	 * @return Verdict Infected with the suggested label and the vote count;
	 *                 unknown when there is no analysis, or no engine judged.
	 */
	public static function judge( array $body, int $engines = self::ENGINES ): Verdict {
		$attributes = self::at( $body, 'data', 'attributes' );
		$stats      = self::at( $attributes, 'last_analysis_stats' );
		$count      = static fn ( string $key ): int => is_numeric( $stats[ $key ] ?? null ) ? max( 0, (int) $stats[ $key ] ) : 0;
		$votes      = $count( 'malicious' );

		if ( $votes >= max( 1, $engines ) ) {
			$label = self::at( $attributes, 'popular_threat_classification' )['suggested_threat_label'] ?? '';
			$label = is_string( $label ) ? $label : '';

			return Verdict::infected( sprintf( '%s (%d engines on VirusTotal)', '' === $label ? 'malicious' : $label, $votes ) );
		}

		if ( array() === $stats ) {
			return Verdict::unknown( 'VirusTotal has no analysis of this file' );
		}

		$judged = $votes + $count( 'suspicious' ) + $count( 'undetected' ) + $count( 'harmless' );

		return 0 === $judged ? Verdict::unknown( 'no engine on VirusTotal could judge this file' ) : Verdict::clean();
	}

	/**
	 * The array at a path into decoded JSON, or an empty one.
	 *
	 * @param array<mixed> $json    Decoded JSON.
	 * @param string       ...$path Keys, outermost first.
	 *
	 * @return array<mixed>
	 */
	private static function at( array $json, string ...$path ): array {
		foreach ( $path as $key ) {
			$next = $json[ $key ] ?? null;
			$json = is_array( $next ) ? $next : array();
		}

		return $json;
	}
}
