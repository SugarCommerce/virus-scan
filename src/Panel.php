<?php
/**
 * Several scanners, asked as one.
 *
 * @package   SugarCommerce\VirusScan
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\VirusScan;

/**
 * Class Panel
 *
 * The usual set-up is clamd for what fits its stream limit and a hash
 * lookup for everything, and the usual mistake is in how their answers are
 * put together. This asks every scanner that can take the file and combines
 * them by Verdict::combine(): infected from any one wins, an error from any
 * one means ask again, and a clean answer from one is not undone by another
 * having nothing to say.
 *
 * Two answers say the panel itself could not judge, and both are unknown
 * with a fixed detail so a caller can tell them apart from a scanner's own
 * "never seen it": NONE when nothing is configured, NOBODY when nothing
 * configured can take a file this big. Neither is worth retrying — the
 * configuration will not change in a minute — so both belong in front of a
 * person rather than in a retry loop.
 *
 * @since 1.0.0
 */
final readonly class Panel {

	/**
	 * The detail when there are no scanners at all.
	 */
	public const string NONE = 'no scanner configured';

	/**
	 * The detail when no scanner accepts a file this size.
	 */
	public const string NOBODY = 'too big for every configured scanner';

	/**
	 * The scanners, in the order they are asked.
	 *
	 * @var array<int, Scanner>
	 */
	private array $scanners;

	/**
	 * A panel of scanners.
	 *
	 * @since 1.0.0
	 *
	 * @param Scanner ...$scanners In the order to ask them. Cheapest first:
	 *                             an infected answer stops the rest.
	 */
	public function __construct( Scanner ...$scanners ) {
		$this->scanners = array_values( $scanners );
	}

	/**
	 * Every scanner on the panel.
	 *
	 * @since 1.0.0
	 *
	 * @return array<int, Scanner>
	 */
	public function scanners(): array {
		return $this->scanners;
	}

	/**
	 * The scanners that can take a file this big.
	 *
	 * @since 1.0.0
	 *
	 * @param int $bytes File size.
	 *
	 * @return array<int, Scanner>
	 */
	public function able( int $bytes ): array {
		return array_values( array_filter( $this->scanners, static fn ( Scanner $scanner ): bool => $scanner->accepts( $bytes ) ) );
	}

	/**
	 * Ask every scanner that can take this file.
	 *
	 * Stops at the first infected answer: the rest cannot change it.
	 *
	 * @since 1.0.0
	 *
	 * @param Subject $subject The file. Give it a computed digest
	 *                         (Subject::digest()) when any scanner looks
	 *                         files up by hash.
	 *
	 * @return Verdict With every detail credited to its scanner.
	 */
	public function scan( Subject $subject ): Verdict {
		if ( array() === $this->scanners ) {
			return Verdict::unknown( self::NONE );
		}

		$able = $this->able( $subject->size );

		if ( array() === $able ) {
			return Verdict::unknown( self::NOBODY );
		}

		$verdicts = array();

		foreach ( $able as $scanner ) {
			$verdict = $scanner->scan( $subject );

			if ( $verdict->is_infected() ) {
				return $verdict->from( $scanner->name() );
			}

			// Two scanners under one name — two clamds — must not share a
			// slot: the second one's clean would overwrite the first's error.
			$name = $scanner->name();

			for ( $n = 2; isset( $verdicts[ $name ] ); $n++ ) {
				$name = $scanner->name() . '#' . $n;
			}

			$verdicts[ $name ] = $verdict;
		}

		return Verdict::combine( $verdicts );
	}

	/**
	 * Whether a verdict is the panel saying it could not judge, rather
	 * than a scanner saying it had nothing to say.
	 *
	 * @since 1.0.0
	 *
	 * @param Verdict $verdict From scan().
	 *
	 * @return bool
	 */
	public static function unjudged( Verdict $verdict ): bool {
		return State::Unknown === $verdict->state && in_array( $verdict->detail, array( self::NONE, self::NOBODY ), true );
	}
}
