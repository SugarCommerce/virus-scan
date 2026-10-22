<?php
/**
 * What a scanner said about one file.
 *
 * @package   SugarCommerce\VirusScan
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\VirusScan;

/**
 * Class Verdict
 *
 * A state, a detail — the signature found, or what went wrong — and,
 * optionally, the SHA-256 of the bytes that were judged. That last one is
 * what lets a caller record what was looked at as well as what was said
 * about it: a verdict on a file whose stored digest was a claim nobody
 * checked is a verdict on something else.
 *
 * Not file-inspect's Verdict, which says whether a file's type is allowed.
 * They share a name and nothing else.
 *
 * @since 1.0.0
 */
final readonly class Verdict {

	/**
	 * A verdict; made by the named constructors.
	 *
	 * @param State  $state  What was said.
	 * @param string $detail The signature found, or what went wrong.
	 * @param string $digest Lower-case hex SHA-256 of the bytes judged, or
	 *                       '' when they were not all read.
	 */
	private function __construct(
		public State $state,
		public string $detail = '',
		public string $digest = '',
	) {}

	/**
	 * Looked, and found nothing.
	 *
	 * @since 1.0.0
	 *
	 * @return self
	 */
	public static function clean(): self {
		return new self( State::Clean );
	}

	/**
	 * Looked, and found this.
	 *
	 * @since 1.0.0
	 *
	 * @param string $signature What the scanner called it.
	 *
	 * @return self
	 */
	public static function infected( string $signature ): self {
		return new self( State::Infected, $signature );
	}

	/**
	 * Has nothing to say about it either way.
	 *
	 * @since 1.0.0
	 *
	 * @param string $why Why not.
	 *
	 * @return self
	 */
	public static function unknown( string $why = '' ): self {
		return new self( State::Unknown, $why );
	}

	/**
	 * Could not look; worth asking again.
	 *
	 * @since 1.0.0
	 *
	 * @param string $why What went wrong.
	 *
	 * @return self
	 */
	public static function error( string $why ): self {
		return new self( State::Error, $why );
	}

	/**
	 * The same verdict, with the digest of the bytes that were read.
	 *
	 * @since 1.0.0
	 *
	 * @param string $digest Hex SHA-256. Lower-cased.
	 *
	 * @return self
	 */
	public function read( string $digest ): self {
		return new self( $this->state, $this->detail, strtolower( $digest ) );
	}

	/**
	 * The same verdict, its detail credited to a scanner.
	 *
	 * "clamav: Eicar-Test-Signature" rather than a bare signature, so an
	 * operator reading the note knows which scanner to argue with.
	 *
	 * @since 1.0.0
	 *
	 * @param string $scanner Scanner name.
	 *
	 * @return self
	 */
	public function from( string $scanner ): self {
		return new self( $this->state, $scanner . ': ' . ( State::Clean === $this->state ? 'clean' : $this->detail ), $this->digest );
	}

	/**
	 * Whether something was found.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	#[\NoDiscard( 'An infected file that nothing acts on is still served.' )]
	public function is_infected(): bool {
		return State::Infected === $this->state;
	}

	/**
	 * Whether the scanner looked and found nothing.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function is_clean(): bool {
		return State::Clean === $this->state;
	}

	/**
	 * Whether this settles anything — clean or infected.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function conclusive(): bool {
		return $this->state->conclusive();
	}

	/**
	 * Several scanners' verdicts on one file, as one.
	 *
	 * In order of weight:
	 *
	 * - **Infected from any one wins.** One scanner finding something is
	 *   enough; the others not finding it is not a defence.
	 * - **An error from any one means ask again.** A clean answer from a
	 *   hash lookup does not cover for clamd not having looked: the lookup
	 *   is blind to anything new, which is exactly what clamd is there for.
	 * - **Clean from any one is clean.** The rest had nothing to say.
	 * - **Unknown from all of them is unknown**, with every scanner's reason
	 *   joined, and is the caller's to decide. For a new upload it is the
	 *   normal state: nothing found it, and nobody has seen it before.
	 *
	 * An empty list is unknown. The details come back credited to their
	 * scanners (see from()).
	 *
	 * @since 1.0.0
	 *
	 * @param array<string, Verdict> $verdicts By scanner name.
	 *
	 * @return self
	 */
	public static function combine( array $verdicts ): self {
		foreach ( array( State::Infected, State::Error ) as $decisive ) {
			foreach ( $verdicts as $name => $verdict ) {
				if ( $decisive === $verdict->state ) {
					return $verdict->from( (string) $name );
				}
			}
		}

		$notes = array();
		$clean = false;

		foreach ( $verdicts as $name => $verdict ) {
			$clean   = $clean || $verdict->is_clean();
			$notes[] = $verdict->from( (string) $name )->detail;
		}

		return $clean ? self::clean() : self::unknown( implode( '; ', $notes ) );
	}
}
