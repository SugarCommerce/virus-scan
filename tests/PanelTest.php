<?php
/**
 * Panel and Verdict test suite.
 *
 * @package   SugarCommerce\VirusScan
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\VirusScan\Tests;

use PHPUnit\Framework\TestCase;
use SugarCommerce\VirusScan\{Panel, Scanner, State, Subject, Verdict};

/**
 * Class PanelTest
 *
 * How several scanners' answers become one: the part an outage must never
 * turn into a pass.
 */
final class PanelTest extends TestCase {

	/**
	 * A scanner that says what it is told, and counts how often it was asked.
	 */
	private static function scanner( Verdict $verdict, string $name = 'fake', int $limit = PHP_INT_MAX ): Scanner {
		return new class( $verdict, $name, $limit ) implements Scanner {
			/** @var int How often it was asked. */
			public int $asked = 0;

			public function __construct( private Verdict $verdict, private string $label, private int $limit ) {}

			public function name(): string {
				return $this->label;
			}

			public function accepts( int $bytes ): bool {
				return $bytes <= $this->limit;
			}

			public function scan( Subject $subject ): Verdict {
				++$this->asked;

				return $this->verdict;
			}
		};
	}

	/* ─── Panel ────────────────────────────────────────────────────────── */

	public function test_infected_from_any_one_wins_and_stops_the_rest(): void {
		$later = self::scanner( Verdict::clean(), 'b' );

		$verdict = ( new Panel( self::scanner( Verdict::infected( 'Trojan' ), 'a' ), $later ) )->scan( Subject::from_string( 'x' ) );

		$this->assertTrue( $verdict->is_infected() );
		$this->assertSame( 'a: Trojan', $verdict->detail );
		$this->assertSame( 0, $later->asked );
	}

	/**
	 * A clean hash lookup does not cover for clamd not having looked.
	 */
	public function test_an_error_from_any_one_is_an_error(): void {
		$verdict = ( new Panel( self::scanner( Verdict::error( 'down' ), 'clamav' ), self::scanner( Verdict::clean(), 'virustotal' ) ) )->scan( Subject::from_string( 'x' ) );

		$this->assertSame( State::Error, $verdict->state );
		$this->assertSame( 'clamav: down', $verdict->detail );
	}

	public function test_one_clean_answer_is_clean(): void {
		$verdict = ( new Panel( self::scanner( Verdict::clean(), 'clamav' ), self::scanner( Verdict::unknown( 'never seen' ), 'virustotal' ) ) )->scan( Subject::from_string( 'x' ) );

		$this->assertTrue( $verdict->is_clean() );
	}

	public function test_unknown_from_every_one_is_unknown_with_every_reason(): void {
		$verdict = ( new Panel( self::scanner( Verdict::unknown( 'never seen' ), 'virustotal' ), self::scanner( Verdict::unknown( 'no idea' ), 'other' ) ) )->scan( Subject::from_string( 'x' ) );

		$this->assertSame( State::Unknown, $verdict->state );
		$this->assertSame( 'virustotal: never seen; other: no idea', $verdict->detail );
		$this->assertFalse( Panel::unjudged( $verdict ) );
	}

	public function test_only_scanners_that_take_the_size_are_asked(): void {
		$small = self::scanner( Verdict::infected( 'x' ), 'clamav', 1 );
		$any   = self::scanner( Verdict::clean(), 'virustotal' );
		$panel = new Panel( $small, $any );

		$this->assertTrue( $panel->scan( Subject::from_string( 'too big' ) )->is_clean() );
		$this->assertSame( 0, $small->asked );
		$this->assertSame( array( $any ), $panel->able( 7 ) );
		$this->assertCount( 2, $panel->scanners() );
	}

	public function test_nobody_able_and_nothing_configured_are_told_apart(): void {
		$nobody = ( new Panel( self::scanner( Verdict::clean(), 'clamav', 1 ) ) )->scan( Subject::from_string( 'too big' ) );
		$none   = ( new Panel() )->scan( Subject::from_string( 'x' ) );

		$this->assertSame( Panel::NOBODY, $nobody->detail );
		$this->assertSame( Panel::NONE, $none->detail );
		$this->assertTrue( Panel::unjudged( $nobody ) );
		$this->assertTrue( Panel::unjudged( $none ) );
	}

	/* ─── Verdict ──────────────────────────────────────────────────────── */

	public function test_only_clean_and_infected_are_conclusive(): void {
		$this->assertTrue( Verdict::clean()->conclusive() );
		$this->assertTrue( Verdict::infected( 'x' )->conclusive() );
		$this->assertFalse( Verdict::unknown()->conclusive() );
		$this->assertFalse( Verdict::error( 'x' )->conclusive() );
		$this->assertTrue( State::Error->worth_retrying() );
		$this->assertFalse( State::Unknown->worth_retrying() );
	}

	public function test_a_verdict_carries_the_digest_it_was_made_on(): void {
		$verdict = Verdict::infected( 'Eicar' )->read( str_repeat( 'A', 64 ) );

		$this->assertSame( str_repeat( 'a', 64 ), $verdict->digest );
		$this->assertSame( 'Eicar', $verdict->detail );
		$this->assertSame( str_repeat( 'a', 64 ), $verdict->from( 'clamav' )->digest, 'Crediting keeps it.' );
	}

	public function test_combining_nothing_is_unknown(): void {
		$this->assertSame( State::Unknown, Verdict::combine( array() )->state );
	}

	public function test_combining_puts_infected_before_an_earlier_error(): void {
		$verdict = Verdict::combine( array( 'a' => Verdict::error( 'down' ), 'b' => Verdict::infected( 'Worm' ) ) );

		$this->assertSame( 'b: Worm', $verdict->detail );
	}
}
