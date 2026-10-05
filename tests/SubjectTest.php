<?php
/**
 * Subject test suite.
 *
 * @package   SugarCommerce\VirusScan
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\VirusScan\Tests;

use PHPUnit\Framework\TestCase;
use SugarCommerce\VirusScan\Subject;

/**
 * Class SubjectTest
 *
 * What a scanner reads, and the digest it is judged by.
 */
final class SubjectTest extends TestCase {

	/* ─── The digest ───────────────────────────────────────────────────── */

	public function test_the_digest_is_of_the_bytes_read(): void {
		$this->assertSame( hash( 'sha256', 'hello world' ), Subject::from_string( 'hello world' )->digest() );
	}

	public function test_a_large_file_is_hashed_a_range_at_a_time(): void {
		$bytes = str_repeat( 'a', 1000 ) . 'tail';
		$reads = 0;
		$subject = new Subject( strlen( $bytes ), '', static function ( int $from, int $to ) use ( $bytes, &$reads ): string {
			++$reads;

			return substr( $bytes, $from, $to - $from + 1 );
		} );

		$this->assertSame( hash( 'sha256', $bytes ), $subject->digest( 100 ) );
		$this->assertSame( 11, $reads );
	}

	/**
	 * A server that ignores Range answers with the whole object; one that
	 * stops short answers with less. Either way it is not the file.
	 */
	public function test_a_read_of_the_wrong_length_is_refused(): void {
		$whole = new Subject( 5, '', static fn (): string => 'hello world' );

		$this->expectException( \RuntimeException::class );

		$whole->digest();
	}

	public function test_a_short_read_is_refused(): void {
		$this->expectException( \RuntimeException::class );

		( new Subject( 5, '', static fn (): string => 'he' ) )->read( 0, 4 );
	}

	public function test_an_empty_file_hashes_without_reading(): void {
		$subject = new Subject( 0, '', static fn (): string => throw new \LogicException( 'Never read.' ) );

		$this->assertSame( hash( 'sha256', '' ), $subject->digest() );
	}

	public function test_a_subject_known_only_by_its_digest_cannot_be_read(): void {
		$subject = new Subject( 5, str_repeat( 'A', 64 ) );

		$this->assertFalse( $subject->readable() );
		$this->assertSame( str_repeat( 'a', 64 ), $subject->sha256, 'Lower-cased.' );

		$this->expectException( \LogicException::class );

		$subject->read( 0, 4 );
	}

	/* ─── Building one ─────────────────────────────────────────────────── */

	public function test_a_digest_that_is_not_one_is_no_digest(): void {
		$this->assertSame( '', ( new Subject( 1, 'short' ) )->sha256 );
		$this->assertSame( '', ( new Subject( 1, str_repeat( 'z', 64 ) ) )->sha256 );
	}

	public function test_another_digest_keeps_the_bytes(): void {
		$subject = Subject::from_string( 'abc' )->with_sha256( str_repeat( 'b', 64 ) );

		$this->assertSame( str_repeat( 'b', 64 ), $subject->sha256 );
		$this->assertSame( 'abc', $subject->read( 0, 2 ) );
	}

	public function test_a_stream_is_read_by_range(): void {
		$handle = fopen( 'php://temp', 'w+b' );
		fwrite( $handle, 'hello world' );

		$subject = Subject::from_stream( $handle, 11 );

		$this->assertSame( 'world', $subject->read( 6, 10 ) );
		$this->assertSame( 'hello', $subject->read( 0, 4 ) );
		$this->assertSame( hash( 'sha256', 'hello world' ), $subject->digest( 4 ) );

		fclose( $handle );
	}

	public function test_a_stream_shorter_than_its_size_is_refused(): void {
		$handle = fopen( 'php://temp', 'w+b' );
		fwrite( $handle, 'abc' );

		$this->expectException( \RuntimeException::class );

		Subject::from_stream( $handle, 10 )->digest();
	}

	public function test_a_negative_size_is_refused(): void {
		$this->expectException( \InvalidArgumentException::class );

		new Subject( -1 );
	}

	public function test_ranges_cover_the_file_exactly(): void {
		$ranges = iterator_to_array( Subject::from_string( 'abcdefg' )->ranges( 3 ) );

		$this->assertSame( array( 0 => 'abc', 3 => 'def', 6 => 'g' ), $ranges );
	}
}
