<?php
/**
 * Clamd test suite.
 *
 * @package   SugarCommerce\VirusScan
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\VirusScan\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SugarCommerce\VirusScan\{Clamd, State, Subject};

/**
 * Class ClamdTest
 *
 * clamd is never reached: it is the far end of a local socket pair, with its
 * answer already waiting.
 */
final class ClamdTest extends TestCase {

	/**
	 * A clamd whose answer is already waiting, and the end that hears what
	 * was sent.
	 *
	 * @param string $reply What clamd says.
	 * @param int    $limit Its stream limit.
	 * @param int    $read  Bytes read from the subject at a time.
	 * @param int    $chunk Bytes per INSTREAM chunk.
	 *
	 * @return array{0: Clamd, 1: resource}
	 */
	private static function clamd( string $reply, int $limit = 1000, int $read = Subject::READ, int $chunk = Clamd::CHUNK ): array {
		[ $ours, $theirs ] = stream_socket_pair( STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP );

		fwrite( $theirs, $reply );
		stream_socket_shutdown( $theirs, STREAM_SHUT_WR );

		return array( new Clamd( 'unix:///nowhere', $limit, 5, static fn () => $ours, $read, $chunk ), $theirs );
	}

	/* ─── INSTREAM ─────────────────────────────────────────────────────── */

	public function test_the_file_is_sent_as_an_instream(): void {
		[ $clamd, $theirs ] = self::clamd( "stream: OK\0" );

		$verdict = $clamd->scan( Subject::from_string( 'hello world' ) );

		$this->assertSame( State::Clean, $verdict->state );
		$this->assertSame( "zINSTREAM\0" . pack( 'N', 11 ) . 'hello world' . pack( 'N', 0 ), stream_get_contents( $theirs ) );
	}

	/**
	 * Read in ranges, sent in chunks: the framing is per chunk, whatever the
	 * read size.
	 */
	public function test_reads_and_chunks_are_framed_separately(): void {
		[ $clamd, $theirs ] = self::clamd( "stream: OK\0", read: 4, chunk: 3 );

		$clamd->scan( Subject::from_string( 'abcdefghij' ) );

		$this->assertSame(
			"zINSTREAM\0" . pack( 'N', 3 ) . 'abc' . pack( 'N', 1 ) . 'd' . pack( 'N', 3 ) . 'efg' . pack( 'N', 1 ) . 'h' . pack( 'N', 2 ) . 'ij' . pack( 'N', 0 ),
			stream_get_contents( $theirs )
		);
	}

	public function test_finding_something_is_infected_with_its_name(): void {
		[ $clamd ] = self::clamd( "stream: Eicar-Test-Signature FOUND\0" );

		$verdict = $clamd->scan( Subject::from_string( 'X5O!P' ) );

		$this->assertTrue( $verdict->is_infected() );
		$this->assertSame( 'Eicar-Test-Signature', $verdict->detail );
	}

	public function test_an_error_reply_is_an_error_not_a_pass(): void {
		[ $clamd ] = self::clamd( "INSTREAM size limit exceeded. ERROR\0" );

		$this->assertSame( State::Error, $clamd->scan( Subject::from_string( 'abcde' ) )->state );
	}

	public function test_an_unreachable_clamd_is_an_error(): void {
		$clamd = new Clamd( 'unix:///nowhere', 1000, 1, static fn () => false );

		$verdict = $clamd->scan( Subject::from_string( 'abcde' ) );

		$this->assertSame( State::Error, $verdict->state );
		$this->assertStringContainsString( 'unix:///nowhere', $verdict->detail );
	}

	/**
	 * A storage read that comes back short must not become a scan of the
	 * shorter file.
	 */
	public function test_a_short_read_is_an_error(): void {
		[ $clamd ] = self::clamd( '' );

		$short = new Subject( 10, '', static fn ( int $from, int $to ): string => 'abc' );

		$this->assertSame( State::Error, $clamd->scan( $short )->state );
	}

	/**
	 * clamd answered and hung up mid-stream: the answer is what counts.
	 */
	public function test_an_answer_before_a_hang_up_outranks_the_failed_write(): void {
		[ $ours, $theirs ] = stream_socket_pair( STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP );

		fwrite( $theirs, "stream: Early.Match FOUND\0" );
		fclose( $theirs );

		$clamd   = new Clamd( 'unix:///nowhere', PHP_INT_MAX, 5, static fn () => $ours );
		$verdict = $clamd->scan( Subject::from_string( str_repeat( 'x', 4 * 1024 * 1024 ) ) );

		$this->assertTrue( $verdict->is_infected(), $verdict->detail );
		$this->assertSame( 'Early.Match', $verdict->detail );
	}

	/**
	 * clamd said OK and hung up before the stream was finished: that OK is
	 * about part of the file, so it is not clean.
	 */
	public function test_a_clean_answer_before_a_hang_up_is_an_error(): void {
		[ $ours, $theirs ] = stream_socket_pair( STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP );

		fwrite( $theirs, "stream: OK\0" );
		fclose( $theirs );

		$clamd   = new Clamd( 'unix:///nowhere', PHP_INT_MAX, 5, static fn () => $ours );
		$verdict = $clamd->scan( Subject::from_string( str_repeat( 'x', 4 * 1024 * 1024 ) ) );

		$this->assertSame( State::Error, $verdict->state, $verdict->detail );
	}

	public function test_a_digest_alone_is_nothing_to_stream(): void {
		$clamd = new Clamd( 'unix:///nowhere', 1000, 1, static fn () => $this->fail( 'Never connects.' ) );

		$this->assertSame( State::Unknown, $clamd->scan( new Subject( 5, str_repeat( 'a', 64 ) ) )->state );
	}

	/* ─── What it accepts ──────────────────────────────────────────────── */

	public function test_only_what_fits_the_stream_limit_is_accepted(): void {
		$clamd = new Clamd( 'unix:///nowhere', 100 );

		$this->assertTrue( $clamd->accepts( 100 ) );
		$this->assertFalse( $clamd->accepts( 101 ) );
		$this->assertSame( 'clamav', $clamd->name() );
	}

	/* ─── Replies ──────────────────────────────────────────────────────── */

	/**
	 * @return array<string, array{string, State, string}>
	 */
	public static function replies(): array {
		return array(
			'ok'           => array( "stream: OK\0", State::Clean, '' ),
			'found'        => array( "stream: Win.Test.EICAR_HDB-1 FOUND\0", State::Infected, 'Win.Test.EICAR_HDB-1' ),
			'newline'      => array( "stream: OK\n", State::Clean, '' ),
			'error'        => array( "INSTREAM size limit exceeded. ERROR\0", State::Error, 'INSTREAM size limit exceeded. ERROR' ),
			'nothing'      => array( '', State::Error, 'clamd closed without answering' ),
		);
	}

	#[DataProvider( 'replies' )]
	public function test_replies_are_read( string $reply, State $state, string $detail ): void {
		$verdict = Clamd::answer( $reply );

		$this->assertSame( $state, $verdict->state );
		$this->assertSame( $detail, $verdict->detail );
	}

	/* ─── Configuration ────────────────────────────────────────────────── */

	public function test_a_socket_wins_over_a_host_and_a_host_gets_the_default_port(): void {
		$this->assertSame( 'unix:///run/clamd.sock', Clamd::address( 'scanner', '/run/clamd.sock' ) );
		$this->assertSame( 'tcp://scanner:3310', Clamd::address( 'scanner', '' ) );
		$this->assertSame( 'tcp://scanner:9999', Clamd::address( 'scanner:9999' ) );
		$this->assertSame( '', Clamd::address( '', '' ) );
	}

	/* ─── Health ───────────────────────────────────────────────────────── */

	public function test_ping_wants_pong(): void {
		[ $clamd, $theirs ] = self::clamd( "PONG\0" );

		$this->assertTrue( $clamd->ping() );
		$this->assertSame( "zPING\0", stream_get_contents( $theirs ) );
	}

	public function test_ping_fails_on_silence_or_no_connection(): void {
		[ $silent ] = self::clamd( '' );

		$this->assertFalse( $silent->ping() );
		$this->assertFalse( ( new Clamd( 'unix:///nowhere', 1, 1, static fn () => false ) )->ping() );
	}

	public function test_version_is_the_reply(): void {
		[ $clamd, $theirs ] = self::clamd( "ClamAV 1.4.1/27431/Mon Oct  5 08:20:31 2026\0" );

		$this->assertSame( 'ClamAV 1.4.1/27431/Mon Oct  5 08:20:31 2026', $clamd->version() );
		$this->assertSame( "zVERSION\0", stream_get_contents( $theirs ) );
		$this->assertSame( '', ( new Clamd( 'unix:///nowhere', 1, 1, static fn () => false ) )->version() );
	}
}
