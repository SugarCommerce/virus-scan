<?php
/**
 * VirusTotal test suite.
 *
 * @package   SugarCommerce\VirusScan
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\VirusScan\Tests;

use PHPUnit\Framework\TestCase;
use SugarCommerce\HttpClient\{Fake, Response};
use SugarCommerce\VirusScan\{State, Subject, VirusTotal};

/**
 * Class VirusTotalTest
 *
 * VirusTotal is a scripted HTTP client throughout. Nothing here reaches it.
 */
final class VirusTotalTest extends TestCase {

	private const string SHA = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

	private static function stats( int $malicious, string $label = '' ): Response {
		$attributes = array( 'last_analysis_stats' => array( 'malicious' => $malicious, 'undetected' => 60 ) );

		if ( '' !== $label ) {
			$attributes['popular_threat_classification'] = array( 'suggested_threat_label' => $label );
		}

		return new Response( true, 200, (string) json_encode( array( 'data' => array( 'attributes' => $attributes ) ) ) );
	}

	private static function subject(): Subject {
		return new Subject( 5, self::SHA );
	}

	public function test_it_asks_by_digest_with_the_key_and_never_sends_the_file(): void {
		$http = Fake::strict()->on( 'GET', VirusTotal::ENDPOINT . '*', self::stats( 0 ) );

		$verdict = ( new VirusTotal( 'vt-key', $http ) )->scan( Subject::from_string( 'abcde' )->with_sha256( self::SHA ) );
		$sent    = $http->sent( 'GET' );

		$this->assertSame( State::Clean, $verdict->state );
		$this->assertCount( 1, $sent );
		$this->assertSame( VirusTotal::ENDPOINT . self::SHA, $sent[0]['url'] );
		$this->assertSame( 'vt-key', $sent[0]['headers']['x-apikey'] );
		$this->assertCount( 0, $http->sent( 'POST' ) );
	}

	public function test_a_file_it_has_never_seen_is_unknown_not_infected(): void {
		$http = Fake::strict()->on( 'GET', '*', new Response( false, 404, '{"error":{"code":"NotFoundError"}}' ) );

		$this->assertSame( State::Unknown, ( new VirusTotal( 'k', $http ) )->scan( self::subject() )->state );
	}

	public function test_two_engines_agreeing_is_infected_with_the_label(): void {
		$http = Fake::strict()->on( 'GET', '*', self::stats( VirusTotal::ENGINES, 'trojan.eicar/test' ) );

		$verdict = ( new VirusTotal( 'k', $http ) )->scan( self::subject() );

		$this->assertTrue( $verdict->is_infected() );
		$this->assertSame( 'trojan.eicar/test (2 engines on VirusTotal)', $verdict->detail );
	}

	public function test_one_engine_alone_is_not_enough(): void {
		$http = Fake::strict()->on( 'GET', '*', self::stats( 1 ) );

		$this->assertSame( State::Clean, ( new VirusTotal( 'k', $http ) )->scan( self::subject() )->state );
	}

	public function test_the_threshold_can_be_raised_or_lowered(): void {
		$http = Fake::strict()->on( 'GET', '*', self::stats( 1 ) );

		$this->assertTrue( ( new VirusTotal( 'k', $http, engines: 1 ) )->scan( self::subject() )->is_infected() );
		$this->assertTrue( VirusTotal::judge( array( 'data' => array( 'attributes' => array( 'last_analysis_stats' => array( 'malicious' => 1 ) ) ) ), 0 )->is_infected(), 'Never below one vote.' );
		$this->assertFalse( VirusTotal::judge( array( 'data' => array( 'attributes' => array( 'last_analysis_stats' => array( 'malicious' => 3 ) ) ) ), 4 )->is_infected() );
	}

	/**
	 * Every engine timed out, failed or could not read the type: nobody
	 * judged it, so it is not clean.
	 */
	public function test_an_analysis_no_engine_judged_is_unknown_not_clean(): void {
		$stats = array( 'malicious' => 0, 'suspicious' => 0, 'undetected' => 0, 'harmless' => 0, 'timeout' => 12, 'type-unsupported' => 60 );

		$this->assertSame( State::Unknown, VirusTotal::judge( array( 'data' => array( 'attributes' => array( 'last_analysis_stats' => $stats ) ) ) )->state );
		$this->assertSame( State::Clean, VirusTotal::judge( array( 'data' => array( 'attributes' => array( 'last_analysis_stats' => array( 'undetected' => 70 ) ) ) ) )->state );
		$this->assertSame( State::Unknown, VirusTotal::judge( array( 'data' => array( 'attributes' => array( 'last_analysis_stats' => array( 'undetected' => -5 ) ) ) ) )->state );
	}

	public function test_a_dump_does_not_show_the_key(): void {
		$this->assertStringNotContainsString( 'vt-secret', print_r( new VirusTotal( 'vt-secret' ), true ) );
	}

	public function test_no_analysis_at_all_is_unknown(): void {
		$this->assertSame( State::Unknown, VirusTotal::judge( array( 'data' => array( 'attributes' => array() ) ) )->state );
	}

	public function test_an_outage_or_quota_is_an_error_to_retry(): void {
		foreach ( array( new Response( false, 429, '' ), new Response( false, 503, '' ), Response::failure( 'timeout' ) ) as $answer ) {
			$http = Fake::strict()->on( 'GET', '*', $answer );

			$this->assertSame( State::Error, ( new VirusTotal( 'k', $http ) )->scan( self::subject() )->state );
		}
	}

	public function test_it_takes_files_of_any_size(): void {
		$scanner = new VirusTotal( 'k', Fake::strict() );

		$this->assertTrue( $scanner->accepts( PHP_INT_MAX ) );
		$this->assertSame( 'virustotal', $scanner->name() );
	}

	public function test_a_file_without_a_whole_file_digest_is_not_looked_up(): void {
		$http = Fake::strict();

		$verdict = ( new VirusTotal( 'k', $http ) )->scan( new Subject( 5, 'short' ) );

		$this->assertSame( State::Unknown, $verdict->state );
		$this->assertSame( array(), $http->sent() );
	}

	public function test_the_key_is_kept_out_of_stack_traces(): void {
		$parameter = ( new \ReflectionMethod( VirusTotal::class, '__construct' ) )->getParameters()[0];

		$this->assertCount( 1, $parameter->getAttributes( \SensitiveParameter::class ) );
	}
}
