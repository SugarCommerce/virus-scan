<?php
/**
 * Results that must not be ignored.
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
use SugarCommerce\VirusScan\{Clamd, Verdict};

/**
 * Class MustCheckTest
 *
 * An infected file nothing acts on is still served, and a health check
 * nobody reads checks nothing. #[\NoDiscard] makes PHP warn where such a
 * result is dropped; this keeps the attribute from being lost in a refactor.
 */
final class MustCheckTest extends TestCase {

	/**
	 * @return array<string, array{string}>
	 */
	public static function methods(): array {
		return array(
			'Verdict::is_infected' => array( Verdict::class . '::is_infected' ),
			'Clamd::ping'          => array( Clamd::class . '::ping' ),
		);
	}

	#[DataProvider( 'methods' )]
	public function test_the_result_must_be_used( string $method ): void {
		$attributes = \ReflectionMethod::createFromMethodName( $method )->getAttributes( \NoDiscard::class );

		$this->assertCount( 1, $attributes, $method . ' lost #[\NoDiscard].' );
		$this->assertNotSame( '', $attributes[0]->newInstance()->message, 'Say why it matters.' );
	}
}
