<?php
/**
 * Something that can say whether a file is malware.
 *
 * @package   SugarCommerce\VirusScan
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\VirusScan;

/**
 * Interface Scanner
 *
 * A scanner never throws for a scan it could not make: a refused
 * connection, a quota, a timeout are all Verdict::error(), so the caller
 * has one thing to handle and an outage can never escape as a pass. See
 * State for why there are four answers rather than two.
 *
 * @since 1.0.0
 */
interface Scanner {

	/**
	 * A short name, for notes and health checks: `clamav`, `virustotal`.
	 *
	 * @since 1.0.0
	 *
	 * @return string
	 */
	public function name(): string;

	/**
	 * Whether this scanner can look at a file this big.
	 *
	 * A scanner that would only see part of a file must say no here, not
	 * scan the part and answer clean.
	 *
	 * @since 1.0.0
	 *
	 * @param int $bytes File size.
	 *
	 * @return bool
	 */
	public function accepts( int $bytes ): bool;

	/**
	 * Look at one file.
	 *
	 * @since 1.0.0
	 *
	 * @param Subject $subject The file.
	 *
	 * @return Verdict
	 */
	public function scan( Subject $subject ): Verdict;
}
