<?php
/**
 * The four things a scanner can say.
 *
 * @package   SugarCommerce\VirusScan
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\VirusScan;

/**
 * Enum State
 *
 * Two answers decide something and two do not. Clean and infected are
 * verdicts. Unknown means this scanner has nothing to say — a hash lookup
 * that has never seen the file — and error means it could not look, so ask
 * again later.
 *
 * Keeping the last two apart is the whole design. Collapse error into
 * clean and a VirusTotal outage, or a clamd that is not running, passes
 * every upload. Collapse unknown into error and every file nobody has
 * uploaded before is a failure that is retried for ever.
 *
 * @since 1.0.0
 */
enum State: string {

	case Clean    = 'clean';
	case Infected = 'infected';
	case Unknown  = 'unknown';
	case Error    = 'error';

	/**
	 * Whether this answer settles anything.
	 *
	 * @since 1.0.0
	 *
	 * @return bool True for clean and infected.
	 */
	public function conclusive(): bool {
		return self::Clean === $this || self::Infected === $this;
	}

	/**
	 * Whether asking again could change the answer.
	 *
	 * Only an error. Unknown is a real answer — nobody has seen these bytes
	 * — and asking a minute later gets the same one.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function worth_retrying(): bool {
		return self::Error === $this;
	}
}
