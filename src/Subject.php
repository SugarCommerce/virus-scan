<?php
/**
 * The file a scanner is asked about.
 *
 * @package   SugarCommerce\VirusScan
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\VirusScan;

/**
 * Class Subject
 *
 * A size, a digest, and a way to read a range of bytes — which is all any
 * scanner needs, and nothing about where the bytes live. An object in a
 * bucket, a file on disk and a string in a test are the same thing here.
 *
 * Read a range at a time, never whole: a two-gigabyte upload streamed to
 * clamd, or hashed, never sits in memory. And every range must come back
 * exactly as long as was asked for. A storage server that ignores the
 * Range header answers with the whole object; one that stops short answers
 * with less. Either way the scanner would judge, or the hash would
 * describe, something other than the file — so a read of the wrong length
 * is an exception, not a smaller file.
 *
 * The digest is a claim until digest() has checked it. Hash lookups judge a
 * file by its digest alone, so a digest nobody computed lets known malware
 * through under a made-up name; see the README.
 *
 * @since 1.0.0
 */
final readonly class Subject {

	/**
	 * Bytes per read. Large enough that a big file is not thousands of
	 * requests to a bucket; small enough to hold without noticing.
	 */
	public const int READ = 8 * 1024 * 1024;

	/**
	 * Lower-case hex SHA-256 of the whole file, as claimed, or ''.
	 */
	public string $sha256;

	/**
	 * A file of this size, perhaps with a digest, perhaps readable.
	 *
	 * @since 1.0.0
	 *
	 * @param int           $size   Bytes.
	 * @param string        $sha256 Hex SHA-256 of the whole file, or '' when
	 *                              not known. Lower-cased; anything that is
	 *                              not 64 hex characters is treated as ''.
	 * @param \Closure|null $read   fn( int $from, int $to ): string — the
	 *                              bytes from `$from` to `$to` inclusive,
	 *                              as an HTTP Range is. Null for a subject
	 *                              known only by its digest.
	 *
	 * @throws \InvalidArgumentException When the size is negative.
	 */
	public function __construct(
		public int $size,
		string $sha256 = '',
		private ?\Closure $read = null,
	) {
		if ( $size < 0 ) {
			throw new \InvalidArgumentException( 'A file cannot be smaller than nothing.' );
		}

		$sha256       = strtolower( trim( $sha256 ) );
		$this->sha256 = 64 === strlen( $sha256 ) && ctype_xdigit( $sha256 ) ? $sha256 : '';
	}

	/**
	 * A subject held in memory. Its digest is computed, not claimed.
	 *
	 * @since 1.0.0
	 *
	 * @param string $bytes The whole file.
	 *
	 * @return self
	 */
	public static function from_string( string $bytes ): self {
		return new self(
			strlen( $bytes ),
			hash( 'sha256', $bytes ),
			static fn ( int $from, int $to ): string => substr( $bytes, $from, $to - $from + 1 )
		);
	}

	/**
	 * A subject read from an open, seekable stream.
	 *
	 * The stream stays the caller's to close.
	 *
	 * @since 1.0.0
	 *
	 * @param resource $handle Seekable stream — a file, php://temp.
	 * @param int      $size   Bytes.
	 * @param string   $sha256 Claimed digest, or ''.
	 *
	 * @return self
	 *
	 * @throws \InvalidArgumentException When the handle is not a stream.
	 */
	public static function from_stream( $handle, int $size, string $sha256 = '' ): self {
		if ( ! is_resource( $handle ) ) {
			throw new \InvalidArgumentException( 'Give an open stream.' );
		}

		return new self( $size, $sha256, static function ( int $from, int $to ) use ( $handle ): string {
			if ( 0 !== fseek( $handle, $from ) ) {
				return '';
			}

			$bytes = '';

			while ( ( $want = $to - $from + 1 - strlen( $bytes ) ) > 0 && ! feof( $handle ) ) {
				$chunk = fread( $handle, $want );

				if ( false === $chunk || '' === $chunk ) {
					break;
				}

				$bytes .= $chunk;
			}

			return $bytes;
		} );
	}

	/**
	 * The same subject, under another digest.
	 *
	 * For asking a hash lookup about what the bytes really are, once
	 * digest() has said.
	 *
	 * @since 1.0.0
	 *
	 * @param string $sha256 Hex SHA-256.
	 *
	 * @return self
	 */
	public function with_sha256( string $sha256 ): self {
		return new self( $this->size, $sha256, $this->read );
	}

	/**
	 * Whether there is anything to read, as opposed to only a digest.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function readable(): bool {
		return null !== $this->read;
	}

	/**
	 * One range of bytes.
	 *
	 * @since 1.0.0
	 *
	 * @param int $from First byte.
	 * @param int $to   Last byte, inclusive.
	 *
	 * @return string Exactly `$to - $from + 1` bytes.
	 *
	 * @throws \LogicException    When the subject has no reader.
	 * @throws \RuntimeException  When the reader returns the wrong length,
	 *                            or fails. Whatever the reader throws is
	 *                            passed on.
	 */
	public function read( int $from, int $to ): string {
		if ( null === $this->read ) {
			throw new \LogicException( 'This file is known only by its digest; there is nothing to read.' );
		}

		$bytes = ( $this->read )( $from, $to );

		if ( ! is_string( $bytes ) ) {
			throw new \RuntimeException( 'Storage returned something other than bytes.' );
		}

		if ( strlen( $bytes ) !== $to - $from + 1 ) {
			throw new \RuntimeException( sprintf( 'Storage returned %d bytes for a read of %d.', strlen( $bytes ), $to - $from + 1 ) );
		}

		return $bytes;
	}

	/**
	 * Every byte, a range at a time.
	 *
	 * @since 1.0.0
	 *
	 * @param int $size Bytes per range.
	 *
	 * @return \Generator<int, string> Byte offset => bytes.
	 *
	 * @throws \LogicException   When the subject has no reader.
	 * @throws \RuntimeException When a range comes back the wrong length.
	 */
	public function ranges( int $size = self::READ ): \Generator {
		$size = max( 1, $size );

		for ( $from = 0; $from < $this->size; $from += $size ) {
			yield $from => $this->read( $from, min( $this->size, $from + $size ) - 1 );
		}
	}

	/**
	 * What the bytes really hash to.
	 *
	 * Reads every byte. The digest a file arrives with is somebody's word
	 * for it; this is the one to file it under and to ask a hash lookup
	 * about.
	 *
	 * @since 1.0.0
	 *
	 * @param int $size Bytes per read.
	 *
	 * @return string Lower-case hex SHA-256.
	 *
	 * @throws \LogicException   When the subject has no reader.
	 * @throws \RuntimeException When a read fails or is the wrong length.
	 */
	public function digest( int $size = self::READ ): string {
		$context = hash_init( 'sha256' );

		foreach ( $this->ranges( $size ) as $bytes ) {
			hash_update( $context, $bytes );
		}

		return hash_final( $context );
	}
}
