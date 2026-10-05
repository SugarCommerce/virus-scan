<?php
/**
 * ClamAV, through clamd's INSTREAM command.
 *
 * @package   SugarCommerce\VirusScan
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\VirusScan;

/**
 * Class Clamd
 *
 * The file is read a range at a time and passed straight on, so a large
 * upload never sits in this process's memory and never touches its disk:
 * clamd sees the bytes, nothing else does. That is also why it is INSTREAM
 * rather than SCAN: SCAN needs the file on a disk clamd can read.
 *
 * INSTREAM is `zINSTREAM\0`, then chunks each prefixed with their length as
 * four big-endian bytes, then four zero bytes. clamd answers
 * `stream: OK`, `stream: <name> FOUND`, or `… ERROR`.
 *
 * Two mistakes it is built to avoid:
 *
 * - **A truncated scan reported clean.** clamd stops reading at its
 *   StreamMaxLength and answers about what it read. accepts() refuses
 *   anything longer than the limit it is given, so a file is scanned whole
 *   or not by this scanner at all.
 * - **A hang-up taken as an error when clamd had answered.** clamd can
 *   reply and close before the stream ends — a match early in the file,
 *   or the size limit — and the next write fails. What it said, if
 *   anything, outranks the failed write.
 *
 * @since 1.0.0
 */
final readonly class Clamd implements Scanner {

	/**
	 * Bytes per INSTREAM chunk. clamd's StreamMaxLength is per stream, not
	 * per chunk, so this only bounds a single write.
	 */
	public const int CHUNK = 1024 * 1024;

	/**
	 * clamd's default port.
	 */
	public const int PORT = 3310;

	/**
	 * @since 1.0.0
	 *
	 * @param string        $address tcp://host:port or unix:///path/clamd.sock.
	 *                               See address().
	 * @param int           $limit   clamd's StreamMaxLength. Anything longer
	 *                               would be cut off by clamd, so it is not
	 *                               accepted.
	 * @param int           $timeout Seconds to wait on clamd, per read and
	 *                               write.
	 * @param \Closure|null $connect Opens the connection: returns a stream or
	 *                               false. For tests; null connects to
	 *                               $address.
	 * @param int           $read    Bytes read from the subject at a time.
	 * @param int           $chunk   Bytes per INSTREAM chunk.
	 */
	public function __construct(
		private string $address,
		private int $limit = 2_147_483_648,
		private int $timeout = 60,
		private ?\Closure $connect = null,
		private int $read = Subject::READ,
		private int $chunk = self::CHUNK,
	) {}

	/**
	 * The address clamd is at, from configuration.
	 *
	 * A socket path wins over a host: on the same machine it is faster and
	 * needs no port open.
	 *
	 * @since 1.0.0
	 *
	 * @param string $host   host or host:port, or ''.
	 * @param string $socket A unix socket path, or ''.
	 *
	 * @return string '' when neither is set.
	 */
	public static function address( string $host, string $socket = '' ): string {
		return match ( true ) {
			'' !== $socket => 'unix://' . $socket,
			'' !== $host   => 'tcp://' . ( str_contains( $host, ':' ) ? $host : $host . ':' . self::PORT ),
			default        => '',
		};
	}

	/**
	 * {@inheritDoc}
	 *
	 * @since 1.0.0
	 */
	public function name(): string {
		return 'clamav';
	}

	/**
	 * {@inheritDoc}
	 *
	 * @since 1.0.0
	 */
	public function accepts( int $bytes ): bool {
		return $bytes <= $this->limit;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @since 1.0.0
	 */
	public function scan( Subject $subject ): Verdict {
		if ( ! $subject->readable() ) {
			return Verdict::unknown( 'clamd needs the bytes, not only a digest' );
		}

		$stream = $this->open();

		if ( false === $stream ) {
			return Verdict::error( 'clamd is not reachable at ' . $this->address );
		}

		try {
			return $this->instream( $stream, $subject );
		} catch ( \Throwable $e ) {
			$said = self::answer( (string) @stream_get_contents( $stream ) );

			return State::Error === $said->state && str_contains( $said->detail, 'without answering' ) ? Verdict::error( $e->getMessage() ) : $said;
		} finally {
			fclose( $stream );
		}
	}

	/**
	 * Whether clamd is up and answering.
	 *
	 * For a health check: PING, expecting PONG.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	#[\NoDiscard( 'False means uploads are not being scanned by clamd.' )]
	public function ping(): bool {
		return 'PONG' === $this->ask( 'PING' );
	}

	/**
	 * clamd's version and signature database date.
	 *
	 * e.g. "ClamAV 1.4.1/27431/Mon Oct  5 08:20:31 2026". A database date
	 * weeks old is a scanner that has stopped updating, which a health check
	 * wants to know about.
	 *
	 * @since 1.0.0
	 *
	 * @return string '' when clamd did not answer.
	 */
	public function version(): string {
		return $this->ask( 'VERSION' );
	}

	/**
	 * What clamd's reply to INSTREAM means.
	 *
	 * @since 1.0.0
	 *
	 * @param string $reply e.g. "stream: OK\0".
	 *
	 * @return Verdict
	 */
	public static function answer( string $reply ): Verdict {
		$reply = trim( $reply, "\0\n\r " );

		return match ( true ) {
			str_ends_with( $reply, 'FOUND' ) => Verdict::infected( trim( substr( $reply, (int) strpos( $reply, ':' ) + 1, -5 ) ) ),
			str_ends_with( $reply, ': OK' )  => Verdict::clean(),
			default                          => Verdict::error( '' === $reply ? 'clamd closed without answering' : $reply ),
		};
	}

	/**
	 * Send the file, and read the answer.
	 *
	 * @param resource $stream  Open connection.
	 * @param Subject  $subject The file.
	 *
	 * @return Verdict
	 *
	 * @throws \RuntimeException When the connection drops or a read is short.
	 */
	private function instream( $stream, Subject $subject ): Verdict {
		self::write( $stream, "zINSTREAM\0" );

		foreach ( $subject->ranges( $this->read ) as $bytes ) {
			foreach ( str_split( $bytes, max( 1, $this->chunk ) ) as $chunk ) {
				self::write( $stream, pack( 'N', strlen( $chunk ) ) . $chunk );
			}
		}

		self::write( $stream, pack( 'N', 0 ) );

		return self::answer( (string) stream_get_contents( $stream ) );
	}

	/**
	 * Send one short command and read the reply.
	 *
	 * @param string $command PING, VERSION.
	 *
	 * @return string The reply, trimmed, or '' when there was none.
	 */
	private function ask( string $command ): string {
		$stream = $this->open();

		if ( false === $stream ) {
			return '';
		}

		try {
			self::write( $stream, 'z' . $command . "\0" );

			return trim( (string) stream_get_contents( $stream ), "\0\n\r " );
		} catch ( \RuntimeException ) {
			return '';
		} finally {
			fclose( $stream );
		}
	}

	/**
	 * Open a connection, with the timeout applied to every read and write.
	 *
	 * @return resource|false
	 */
	private function open() {
		$stream = null !== $this->connect
			? ( $this->connect )()
			: @stream_socket_client( $this->address, $errno, $error, $this->timeout );

		if ( ! is_resource( $stream ) ) {
			return false;
		}

		stream_set_timeout( $stream, $this->timeout );

		return $stream;
	}

	/**
	 * Write all of it, or say the connection went.
	 *
	 * @param resource $stream Connection.
	 * @param string   $bytes  What to send.
	 *
	 * @return void
	 *
	 * @throws \RuntimeException When it cannot be written.
	 */
	private static function write( $stream, string $bytes ): void {
		for ( $sent = 0, $length = strlen( $bytes ); $sent < $length; $sent += $wrote ) {
			// Silenced: a closed connection is reported by the exception
			// below, with the reply clamd may have left before closing.
			$wrote = @fwrite( $stream, substr( $bytes, $sent ) );

			if ( false === $wrote || 0 === $wrote ) {
				throw new \RuntimeException( 'The connection to clamd closed while sending.' );
			}
		}
	}
}
