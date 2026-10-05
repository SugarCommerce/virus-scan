# Virus Scan

Malware scanning for stored uploads: ClamAV over clamd's `INSTREAM`, a VirusTotal lookup by digest, and a panel that combines them without mistaking an outage for a clean bill of health. Files are read a range at a time, so a two-gigabyte upload never sits in memory.

## Why

Scanning an upload looks like one function call. Most of the ways it goes wrong are in the parts around the call:

- **An outage reads as a pass.** A scanner that is down, rate-limited or timed out has not said the file is clean. Code that turns "no answer" into "nothing found" serves every upload while the scanner is broken.
- **"Never seen it" reads as a failure.** A hash lookup knows nothing about a file nobody has uploaded before, which is every new file. Treating that as an error retries for ever; treating it as clean is fine only if something else looked at the bytes.
- **The digest is a claim.** A hash lookup judges a file by its SHA-256 alone. If that digest came from the uploader's browser, known malware under a made-up digest is a file nobody has "ever seen".
- **A truncated scan reads as clean.** clamd stops at its `StreamMaxLength` and answers about the part it read.
- **Big files end up in memory**, or on a disk the scanner was never meant to touch.

## Features

- 🧭 **Four answers, not two.** `clean`, `infected`, `unknown` (nothing to say) and `error` (ask again) — so an outage can never become a pass.
- 🧮 **Digest computed, not trusted.** `Subject::digest()` reads every byte; hand the result to the lookups.
- 📏 **Exact-length reads.** A range that comes back short, or a server that ignores `Range`, is an exception, never a smaller file.
- 🦠 **ClamAV `INSTREAM`.** Streamed from wherever the bytes are, refused above the stream limit rather than scanned in part, with `ping()` and `version()` for health checks.
- 🔎 **VirusTotal by hash.** The file is never sent. Two engines must agree before a file counts as malware.
- 🧩 **A panel that combines them.** Infected from any one wins; an error from any one means retry; one clean answer is clean.
- 🔐 **API key kept out of stack traces** with `#[\SensitiveParameter]`.

## Requirements

PHP 8.5+, `sugarcommerce/http-client`

## Installation

```bash
composer require sugarcommerce/virus-scan
```

## The file: `Subject`

A size, a digest and a way to read a range of bytes. Nothing about where the bytes live.

```php
use SugarCommerce\VirusScan\Subject;

// An object in a bucket: any reader of inclusive byte ranges will do.
$subject = new Subject(
    $row['size_bytes'],
    $row['sha256'],                                   // a claim, until checked
    fn ( int $from, int $to ): string => $bucket->read( $key, $from, $to ),
);

$real    = $subject->digest();                        // reads every byte, 8 MiB at a time
$subject = $subject->with_sha256( $real );            // ask the lookups about the bytes

Subject::from_string( $bytes );                       // in memory; digest computed
Subject::from_stream( $handle, $size );               // any seekable stream
```

Every read must come back exactly as long as was asked for, or `RuntimeException` is thrown.

## Scanners

```php
use SugarCommerce\VirusScan\{Clamd, Panel, VirusTotal};

$clamd = new Clamd( Clamd::address( 'scanner', '' ), limit: 2_147_483_648 );   // tcp://scanner:3310
$vt    = new VirusTotal( $api_key, $http );                                     // an HttpClient\Client

$panel   = new Panel( $clamd, $vt );     // cheapest first: an infected answer stops the rest
$verdict = $panel->scan( $subject );

match ( true ) {
    $verdict->is_infected()            => block( $verdict->detail ),        // "clamav: Eicar-Test-Signature"
    $verdict->state->worth_retrying()  => retry_later( $verdict->detail ),
    Panel::unjudged( $verdict )        => hand_to_a_person( $verdict->detail ),
    default                            => release(),                        // clean, or nobody has seen it
};
```

`Clamd::address( $host, $socket )` prefers a unix socket, and gives a bare host clamd's default port. `accepts()` refuses a file over the stream limit, so it is scanned whole or not by clamd at all; the panel then asks only the scanners that can take it, and answers `Panel::NOBODY` when none can.

For a health check:

```php
$clamd->ping();       // PING → PONG
$clamd->version();    // "ClamAV 1.4.1/27431/Mon Oct  5 08:20:31 2026" — a stale date is a scanner that stopped updating
```

### Writing your own

```php
use SugarCommerce\VirusScan\{Scanner, Subject, Verdict};

final class Quarantine implements Scanner {
    public function name(): string { return 'quarantine'; }
    public function accepts( int $bytes ): bool { return true; }
    public function scan( Subject $subject ): Verdict { /* never throw: return Verdict::error() */ }
}
```

## Combining verdicts

`Verdict::combine( array $by_name )` is what the panel uses, for callers that ask their scanners themselves:

| Any infected | Any error | Any clean | Result |
|---|---|---|---|
| yes | – | – | infected |
| no | yes | – | error |
| no | no | yes | clean |
| no | no | no | unknown, every reason joined |

## Testing

```bash
composer install
composer test
```

52 tests. clamd is the far end of a local socket pair and VirusTotal is `HttpClient\Fake`, so nothing reaches a real scanner. Covered: `INSTREAM` framing across read and chunk sizes, every clamd reply, an answer that arrives before a hang-up, short reads, `PING`/`VERSION`, VirusTotal's thresholds, 404, quota and outage handling, exact-length range reads from strings and streams, and every row of the combining table.

## License

GPL-2.0-or-later
