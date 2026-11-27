<?php

declare(strict_types=1);

namespace Componenta\Auth\Token\Tests;

use Componenta\Auth\Token\DatabaseTokenManager;
use Componenta\Auth\Token\TokenPurpose;
use Componenta\Auth\Token\Tests\Support\SqliteDatabaseFixture;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\Uuid;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use Psr\Log\LoggerAwareInterface;

final class ConsumptionExpiryTest extends TestCase
{
    /** @return iterable<string, array{string, int, bool}> */
    public static function claimDelays(): iterable
    {
        foreach (['UPDATE', 'Commit transaction'] as $boundary) {
            yield $boundary . ' completes before expiry' => [$boundary, 29, true];
            yield $boundary . ' completes at expiry' => [$boundary, 30, false];
            yield $boundary . ' completes after expiry' => [$boundary, 31, false];
        }
    }

    #[DataProvider('claimDelays')]
    public function testTokenMustRemainUnexpiredWhenItsClaimCompletes(
        string $boundary,
        int $delay,
        bool $accepted,
    ): void {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }

        $database = SqliteDatabaseFixture::create();
        $clock = new FrozenClock('2030-01-01T00:00:00Z', 'UTC');
        $tokens = new DatabaseTokenManager($database, $clock);
        $purpose = new TokenPurpose('password_reset');
        $credential = $tokens->issue(
            Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc'),
            $purpose,
            ttlSeconds: 30,
        );
        $driver = $database->getDriver(DatabaseInterface::WRITE);
        self::assertInstanceOf(LoggerAwareInterface::class, $driver);
        $delayOnClaim = new class($clock, $boundary, $delay) extends AbstractLogger {
            public bool $advanced = false;

            public function __construct(
                private FrozenClock $clock,
                private string $boundary,
                private int $delay,
            ) {}

            public function log($level, string|\Stringable $message, array $context = []): void
            {
                if (!$this->advanced && str_starts_with((string) $message, $this->boundary)) {
                    $this->advanced = true;
                    $this->clock->advance(sprintf('+%d seconds', $this->delay));
                }
            }
        };
        $driver->setLogger($delayOnClaim);

        $claimed = $tokens->consume($credential, $purpose);

        self::assertTrue($delayOnClaim->advanced, 'The claim must cross the delayed database boundary.');
        self::assertSame($accepted, $claimed !== null);
        self::assertNull($tokens->consume($credential, $purpose));
    }
}
