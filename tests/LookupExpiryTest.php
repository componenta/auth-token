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

final class LookupExpiryTest extends TestCase
{
    /** @return iterable<string, array{int, bool}> */
    public static function readDelays(): iterable
    {
        yield 'read completes before expiry' => [29, true];
        yield 'read completes at expiry' => [30, false];
        yield 'read completes after expiry' => [31, false];
    }

    #[DataProvider('readDelays')]
    public function testLookupDoesNotReturnATokenExpiredDuringItsRead(
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
        $subject = Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
        $credential = $tokens->issue($subject, $purpose, ttlSeconds: 30);
        $driver = $database->getDriver(DatabaseInterface::WRITE);
        self::assertInstanceOf(LoggerAwareInterface::class, $driver);
        $delayOnRead = new class($clock, $delay) extends AbstractLogger {
            public bool $advanced = false;

            public function __construct(private FrozenClock $clock, private int $delay) {}

            public function log($level, string|\Stringable $message, array $context = []): void
            {
                if (!$this->advanced && str_starts_with((string) $message, 'SELECT')) {
                    $this->advanced = true;
                    $this->clock->advance(sprintf('+%d seconds', $this->delay));
                }
            }
        };
        $driver->setLogger($delayOnRead);

        $record = $tokens->find($credential, $purpose);

        self::assertTrue($delayOnRead->advanced, 'The lookup must cross the delayed read boundary.');
        self::assertSame($accepted, $record !== null);

        if ($accepted) {
            self::assertNotNull($record);
            self::assertTrue($subject->equals($record->subjectId));
            self::assertNull($record->usedAt);
            self::assertNotNull($tokens->find($credential, $purpose));
            self::assertNotNull($tokens->consume($credential, $purpose));
            self::assertNull($tokens->find($credential, $purpose));
        } else {
            self::assertNull($tokens->consume($credential, $purpose));
        }
    }
}
