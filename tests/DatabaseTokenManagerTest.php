<?php

declare(strict_types=1);

namespace Componenta\Auth\Token\Tests;

use Componenta\Auth\Token\DatabaseTokenManager;
use Componenta\Auth\Token\TokenPurpose;
use Componenta\Auth\Token\Tests\Support\SqliteDatabaseFixture;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\Uuid;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DatabaseTokenManagerTest extends TestCase
{
    /** @return iterable<string, array{int, string}> */
    public static function clockCorrections(): iterable
    {
        yield 'clock moved backwards' => [-1, '2030-01-01 00:00:00.500000'];
        yield 'clock advanced normally' => [1, '2030-01-01 00:00:01.500000'];
    }

    #[DataProvider('clockCorrections')]
    public function testConsumptionPreservesTheTokenTimelineAcrossClockCorrections(
        int $clockOffset,
        string $expectedUsedAt,
    ): void {
        self::requireSqlite();
        $clock = new FrozenClock('2030-01-01T00:00:00.500000+00:00', 'UTC');
        $manager = new DatabaseTokenManager(SqliteDatabaseFixture::create(), $clock);
        $subject = Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
        $purpose = new TokenPurpose('magic_link');
        $credential = $manager->issue($subject, $purpose, binding: 'browser');
        $clock->advance(sprintf('%+d seconds', $clockOffset));
        self::assertNotNull($manager->find($credential, $purpose, 'browser'));

        $record = $manager->consume($credential, $purpose, 'browser');

        self::assertNotNull($record);
        self::assertTrue($subject->equals($record->subjectId));
        self::assertSame('browser', $record->binding);
        self::assertSame('2030-01-01 00:00:00.500000', $record->createdAt->format('Y-m-d H:i:s.u'));
        self::assertSame('2030-01-01 00:05:00.500000', $record->expiresAt->format('Y-m-d H:i:s.u'));
        self::assertSame($expectedUsedAt, $record->usedAt?->format('Y-m-d H:i:s.u'));
        self::assertNull($manager->find($credential, $purpose, 'browser'));
        self::assertNull($manager->consume($credential, $purpose, 'browser'));
        $clock->freeze('2030-01-01T00:00:02+00:00');
        self::assertNull($manager->consume($credential, $purpose, 'browser'));
    }

    public function testClockCorrectionDoesNotExtendAnUnusedTokensOriginalExpiry(): void
    {
        self::requireSqlite();
        $clock = new FrozenClock('2030-01-01T00:00:00.500000+00:00', 'UTC');
        $manager = new DatabaseTokenManager(SqliteDatabaseFixture::create(), $clock);
        $purpose = new TokenPurpose('magic_link');
        $credential = $manager->issue(
            Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc'),
            $purpose,
        );
        $clock->advance('-1 second');
        self::assertNotNull($manager->find($credential, $purpose));
        $clock->freeze('2030-01-01T00:05:00.500000+00:00');

        self::assertNull($manager->find($credential, $purpose));
        self::assertNull($manager->consume($credential, $purpose));
    }

    public function testPurposesCoexistAndReplacementInvalidatesOnlySamePurpose(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        $manager = new DatabaseTokenManager(
            $database,
            new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC'),
        );
        $subject = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
        $magic = new TokenPurpose('magic_link');
        $reset = new TokenPurpose('password_reset');
        $firstMagic = $manager->issue($subject, $magic);
        $resetToken = $manager->issue($subject, $reset);
        $secondMagic = $manager->issue($subject, $magic);

        self::assertNull($manager->find($firstMagic, $magic));
        self::assertNotNull($manager->find($secondMagic, $magic));
        self::assertNotNull($manager->find($resetToken, $reset));
        self::assertNull($manager->find($secondMagic, $reset));
        self::assertSame(
            2,
            $database->select()->from('auth_one_time_tokens')->count(),
        );
    }

    public function testBoundTokenCannotBeUsedWithAnotherBinding(): void
    {
        self::requireSqlite();
        $manager = new DatabaseTokenManager(
            SqliteDatabaseFixture::create(),
            new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC'),
        );
        $purpose = new TokenPurpose('magic_link');
        $credential = $manager->issue(
            Uuid::fromString(
                '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
            ),
            $purpose,
            binding: 'binding-a',
        );

        self::assertNull($manager->find(
            $credential,
            $purpose,
            'binding-b',
        ));
        self::assertNull($manager->consume(
            $credential,
            $purpose,
            'binding-b',
        ));
        self::assertNotNull($manager->consume(
            $credential,
            $purpose,
            'binding-a',
        ));
    }

    public function testConsumeIsSingleUse(): void
    {
        self::requireSqlite();
        $manager = new DatabaseTokenManager(
            SqliteDatabaseFixture::create(),
            new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC'),
        );
        $purpose = new TokenPurpose('magic_link');
        $credential = $manager->issue(
            Uuid::fromString(
                '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
            ),
            $purpose,
        );

        self::assertNotNull($manager->consume($credential, $purpose));
        self::assertNull($manager->consume($credential, $purpose));
    }

    public function testDatabaseDoesNotContainRawCredential(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        $manager = new DatabaseTokenManager(
            $database,
            new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC'),
        );
        $purpose = new TokenPurpose('password_reset');
        $credential = $manager->issue(
            Uuid::fromString(
                '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
            ),
            $purpose,
        );
        $row = $database->select()
            ->from('auth_one_time_tokens')
            ->run()
            ->fetch();

        self::assertIsArray($row);
        self::assertNotSame(
            $credential->toString(),
            $row['credential_hash'] ?? null,
        );
    }

    private static function requireSqlite(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
    }
}
