<?php

declare(strict_types=1);

namespace Componenta\Auth\Token\Tests;

use Componenta\Auth\Token\DatabaseTokenManager;
use Componenta\Auth\Token\TokenPurpose;
use Componenta\Auth\Token\Tests\Support\SqliteDatabaseFixture;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\UuidFactory;
use Cycle\Database\Database;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\TestCase;

final class PrimaryReadConsistencyTest extends TestCase
{
    public function testFreshTokenCanBeConsumedBeforeReplication(): void
    {
        [$primary, , $split] = $this->databases();
        $purpose = new TokenPurpose('magic_link');
        $token = $this->manager($primary)->issue((new UuidFactory())->generate(), $purpose, binding: 'browser');
        $manager = $this->manager($split);
        self::assertNotNull($manager->find($token, $purpose, 'browser'));
        self::assertNotNull($manager->consume($token, $purpose, 'browser'));
        self::assertNull($manager->consume($token, $purpose, 'browser'));
    }

    public function testUsedTokenIsNotReportedAsActiveByLaggingReplica(): void
    {
        [$primary, $replica, $split] = $this->databases();
        $purpose = new TokenPurpose('password_reset');
        $writer = $this->manager($primary);
        $token = $writer->issue((new UuidFactory())->generate(), $purpose);
        $this->replicate($primary, $replica);
        self::assertNotNull($writer->consume($token, $purpose));
        self::assertNull($this->manager($split)->find($token, $purpose));
        self::assertNull($this->manager($split)->consume($token, $purpose));
    }

    public function testReplacementIsAuthoritativeBeforeReplication(): void
    {
        [$primary, $replica, $split] = $this->databases();
        $subject = (new UuidFactory())->generate();
        $purpose = new TokenPurpose('magic_link');
        $writer = $this->manager($primary);
        $old = $writer->issue($subject, $purpose);
        $this->replicate($primary, $replica);
        $new = $writer->issue($subject, $purpose);
        $manager = $this->manager($split);
        self::assertNull($manager->find($old, $purpose));
        self::assertNotNull($manager->find($new, $purpose));
        self::assertNotNull($manager->consume($new, $purpose));
    }

    /** @return array{DatabaseInterface, DatabaseInterface, DatabaseInterface} */
    private function databases(): array
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
        $primary = SqliteDatabaseFixture::create();
        $replica = SqliteDatabaseFixture::create();
        return [$primary, $replica, new Database('split', '', $primary->getDriver(DatabaseInterface::WRITE), $replica->getDriver(DatabaseInterface::READ))];
    }

    private function manager(DatabaseInterface $database): DatabaseTokenManager
    {
        return new DatabaseTokenManager($database, new FrozenClock('2030-01-01T00:00:00Z', 'UTC'));
    }

    private function replicate(DatabaseInterface $primary, DatabaseInterface $replica): void
    {
        foreach ($primary->select()->from('auth_one_time_tokens')->run()->fetchAll() as $row) {
            $replica->insert('auth_one_time_tokens')->values($row)->run();
        }
    }
}
