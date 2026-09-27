<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use Cycle\Database\DatabaseInterface;
use Cycle\Database\Query\OnConflict;
use DateTimeImmutable;
use DateTimeZone;
use Psr\Clock\ClockInterface;

final readonly class DatabaseTokenManager implements TokenManagerInterface
{
    private const int MAX_TTL = 31_536_000;
    private const int MAX_CLEANUP = 10_000;
    private const string DATE_FORMAT = 'Y-m-d H:i:s.u';

    public function __construct(
        private DatabaseInterface $database,
        private ClockInterface $clock,
        private string $table = 'auth_one_time_tokens',
    ) {
        if (preg_match('/\A[A-Za-z_][A-Za-z0-9_]*\z/D', $this->table) !== 1) {
            throw new \InvalidArgumentException(
                'One-time token table name is invalid.',
            );
        }
    }

    #[\Override]
    public function issue(
        UuidInterface $subjectId,
        TokenPurpose $purpose,
        int $ttlSeconds = 300,
        ?string $binding = null,
    ): TokenCredential {
        if ($ttlSeconds < 1 || $ttlSeconds > self::MAX_TTL) {
            throw new \InvalidArgumentException(
                'One-time token TTL is out of bounds.',
            );
        }

        self::assertBinding($binding);
        $credential = TokenCredential::generate();
        $now = $this->now();

        $this->database->insert($this->table)->values([
            'subject_uuid' => $subjectId->toString(),
            'purpose' => $purpose->value,
            'binding' => $binding,
            'credential_hash' => $this->hash(
                $credential,
                $purpose,
                $binding,
            ),
            'created_at' => $this->format($now),
            'expires_at' => $this->format(
                $now->modify(sprintf('+%d seconds', $ttlSeconds)),
            ),
            'used_at' => null,
        ])->onConflict(
            OnConflict::target('subject_uuid', 'purpose')->doUpdate([
                'binding',
                'credential_hash',
                'created_at',
                'expires_at',
                'used_at',
            ]),
        )->run();

        return $credential;
    }

    #[\Override]
    public function find(
        #[\SensitiveParameter]
        TokenCredential $credential,
        TokenPurpose $purpose,
        ?string $binding = null,
    ): ?TokenRecord {
        self::assertBinding($binding);
        $now = $this->format($this->now());
        $row = $this->database->select()->withDriver(
                $this->database->getDriver(DatabaseInterface::WRITE),
                $this->database->getPrefix(),
            )
            ->from($this->table)
            ->where('purpose', $purpose->value)
            ->where('binding', $binding)
            ->where(
                'credential_hash',
                $this->hash($credential, $purpose, $binding),
            )
            ->where('used_at', null)
            ->where('expires_at', '>', $now)
            ->run()
            ->fetch();

        return is_array($row) ? $this->hydrate($row) : null;
    }

    #[\Override]
    public function consume(
        #[\SensitiveParameter]
        TokenCredential $credential,
        TokenPurpose $purpose,
        ?string $binding = null,
    ): ?TokenRecord {
        self::assertBinding($binding);

        return $this->database->transaction(function () use (
            $credential,
            $purpose,
            $binding,
        ): ?TokenRecord {
            $hash = $this->hash($credential, $purpose, $binding);
            $now = $this->now();
            $formattedNow = $this->format($now);
            $row = $this->database->select()->withDriver(
                $this->database->getDriver(DatabaseInterface::WRITE),
                $this->database->getPrefix(),
            )
                ->from($this->table)
                ->where('purpose', $purpose->value)
                ->where('binding', $binding)
                ->where('credential_hash', $hash)
                ->where('used_at', null)
                ->where('expires_at', '>', $formattedNow)
                ->run()
                ->fetch();

            if (!is_array($row)) {
                return null;
            }

            $affected = $this->database->update($this->table)
                ->where('subject_uuid', self::stringValue($row, 'subject_uuid'))
                ->where('purpose', $purpose->value)
                ->where('binding', $binding)
                ->where('credential_hash', $hash)
                ->where('used_at', null)
                ->where('expires_at', '>', $formattedNow)
                ->values(['used_at' => $formattedNow])
                ->run();

            if ($affected !== 1) {
                return null;
            }

            $row['used_at'] = $formattedNow;

            return $this->hydrate($row);
        });
    }

    #[\Override]
    public function cleanup(int $limit = 1000): int
    {
        if ($limit < 1 || $limit > self::MAX_CLEANUP) {
            throw new \InvalidArgumentException(
                'One-time token cleanup limit is out of bounds.',
            );
        }

        $now = $this->format($this->now());
        $rows = $this->database->select('credential_hash')->withDriver(
                $this->database->getDriver(DatabaseInterface::WRITE),
                $this->database->getPrefix(),
            )
            ->from($this->table)
            ->where(static function (mixed $query) use ($now): void {
                if (!$query instanceof \Cycle\Database\Query\SelectQuery) {
                    throw new \LogicException(
                        'Cycle must provide a SelectQuery.',
                    );
                }

                $query->where('expires_at', '<=', $now)
                    ->orWhere('used_at', '!=', null);
            })
            ->limit($limit)
            ->run()
            ->fetchAll();
        $hashes = [];

        foreach ($rows as $row) {
            if (is_array($row) && is_string($row['credential_hash'] ?? null)) {
                $hashes[] = $row['credential_hash'];
            }
        }

        return $hashes === []
            ? 0
            : $this->database->delete($this->table)
                ->where('credential_hash', 'IN', $hashes)
                ->run();
    }

    private function hash(
        #[\SensitiveParameter]
        TokenCredential $credential,
        TokenPurpose $purpose,
        ?string $binding,
    ): string {
        return hash(
            'sha256',
            "componenta-auth-token-v1\0"
                . $purpose->value
                . "\0"
                . ($binding === null ? '-' : 'b:' . $binding)
                . "\0"
                . $credential->toString(),
        );
    }

    private static function assertBinding(?string $binding): void
    {
        if (
            $binding !== null
            && (
                $binding === ''
                || strlen($binding) > 256
                || preg_match('/[\x00-\x1F\x7F]/', $binding) === 1
            )
        ) {
            throw new \InvalidArgumentException(
                'One-time token binding is invalid.',
            );
        }
    }

    /** @param array<array-key, mixed> $row */
    private function hydrate(array $row): TokenRecord
    {
        $used = $row['used_at'] ?? null;

        return new TokenRecord(
            Uuid::fromString(self::stringValue($row, 'subject_uuid')),
            new TokenPurpose(self::stringValue($row, 'purpose')),
            $this->date(self::stringValue($row, 'created_at')),
            $this->date(self::stringValue($row, 'expires_at')),
            $used === null ? null : $this->date(self::stringValue($row, 'used_at')),
            binding: self::nullableStringValue($row, 'binding'),
        );
    }

    private function now(): DateTimeImmutable
    {
        return $this->clock->now()->setTimezone(new DateTimeZone('UTC'));
    }

    private function format(DateTimeImmutable $value): string
    {
        return $value->setTimezone(new DateTimeZone('UTC'))
            ->format(self::DATE_FORMAT);
    }

    private function date(string $value): DateTimeImmutable
    {
        $timezone = new DateTimeZone('UTC');

        foreach (['!Y-m-d H:i:s.u', '!Y-m-d H:i:s'] as $format) {
            $date = DateTimeImmutable::createFromFormat(
                $format,
                $value,
                $timezone,
            );

            if ($date instanceof DateTimeImmutable) {
                return $date;
            }
        }

        throw new \UnexpectedValueException(
            'Persisted one-time token timestamp is invalid.',
        );
    }

    /** @param array<array-key, mixed> $row */
    private static function nullableStringValue(
        array $row,
        string $key,
    ): ?string {
        return ($row[$key] ?? null) === null
            ? null
            : self::stringValue($row, $key);
    }

    /** @param array<array-key, mixed> $row */
    private static function stringValue(array $row, string $key): string
    {
        $value = $row[$key] ?? null;

        if (!is_string($value) && !is_int($value)) {
            throw new \UnexpectedValueException(sprintf(
                'Database column "%s" must be a string-compatible value.',
                $key,
            ));
        }

        return (string) $value;
    }
}
