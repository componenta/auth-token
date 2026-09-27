<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

use Componenta\Identity\UuidInterface;

interface TokenManagerInterface
{
    public function issue(
        UuidInterface $subjectId,
        TokenPurpose $purpose,
        int $ttlSeconds = 300,
        ?string $binding = null,
    ): TokenCredential;

    /** Reads a matching, unused, unexpired token without consuming it. */
    public function find(
        #[\SensitiveParameter]
        TokenCredential $credential,
        TokenPurpose $purpose,
        ?string $binding = null,
    ): ?TokenRecord;

    /**
     * Atomically claims a matching, unused, unexpired token. At most one caller
     * succeeds; a replay or competing claim returns null.
     */
    public function consume(
        #[\SensitiveParameter]
        TokenCredential $credential,
        TokenPurpose $purpose,
        ?string $binding = null,
    ): ?TokenRecord;

    public function cleanup(int $limit = 1000): int;
}
