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
    ): TokenCredential;

    public function find(
        #[\SensitiveParameter]
        TokenCredential $credential,
        TokenPurpose $purpose,
    ): ?TokenRecord;

    public function consume(
        #[\SensitiveParameter]
        TokenCredential $credential,
        TokenPurpose $purpose,
    ): ?TokenRecord;

    public function cleanup(int $limit = 1000): int;
}
