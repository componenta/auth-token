<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

interface TokenSenderInterface
{
    /**
     * @param array<array-key, string> $context
     */
    public function send(
        string $destination,
        #[\SensitiveParameter]
        TokenCredential $credential,
        TokenPurpose $purpose,
        array $context = [],
    ): void;
}
