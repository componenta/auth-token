<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

use Componenta\Stdlib\RandomToken;

final readonly class TokenCredential implements \JsonSerializable
{
    private const int RAW_BYTES = 32;

    private function __construct(
        #[\SensitiveParameter]
        private string $value,
    ) {
        if (
            !RandomToken::matchesBase64Url($this->value, self::RAW_BYTES)
        ) {
            throw new \InvalidArgumentException(
                'One-time token credential is invalid.',
            );
        }
    }

    public static function generate(): self
    {
        return new self(RandomToken::generateBase64Url(self::RAW_BYTES));
    }

    public static function fromString(
        #[\SensitiveParameter]
        string $value,
    ): self {
        return new self($value);
    }

    public static function fromBytes(
        #[\SensitiveParameter]
        string $bytes,
    ): self {
        if (strlen($bytes) !== self::RAW_BYTES) {
            throw new \InvalidArgumentException(
                'One-time token source must contain exactly 32 bytes.',
            );
        }

        return new self(RandomToken::encodeBase64Url($bytes));
    }


    public function toString(): string
    {
        return $this->value;
    }

    /** @return array{credential: string} */
    public function __debugInfo(): array
    {
        return ['credential' => '[REDACTED]'];
    }

    /** @return array{credential: string} */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }
}
