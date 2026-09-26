<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

final readonly class TokenCredential implements \JsonSerializable
{
    private const int RAW_BYTES = 32;
    private const int WIRE_LENGTH = 43;

    private function __construct(
        #[\SensitiveParameter]
        private string $value,
    ) {
        if (
            strlen($this->value) !== self::WIRE_LENGTH
            || preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $this->value) !== 1
        ) {
            throw new \InvalidArgumentException(
                'One-time token credential is invalid.',
            );
        }
    }

    public static function generate(): self
    {
        return self::fromBytes(random_bytes(self::RAW_BYTES));
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

        return new self(rtrim(strtr(base64_encode($bytes), '+/', '-_'), '='));
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
