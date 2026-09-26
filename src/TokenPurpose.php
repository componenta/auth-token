<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

final readonly class TokenPurpose implements \Stringable
{
    public function __construct(public string $value)
    {
        if (preg_match('/\A[a-z][a-z0-9._-]{0,63}\z/D', $this->value) !== 1) {
            throw new \InvalidArgumentException(
                'One-time token purpose is invalid.',
            );
        }
    }

    #[\Override]
    public function __toString(): string
    {
        return $this->value;
    }
}
