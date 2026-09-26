<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

final readonly class TokenRequest
{
    /**
     * @param array<string, string> $context
     */
    public function __construct(
        public string $identity,
        public TokenPurpose $purpose,
        public array $context = [],
    ) {
        if (
            $this->identity === ''
            || strlen($this->identity) > 320
            || trim($this->identity) !== $this->identity
            || preg_match('/[\x00-\x1F\x7F]/', $this->identity) === 1
        ) {
            throw new \InvalidArgumentException(
                'One-time token request identity is invalid.',
            );
        }

        foreach ($this->context as $key => $value) {
            if (
                $key === ''
                || strlen($key) > 128
                || preg_match('/\A[A-Za-z0-9][A-Za-z0-9._-]*\z/D', $key) !== 1
                || strlen($value) > 4096
                || preg_match('/[\x00-\x1F\x7F]/', $value) === 1
            ) {
                throw new \InvalidArgumentException(
                    'One-time token request context is invalid.',
                );
            }
        }
    }
}
