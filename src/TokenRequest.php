<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

final readonly class TokenRequest
{
    /** @var array<string, string> */
    public array $context;

    /**
     * @param array<string, string> $context
     */
    public function __construct(
        public string $identity,
        public TokenPurpose $purpose,
        array $context = [],
        public ?string $binding = null,
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

        if (
            $this->binding !== null
            && (
                $this->binding === ''
                || strlen($this->binding) > 256
                || preg_match('/[\x00-\x1F\x7F]/', $this->binding) === 1
            )
        ) {
            throw new \InvalidArgumentException(
                'One-time token request binding is invalid.',
            );
        }

        $snapshot = [];

        foreach ($context as $key => $value) {
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

            // Copy each value so caller-owned PHP references cannot change
            // the validated request while it is queued for delivery.
            $snapshot[$key] = $value;
        }

        $this->context = $snapshot;
    }
}
