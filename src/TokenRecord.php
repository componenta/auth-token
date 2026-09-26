<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

use Componenta\Identity\UuidInterface;
use DateTimeImmutable;

final readonly class TokenRecord
{
    public function __construct(
        public UuidInterface $subjectId,
        public TokenPurpose $purpose,
        public DateTimeImmutable $createdAt,
        public DateTimeImmutable $expiresAt,
        public ?DateTimeImmutable $usedAt = null,
        public ?string $binding = null,
    ) {
        if ($this->expiresAt <= $this->createdAt) {
            throw new \InvalidArgumentException(
                'One-time token expiry must follow creation.',
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
                'One-time token binding is invalid.',
            );
        }

        if ($this->usedAt !== null && $this->usedAt < $this->createdAt) {
            throw new \InvalidArgumentException(
                'One-time token use cannot precede creation.',
            );
        }
    }
}
