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
    ) {
        if ($this->expiresAt <= $this->createdAt) {
            throw new \InvalidArgumentException(
                'One-time token expiry must follow creation.',
            );
        }

        if ($this->usedAt !== null && $this->usedAt < $this->createdAt) {
            throw new \InvalidArgumentException(
                'One-time token use cannot precede creation.',
            );
        }
    }
}
