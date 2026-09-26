<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

use Componenta\Identity\IdentityInterface;

interface TokenIdentityProviderInterface
{
    public function findByIdentity(string $identity): ?IdentityInterface;
}
