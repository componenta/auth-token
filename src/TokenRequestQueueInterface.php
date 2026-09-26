<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

interface TokenRequestQueueInterface
{
    public function enqueue(TokenRequest $request): void;
}
