<?php

declare(strict_types=1);

namespace Componenta\Auth\Token;

final readonly class TokenRequestProcessor
{
    public function __construct(
        private TokenIdentityProviderInterface $identities,
        private TokenManagerInterface $tokens,
        private TokenSenderInterface $sender,
        private TokenPurpose $purpose,
        private int $ttlSeconds = 300,
    ) {}

    public function process(TokenRequest $request): void
    {
        if ($request->purpose->value !== $this->purpose->value) {
            throw new \InvalidArgumentException(
                'One-time token request was routed to the wrong processor.',
            );
        }

        $identity = $this->identities->findByIdentity($request->identity);

        if ($identity === null) {
            return;
        }

        $credential = $this->tokens->issue(
            $identity->uuid,
            $this->purpose,
            $this->ttlSeconds,
            $request->binding,
        );

        $this->sender->send(
            $request->identity,
            $credential,
            $this->purpose,
            $request->context,
        );
    }
}
