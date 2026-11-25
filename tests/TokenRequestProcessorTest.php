<?php

declare(strict_types=1);

namespace Componenta\Auth\Token\Tests;

use Componenta\Auth\Token\TokenCredential;
use Componenta\Auth\Token\TokenIdentityProviderInterface;
use Componenta\Auth\Token\TokenManagerInterface;
use Componenta\Auth\Token\TokenPurpose;
use Componenta\Auth\Token\TokenRecord;
use Componenta\Auth\Token\TokenRequest;
use Componenta\Auth\Token\TokenRequestProcessor;
use Componenta\Auth\Token\TokenSenderInterface;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class TokenRequestProcessorTest extends TestCase
{
    public function testDeliveryReceivesNumericContextKeysUnchanged(): void
    {
        $identity = new readonly class(Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        )) implements IdentityInterface {
            public function __construct(public UuidInterface $uuid) {}
        };
        $identities = $this->createStub(TokenIdentityProviderInterface::class);
        $identities->method('findByIdentity')->willReturn($identity);
        $credential = TokenCredential::fromBytes(str_repeat('a', 32));
        $tokens = $this->createStub(TokenManagerInterface::class);
        $tokens->method('issue')->willReturn($credential);
        $purpose = new TokenPurpose('magic_link');
        $context = [0 => 'zero', 42 => 'numeric-key'];
        $sender = $this->createMock(TokenSenderInterface::class);
        $sender->expects(self::once())
            ->method('send')
            ->with('user@example.test', $credential, $purpose, $context);

        (new TokenRequestProcessor($identities, $tokens, $sender, $purpose))
            ->process(new TokenRequest('user@example.test', $purpose, $context));
    }

    public function testUnknownIdentityDoesNotIssueOrSend(): void
    {
        $identities = $this->createStub(TokenIdentityProviderInterface::class);
        $identities->method('findByIdentity')->willReturn(null);
        $tokens = $this->createMock(TokenManagerInterface::class);
        $tokens->expects(self::never())->method('issue');
        $sender = $this->createMock(TokenSenderInterface::class);
        $sender->expects(self::never())->method('send');
        $purpose = new TokenPurpose('password_reset');

        (new TokenRequestProcessor(
            $identities,
            $tokens,
            $sender,
            $purpose,
        ))->process(new TokenRequest(
            'unknown@example.com',
            $purpose,
        ));
    }

    public function testProcessorRejectsMisroutedPurposeBeforeLookup(): void
    {
        $identities = $this->createMock(TokenIdentityProviderInterface::class);
        $identities->expects(self::never())->method('findByIdentity');
        $tokens = $this->createMock(TokenManagerInterface::class);
        $tokens->expects(self::never())->method('issue');
        $sender = $this->createMock(TokenSenderInterface::class);
        $sender->expects(self::never())->method('send');

        $processor = new TokenRequestProcessor(
            $identities,
            $tokens,
            $sender,
            new TokenPurpose('magic_link'),
        );

        $this->expectException(\InvalidArgumentException::class);

        $processor->process(new TokenRequest(
            'user@example.com',
            new TokenPurpose('password_reset'),
        ));
    }
}
