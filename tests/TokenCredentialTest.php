<?php

declare(strict_types=1);

namespace Componenta\Auth\Token\Tests;

use Componenta\Auth\Token\TokenCredential;
use PHPUnit\Framework\TestCase;

final class TokenCredentialTest extends TestCase
{
    public function testCredentialIs256BitOpaqueSecret(): void
    {
        $credential = TokenCredential::generate();

        self::assertSame(43, strlen($credential->toString()));
        self::assertMatchesRegularExpression(
            '/\A[A-Za-z0-9_-]{43}\z/D',
            $credential->toString(),
        );
        self::assertStringNotContainsString(
            $credential->toString(),
            json_encode($credential->__debugInfo(), JSON_THROW_ON_ERROR),
        );
    }
}
