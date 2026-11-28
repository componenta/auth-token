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
        self::assertStringNotContainsString(
            $credential->toString(),
            json_encode($credential, JSON_THROW_ON_ERROR),
        );
        self::assertNotInstanceOf(\Stringable::class, $credential);
    }

    public function testSharedPrimitivePreservesTheDomainWireFormat(): void
    {
        $bytes = str_repeat("\xfb\xff", 16);
        $expected = rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');

        foreach ([
        TokenCredential::class,
        ] as $class) {
            $credential = $class::fromBytes($bytes);
            self::assertSame($expected, $credential->toString());
            self::assertSame($expected, $class::fromString($expected)->toString());
            // These are opaque strings, not decoded identifiers.
            $presented = str_repeat('a', 43);
            self::assertSame($presented, $class::fromString($presented)->toString());
            self::assertMatchesRegularExpression('/\A[A-Za-z0-9_-]{43}\z/D', $class::generate()->toString());
            foreach (['', str_repeat('a', 42), str_repeat('a', 44), str_repeat('a', 42) . '=', str_repeat('a', 42) . "\n"] as $value) {
                try {
                    $class::fromString($value);
                    self::fail('Malformed credential accepted.');
                } catch (\InvalidArgumentException) {
                    self::assertTrue(true);
                }
            }
            foreach (['', str_repeat('x', 31), str_repeat('x', 33)] as $value) {
                try {
                    $class::fromBytes($value);
                    self::fail('Invalid raw byte count accepted.');
                } catch (\InvalidArgumentException) {
                    self::assertTrue(true);
                }
            }
        }
    }

}
