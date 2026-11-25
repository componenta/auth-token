<?php

declare(strict_types=1);

namespace Componenta\Auth\Token\Tests;

use Componenta\Auth\Token\TokenPurpose;
use Componenta\Auth\Token\TokenRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class TokenRequestTest extends TestCase
{
    /** @return iterable<string, array{int}> */
    public static function numericContextKeys(): iterable
    {
        yield 'zero' => [0];
        yield 'numeric key' => [42];
    }

    #[DataProvider('numericContextKeys')]
    public function testNumericContextKeysSurviveRequestAndJsonRoundTrip(int $key): void
    {
        $context = [$key => 'delivery-value'];
        $request = new TokenRequest(
            'user@example.test',
            new TokenPurpose('magic_link'),
            $context,
        );

        self::assertSame($context, $request->context);
        $decoded = json_decode(json_encode($request, JSON_THROW_ON_ERROR), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame($context, $decoded['context']);
    }

    public function testRequestOwnsItsValidatedContextSnapshot(): void
    {
        $binding = 'browser-transaction';
        $context = ['binding' => &$binding, 'template' => 'login'];
        $request = new TokenRequest(
            'user@example.test',
            new TokenPurpose('magic_link'),
            $context,
            $binding,
        );

        $binding = "changed\ncontext";
        $context['template'] = 'password_reset';

        self::assertSame(
            ['binding' => 'browser-transaction', 'template' => 'login'],
            $request->context,
        );
        self::assertSame('browser-transaction', $request->binding);

        $deliveryContext = $request->context;
        $deliveryContext['binding'] = 'another-transaction';

        self::assertSame('browser-transaction', $request->context['binding']);
    }
}
