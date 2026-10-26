<?php

declare(strict_types=1);

namespace MarjovanLier\EcoFlow\Tests\Unit;

use MarjovanLier\EcoFlow\EcoFlow;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * Assertions on the request an EcoFlow method sent through a MockHttpClient.
 *
 * @mixin TestCase
 * @psalm-require-extends TestCase
 */
trait SignedRequestAssertions
{
    private const BASE_URL = 'https://api-e.ecoflow.com/iot-open/sign';


    private static function assertJsonRequest(MockResponse $mockResponse, string $method, string $path, string $body): void
    {
        self::assertSame($method, $mockResponse->getRequestMethod());
        self::assertSame(self::BASE_URL . $path, $mockResponse->getRequestUrl());
        self::assertSame($body, $mockResponse->getRequestOptions()['body'] ?? null);
        self::assertSame('application/json;charset=UTF-8', self::header($mockResponse, 'content-type'));
    }


    /**
     * Asserts the auth headers are present and that `sign` is the signature of exactly `$signedData`.
     *
     * @param array<int|string, int|string|array<int|string, int|string|array<int|string, int|string>>> $signedData
     */
    private static function assertSignedRequest(EcoFlow $ecoFlow, MockResponse $mockResponse, array $signedData): void
    {
        $nonce = self::header($mockResponse, 'nonce');
        $timestamp = self::header($mockResponse, 'timestamp');

        self::assertSame('ak', self::header($mockResponse, 'accesskey'));
        self::assertMatchesRegularExpression('/^\d{6}$/', $nonce);
        self::assertMatchesRegularExpression('/^\d{13}$/', $timestamp);
        self::assertLessThanOrEqual(5, abs(intdiv((int) $timestamp, 1000) - time()));
        self::assertSame($ecoFlow->generateSignature($nonce, $timestamp, $signedData), self::header($mockResponse, 'sign'));
    }


    private static function header(MockResponse $mockResponse, string $name): string
    {
        /** @var array<string, list<string>> $headers */
        $headers = $mockResponse->getRequestOptions()['normalized_headers'] ?? [];

        return explode(': ', $headers[$name][0] ?? '', 2)[1] ?? '';
    }
}
