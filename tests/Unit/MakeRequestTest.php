<?php

declare(strict_types=1);

namespace MarjovanLier\EcoFlow\Tests\Unit;

use JsonException;
use MarjovanLier\EcoFlow\EcoFlow;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Contracts\HttpClient\Exception\ClientExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\DecodingExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\RedirectionExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\ServerExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Throwable;

final class MakeRequestTest extends TestCase
{
    use SignedRequestAssertions;

    private const URL = 'https://api.test/path';

    private const PARAMS = ['sn' => 'SN1', 'params' => ['a' => 1]];


    /**
     * @return iterable<string, array{string, array<string, array<string, int|string>|string>, string, string}>
     */
    public static function provideMethodsAndParams(): iterable
    {
        yield 'GET with params sends them as query string' => [
            'GET',
            self::PARAMS,
            self::URL . '?sn=SN1&params[a]=1',
            '',
        ];

        yield 'GET without params sends no query string' => ['GET', [], self::URL, ''];

        yield 'POST with params sends a JSON body' => ['POST', self::PARAMS, self::URL, '{"sn":"SN1","params":{"a":1}}'];

        yield 'PUT with params sends a JSON body' => ['PUT', self::PARAMS, self::URL, '{"sn":"SN1","params":{"a":1}}'];

        yield 'PATCH with params sends a JSON body' => ['PATCH', self::PARAMS, self::URL, '{"sn":"SN1","params":{"a":1}}'];

        yield 'PUT without params sends no body' => ['PUT', [], self::URL, ''];

        yield 'DELETE ignores params' => ['DELETE', self::PARAMS, self::URL, ''];
    }


    /**
     * @param array<string, array<string, int|string>|string> $params
     */
    #[DataProvider('provideMethodsAndParams')]
    public function testMakeRequestPlacesParamsByMethod(
        string $method,
        array $params,
        string $expectedUrl,
        string $expectedBody,
    ): void {
        $mockResponse = new MockResponse('{"code":"0","data":[],"eagleEyeTraceId":"e","tid":"t"}');
        $ecoFlow = new EcoFlow('ak', 'sk', new MockHttpClient($mockResponse));

        $result = $ecoFlow->makeRequest(self::URL, $method, ['X-Custom' => 'value'], $params);

        self::assertSame(['code' => '0', 'data' => [], 'eagleEyeTraceId' => 'e', 'tid' => 't'], $result);
        self::assertSame($method, $mockResponse->getRequestMethod());
        self::assertSame($expectedUrl, $mockResponse->getRequestUrl());
        self::assertSame($expectedBody, $mockResponse->getRequestOptions()['body'] ?? '');
        self::assertSame('value', self::header($mockResponse, 'x-custom'));
    }


    public function testMakeRequestReturnsTheDecodedJsonBody(): void
    {
        $body = '{"code":"0","message":"Success","data":[{"sn":"SN1","online":true}],"eagleEyeTraceId":"e","tid":"t"}';
        $ecoFlow = new EcoFlow('ak', 'sk', new MockHttpClient(new MockResponse($body)));

        self::assertSame(
            [
                'code' => '0',
                'message' => 'Success',
                'data' => [['sn' => 'SN1', 'online' => true]],
                'eagleEyeTraceId' => 'e',
                'tid' => 't',
            ],
            $ecoFlow->makeRequest(self::URL, 'GET', []),
        );
    }


    public function testMakeRequestRejectsParamsThatAreNotValidUtf8BeforeSending(): void
    {
        $mockHttpClient = new MockHttpClient(new MockResponse('{}'));
        $ecoFlow = new EcoFlow('ak', 'sk', $mockHttpClient);

        try {
            $ecoFlow->makeRequest(self::URL, 'PUT', [], ['sn' => "\xB1\x31"]);
            self::fail('Expected a JsonException.');
        } catch (JsonException) {
            self::assertSame(0, $mockHttpClient->getRequestsCount());
        }
    }


    /**
     * @return iterable<string, array{MockResponse, string, class-string<Throwable>}>
     */
    public static function provideFailedResponses(): iterable
    {
        yield 'HTTP 401' => [new MockResponse('{}', ['http_code' => 401]), 'GET', ClientExceptionInterface::class];
        yield 'HTTP 404' => [new MockResponse('{}', ['http_code' => 404]), 'GET', ClientExceptionInterface::class];
        yield 'HTTP 500' => [new MockResponse('{}', ['http_code' => 500]), 'GET', ServerExceptionInterface::class];
        yield 'HTTP 503' => [new MockResponse('{}', ['http_code' => 503]), 'GET', ServerExceptionInterface::class];
        yield 'HTTP 302' => [new MockResponse('{}', ['http_code' => 302]), 'GET', RedirectionExceptionInterface::class];
        yield 'body is not JSON' => [new MockResponse('<html>'), 'GET', DecodingExceptionInterface::class];
        yield 'body is a JSON string' => [new MockResponse('"ok"'), 'GET', DecodingExceptionInterface::class];
        yield 'body is empty' => [new MockResponse(''), 'GET', DecodingExceptionInterface::class];
        yield 'network failure' => [new MockResponse('', ['error' => 'down']), 'GET', TransportExceptionInterface::class];
        yield 'lowercase method' => [new MockResponse('{}'), 'get', TransportExceptionInterface::class];
    }


    /**
     * @param class-string<Throwable> $expectedException
     */
    #[DataProvider('provideFailedResponses')]
    public function testMakeRequestThrowsOnFailedResponse(
        MockResponse $mockResponse,
        string $method,
        string $expectedException,
    ): void {
        $ecoFlow = new EcoFlow('ak', 'sk', new MockHttpClient($mockResponse));

        $this->expectException($expectedException);

        $ecoFlow->makeRequest(self::URL, $method, []);
    }


    public function testMakeRequestWithoutInjectedClientUsesTheDefaultClient(): void
    {
        $ecoFlow = new EcoFlow('ak', 'sk');

        // Port 1 on the loopback interface refuses connections, so the default client fails without leaving the host.
        $this->expectException(TransportExceptionInterface::class);

        $ecoFlow->makeRequest('http://127.0.0.1:1/', 'GET', []);
    }
}
