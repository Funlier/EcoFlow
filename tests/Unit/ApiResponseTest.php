<?php

declare(strict_types=1);

namespace MarjovanLier\EcoFlow\Tests\Unit;

use Closure;
use MarjovanLier\EcoFlow\EcoFlow;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

final class ApiResponseTest extends TestCase
{
    use SignedRequestAssertions;


    /**
     * @return iterable<string, array{Closure(EcoFlow): array<string, bool|float|int|string|array<int|string, bool|float|int|string|array<int|string, bool|float|int|string|array<int|string, bool|float|int|string>>>>, string, string}>
     */
    public static function provideQuotaReadErrors(): iterable
    {
        $reads = [
            'getAllQuotaInfo' => [
                static fn(EcoFlow $ecoFlow): array => $ecoFlow->getAllQuotaInfo('SN1'),
                'Error getting all quota information: ',
            ],
            'getParams' => [
                static fn(EcoFlow $ecoFlow): array => $ecoFlow->getParams('SN1', ['quotas' => ['q']]),
                'Error getting quota information: ',
            ],
        ];

        foreach ($reads as $name => [$call, $prefix]) {
            yield $name . ' API message' => [
                $call,
                '{"code":"8513","message":"accessKey is invalid","eagleEyeTraceId":"","tid":""}',
                $prefix . 'accessKey is invalid',
            ];
            yield $name . ' no message falls back to the response' => [$call, '{"code":"1006"}', $prefix . '{"code":"1006"}'];
            yield $name . ' no code' => [$call, '{"message":"device offline"}', $prefix . 'device offline'];
            yield $name . ' empty response' => [$call, '{}', $prefix . '[]'];
        }
    }


    /**
     * @param Closure(EcoFlow): array<string, bool|float|int|string|array<int|string, bool|float|int|string|array<int|string, bool|float|int|string|array<int|string, bool|float|int|string>>>> $call
     */
    #[DataProvider('provideQuotaReadErrors')]
    public function testQuotaReadsThrowOnEveryNonSuccessResponse(Closure $call, string $body, string $expected): void
    {
        $ecoFlow = new EcoFlow('ak', 'sk', new MockHttpClient(new MockResponse($body)));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/^' . preg_quote($expected, '/') . '$/');

        $call($ecoFlow);
    }


    /**
     * @return iterable<string, array{Closure(EcoFlow): string, string, string}>
     */
    public static function provideStringOutcomes(): iterable
    {
        $setParams = static fn(EcoFlow $ecoFlow): string => $ecoFlow->setParams('SN1', 'CMD', ['a' => 1]);
        $setParamsRaw = static fn(EcoFlow $ecoFlow): string => $ecoFlow->setParamsRaw(['sn' => 'SN1']);

        foreach (['setParams' => $setParams, 'setParamsRaw' => $setParamsRaw] as $name => $call) {
            yield $name . ' success ignores the message' => [
                $call,
                '{"code":"0","message":"Success"}',
                'Supply priority set successfully.',
            ];
            yield $name . ' error returns the API message' => [
                $call,
                '{"code":"1006","message":"device offline"}',
                'Error setting supply priority: device offline',
            ];
            yield $name . ' non-zero code without message' => [$call, '{"code":"1"}', 'Something went wrong'];
            yield $name . ' empty response' => [$call, '{}', 'Something went wrong'];
        }
    }


    /**
     * @param Closure(EcoFlow): string $call
     */
    #[DataProvider('provideStringOutcomes')]
    public function testStringResultMethodsMapEachResponseOutcome(Closure $call, string $body, string $expected): void
    {
        $ecoFlow = new EcoFlow('ak', 'sk', new MockHttpClient(new MockResponse($body)));

        self::assertSame($expected, $call($ecoFlow));
    }


    /**
     * @return iterable<string, array{Closure(EcoFlow): array<string, array<int|string, int|string|array<string, int|string>>|string>, string, string}>
     */
    public static function provideAccountEndpoints(): iterable
    {
        $success = '{"code":"0","message":"Success","data":[{"sn":"SN1","online":1}],"eagleEyeTraceId":"e","tid":"t"}';
        $failure = '{"code":"8513","message":"accessKey is invalid","eagleEyeTraceId":"","tid":""}';
        $getDevices = static fn(EcoFlow $ecoFlow): array => $ecoFlow->getDevices();
        $getAppCertification = static fn(EcoFlow $ecoFlow): array => $ecoFlow->getAppCertification();

        yield 'getDevices success' => [$getDevices, '/device/list', $success];
        yield 'getDevices error is returned, not thrown' => [$getDevices, '/device/list', $failure];
        yield 'getAppCertification success' => [$getAppCertification, '/certification', $success];
        yield 'getAppCertification error is returned, not thrown' => [$getAppCertification, '/certification', $failure];
    }


    /**
     * @param Closure(EcoFlow): array<string, array<int|string, int|string|array<string, int|string>>|string> $call
     */
    #[DataProvider('provideAccountEndpoints')]
    public function testAccountEndpointsReturnTheDecodedResponse(Closure $call, string $path, string $body): void
    {
        $mockResponse = new MockResponse($body);
        $ecoFlow = new EcoFlow('ak', 'sk', new MockHttpClient($mockResponse));

        self::assertSame(json_decode($body, true, 512, JSON_THROW_ON_ERROR), $call($ecoFlow));
        self::assertSame('GET', $mockResponse->getRequestMethod());
        self::assertSame(self::BASE_URL . $path, $mockResponse->getRequestUrl());
        self::assertSame('application/json', self::header($mockResponse, 'content-type'));
        self::assertSignedRequest($ecoFlow, $mockResponse, []);
    }
}
