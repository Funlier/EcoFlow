<?php

declare(strict_types=1);

namespace MarjovanLier\EcoFlow\Tests\Unit;

use DateTimeImmutable;
use MarjovanLier\EcoFlow\EcoFlow;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

final class DeviceApiTest extends TestCase
{
    use SignedRequestAssertions;


    public function testGetAllQuotaInfoReturnsDataSortedByKey(): void
    {
        $mockResponse = new MockResponse('{"code":"0","message":"Success","data":{"b":1,"A":{"x":2},"20_1.soc":"3"}}');
        $ecoFlow = new EcoFlow('ak', 'sk', new MockHttpClient($mockResponse));

        self::assertSame(['20_1.soc' => '3', 'A' => ['x' => 2], 'b' => 1], $ecoFlow->getAllQuotaInfo('SN1'));
        self::assertSame('GET', $mockResponse->getRequestMethod());
        self::assertSame(self::BASE_URL . '/device/quota/all?sn=SN1', $mockResponse->getRequestUrl());
        self::assertArrayNotHasKey('body', $mockResponse->getRequestOptions());
        self::assertSignedRequest($ecoFlow, $mockResponse, ['sn' => 'SN1']);
    }


    public function testGetAllQuotaInfoReturnsEmptyArrayForEmptyData(): void
    {
        $ecoFlow = new EcoFlow('ak', 'sk', new MockHttpClient(new MockResponse('{"code":"0","data":{}}')));

        self::assertSame([], $ecoFlow->getAllQuotaInfo('SN1'));
    }


    public function testRequestTimestampIsTheCurrentTimeInMilliseconds(): void
    {
        $mockResponse = new MockResponse('{"code":"0","data":[]}');
        $ecoFlow = new EcoFlow('ak', 'sk', new MockHttpClient($mockResponse));

        $before = (int) (new DateTimeImmutable())->format('Uv');
        $ecoFlow->getDevices();
        $after = (int) (new DateTimeImmutable())->format('Uv');

        $timestamp = (int) self::header($mockResponse, 'timestamp');
        self::assertGreaterThanOrEqual($before, $timestamp);
        self::assertLessThanOrEqual($after, $timestamp);
    }


    public function testSetParamsSendsSignedPutWithJsonBody(): void
    {
        $mockResponse = new MockResponse('{"code":"0"}');
        $ecoFlow = new EcoFlow('ak', 'sk', new MockHttpClient($mockResponse));
        $sent = ['cmdCode' => 'WN511_SET_PERMANENT_WATTS_PACK', 'params' => ['permanentWatts' => 200], 'sn' => 'SN1'];

        $ecoFlow->setParams('SN1', 'WN511_SET_PERMANENT_WATTS_PACK', ['permanentWatts' => 200]);

        self::assertJsonRequest($mockResponse, 'PUT', '/device/quota', json_encode($sent, JSON_THROW_ON_ERROR));
        self::assertSignedRequest($ecoFlow, $mockResponse, $sent);
    }


    public function testSetParamsWithoutParamsSendsEmptyParams(): void
    {
        $mockResponse = new MockResponse('{"code":"0"}');
        $ecoFlow = new EcoFlow('ak', 'sk', new MockHttpClient($mockResponse));

        $ecoFlow->setParams('SN1', 'CMD');

        self::assertJsonRequest($mockResponse, 'PUT', '/device/quota', '{"cmdCode":"CMD","params":[],"sn":"SN1"}');
        self::assertSignedRequest($ecoFlow, $mockResponse, ['cmdCode' => 'CMD', 'params' => [], 'sn' => 'SN1']);
    }


    public function testSetParamsRawSendsTheGivenDataAsIs(): void
    {
        $mockResponse = new MockResponse('{"code":"0"}');
        $ecoFlow = new EcoFlow('ak', 'sk', new MockHttpClient($mockResponse));
        $sent = ['sn' => 'SN1', 'cmdCode' => 'CMD', 'params' => ['ids' => [1, 2], 'cfg' => ['on' => 1]]];

        $ecoFlow->setParamsRaw($sent);

        self::assertJsonRequest($mockResponse, 'PUT', '/device/quota', json_encode($sent, JSON_THROW_ON_ERROR));
        self::assertSignedRequest($ecoFlow, $mockResponse, $sent);
    }


    public function testSetParamsRawWithoutDataSendsNoBody(): void
    {
        $mockResponse = new MockResponse('{"code":"0"}');
        $ecoFlow = new EcoFlow('ak', 'sk', new MockHttpClient($mockResponse));

        $ecoFlow->setParamsRaw();

        self::assertSame('PUT', $mockResponse->getRequestMethod());
        self::assertArrayNotHasKey('body', $mockResponse->getRequestOptions());
        self::assertSignedRequest($ecoFlow, $mockResponse, []);
    }


    public function testGetParamsSendsSignedPostWithQuotaListAndReturnsTheValues(): void
    {
        $mockResponse = new MockResponse('{"code":"0","message":"Success","data":{"20_1.acSetWatts":8000,"20_1.acOffFlag":0}}');
        $ecoFlow = new EcoFlow('ak', 'sk', new MockHttpClient($mockResponse));
        $sent = ['params' => ['quotas' => ['20_1.acOffFlag', '20_1.acSetWatts']], 'sn' => 'SN1'];

        self::assertSame(
            ['20_1.acSetWatts' => 8000, '20_1.acOffFlag' => 0],
            $ecoFlow->getParams('SN1', ['quotas' => ['20_1.acOffFlag', '20_1.acSetWatts']]),
        );
        self::assertJsonRequest($mockResponse, 'POST', '/device/quota', json_encode($sent, JSON_THROW_ON_ERROR));
        self::assertSame('application/json', self::header($mockResponse, 'accept'));
        self::assertSignedRequest($ecoFlow, $mockResponse, $sent);
    }


    public function testGetParamsWithoutParamsSendsEmptyParams(): void
    {
        $mockResponse = new MockResponse('{"code":"0","data":{}}');
        $ecoFlow = new EcoFlow('ak', 'sk', new MockHttpClient($mockResponse));

        self::assertSame([], $ecoFlow->getParams('SN1'));

        self::assertJsonRequest($mockResponse, 'POST', '/device/quota', '{"params":[],"sn":"SN1"}');
        self::assertSignedRequest($ecoFlow, $mockResponse, ['params' => [], 'sn' => 'SN1']);
    }
}
