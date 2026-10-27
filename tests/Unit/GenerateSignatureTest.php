<?php

declare(strict_types=1);

namespace MarjovanLier\EcoFlow\Tests\Unit;

use MarjovanLier\EcoFlow\EcoFlow;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class GenerateSignatureTest extends TestCase
{
    private const NONCE = '345164';

    private const TIMESTAMP = '1671171709428';

    public function testGenerateSignatureProducesExpectedOutput(): void
    {
        $accessKey = 'Fp4SvIprYSDPXtYJidEtUAd1o';
        $secretKey = 'WIbFEKre0s6sLnh4ei7SPUeYnptHG6V';
        $nonce = '345164';
        $timestamp = '1671171709428';
        $data = [
            'params' => [
                'cmdSet' => 11,
                'eps' => 0,
                'id' => 24,
            ],
            'sn' => '123456789',
        ];

        $ecoFlow = new EcoFlow($accessKey, $secretKey);
        $expectedSignature = '07c13b65e037faf3b153d51613638fa80003c4c38d2407379a7f52851af1473e';

        $signature = $ecoFlow->generateSignature($nonce, $timestamp, $data);

        self::assertEquals($expectedSignature, $signature);
    }


    /**
     * Each case pairs input data with the exact key-value string the EcoFlow signing spec
     * (developer docs, "HTTP access steps", steps 1 to 3) says must be signed.
     *
     * @return iterable<string, array{array<int|string, int|string|array<int|string, int|string|array<int|string, int|string>>>, string}>
     */
    public static function provideSignatureBaseStrings(): iterable
    {
        yield 'spec example with list, object and object list' => [
            [
                'name' => 'demo1',
                'ids' => [1, 2, 3],
                'deviceInfo' => ['id' => 1],
                'deviceList' => [['id' => 1], ['id' => 2]],
            ],
            'deviceInfo.id=1&deviceList[0].id=1&deviceList[1].id=2&ids[0]=1&ids[1]=2&ids[2]=3&name=demo1',
        ];

        yield 'quota list as sent by getParams' => [
            [
                'params' => ['quotas' => ['20_1.supplyPriority', '20_1.permanentWatts']],
                'sn' => 'SN1',
            ],
            'params.quotas[0]=20_1.supplyPriority&params.quotas[1]=20_1.permanentWatts&sn=SN1',
        ];

        yield 'keys sorted by ASCII value, uppercase before underscore before lowercase' => [
            ['b' => 1, 'B' => 2, 'a' => 3, '_' => 4],
            'B=2&_=4&a=3&b=1',
        ];

        yield 'list indexes sorted by ASCII value, so 10 comes before 2' => [
            ['ids' => range(0, 10)],
            'ids[0]=0&ids[10]=10&ids[1]=1&ids[2]=2&ids[3]=3&ids[4]=4&ids[5]=5&ids[6]=6&ids[7]=7&ids[8]=8&ids[9]=9',
        ];

        yield 'values are signed raw, not URL-encoded' => [
            ['sn' => 'a b:c/d&e=f+g'],
            'sn=a b:c/d&e=f+g',
        ];

        yield 'empty nested params contribute nothing' => [
            ['cmdCode' => 'CMD', 'params' => [], 'sn' => 'SN1'],
            'cmdCode=CMD&sn=SN1',
        ];
    }


    /**
     * @param array<int|string, int|string|array<int|string, int|string|array<int|string, int|string>>> $data
     */
    #[DataProvider('provideSignatureBaseStrings')]
    public function testGenerateSignatureSignsSpecBaseString(array $data, string $expectedBase): void
    {
        $ecoFlow = new EcoFlow('ak', 'sk');
        $expected = hash_hmac(
            'sha256',
            $expectedBase . '&accessKey=ak&nonce=' . self::NONCE . '&timestamp=' . self::TIMESTAMP,
            'sk',
        );

        self::assertSame($expected, $ecoFlow->generateSignature(self::NONCE, self::TIMESTAMP, $data));
    }


    public function testGenerateSignatureWithoutDataSignsOnlyCredentials(): void
    {
        $ecoFlow = new EcoFlow('ak', 'sk');
        $expected = hash_hmac('sha256', 'accessKey=ak&nonce=' . self::NONCE . '&timestamp=' . self::TIMESTAMP, 'sk');

        self::assertSame($expected, $ecoFlow->generateSignature(self::NONCE, self::TIMESTAMP, []));
    }


    public function testGenerateSignatureIgnoresInputKeyOrder(): void
    {
        $ecoFlow = new EcoFlow('ak', 'sk');

        self::assertSame(
            $ecoFlow->generateSignature(self::NONCE, self::TIMESTAMP, ['sn' => 'SN1', 'cmdCode' => 'CMD']),
            $ecoFlow->generateSignature(self::NONCE, self::TIMESTAMP, ['cmdCode' => 'CMD', 'sn' => 'SN1']),
        );
    }


    /**
     * @return iterable<string, array{string, string, string, string}>
     */
    public static function provideChangedSignatureInputs(): iterable
    {
        yield 'other access key' => ['other', 'sk', self::NONCE, self::TIMESTAMP];
        yield 'other secret key' => ['ak', 'other', self::NONCE, self::TIMESTAMP];
        yield 'other nonce' => ['ak', 'sk', '111111', self::TIMESTAMP];
        yield 'other timestamp' => ['ak', 'sk', self::NONCE, '1671171709429'];
    }


    #[DataProvider('provideChangedSignatureInputs')]
    public function testGenerateSignatureChangesWithEachCredentialInput(
        string $accessKey,
        string $secretKey,
        string $nonce,
        string $timestamp,
    ): void {
        $data = ['sn' => 'SN1'];
        $baseline = (new EcoFlow('ak', 'sk'))->generateSignature(self::NONCE, self::TIMESTAMP, $data);

        self::assertNotSame(
            $baseline,
            (new EcoFlow($accessKey, $secretKey))->generateSignature($nonce, $timestamp, $data),
        );
    }
}
