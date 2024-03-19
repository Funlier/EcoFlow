<?php

declare(strict_types=1);

namespace MarjovanLier\EcoFlow\Tests\Unit;

use MarjovanLier\EcoFlow\EcoFlow;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 *
 * @covers \MarjovanLier\EcoFlow\EcoFlow::generateSignature
 * @covers \MarjovanLier\EcoFlow\EcoFlow::flattenData
 */
final class GenerateSignatureTest extends TestCase
{
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

        $ecoFlow = new EcoFlow();
        $expectedSignature = '07c13b65e037faf3b153d51613638fa80003c4c38d2407379a7f52851af1473e';

        $signature = $ecoFlow->generateSignature($accessKey, $secretKey, $nonce, $timestamp, $data);

        self::assertEquals($expectedSignature, $signature);
    }


    public function testGenerateFlattenData(): void
    {
        $data = [
            'params' => [
                'cmdSet' => 11,
                'eps' => 0,
                'id' => 24,
            ],
            'sn' => '123456789',
        ];

        $ecoFlow = new EcoFlow();
        $expectedFlattenData = [
            'params.cmdSet' => 11,
            'params.eps' => 0,
            'params.id' => 24,
            'sn' => '123456789',
        ];

        $flattenData = $ecoFlow->flattenData($data);

        self::assertEquals($expectedFlattenData, $flattenData);
    }
}
