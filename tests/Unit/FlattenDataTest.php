<?php

declare(strict_types=1);

namespace MarjovanLier\EcoFlow\Tests\Unit;

use MarjovanLier\EcoFlow\EcoFlow;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class FlattenDataTest extends TestCase
{
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

        $ecoFlow = new EcoFlow('', '');
        $expectedFlattenData = [
            'params.cmdSet' => 11,
            'params.eps' => 0,
            'params.id' => 24,
            'sn' => '123456789',
        ];

        $flattenData = $ecoFlow->flattenData($data);

        self::assertEquals($expectedFlattenData, $flattenData);
    }


    public function testGenerateFlattenData2(): void
    {
        $data = [
            'params' => [
                'quotas' => ['20_1.supplyPriority'],
            ],
            'sn' => '123456789',
        ];

        $ecoFlow = new EcoFlow('', '');
        $expectedFlattenData = [
            'params.quotas[0]' => '20_1.supplyPriority',
            'sn' => '123456789',
        ];

        $flattenData = $ecoFlow->flattenData($data);

        self::assertEquals($expectedFlattenData, $flattenData);
    }


    /**
     * @return iterable<string, array{array<int|string, int|string|array<int|string, int|string|array<int|string, int|string>>>, string, array<int|string, int|string>}>
     */
    public static function provideFlattenCases(): iterable
    {
        yield 'empty input' => [[], '', []];

        yield 'scalar values keep their type' => [['a' => 1, 'b' => '1'], '', ['a' => 1, 'b' => '1']];

        yield 'spec example with list, object and object list' => [
            ['name' => 'demo1', 'ids' => [1, 2, 3], 'deviceInfo' => ['id' => 1], 'deviceList' => [['id' => 1], ['id' => 2]]],
            '',
            [
                'name' => 'demo1',
                'ids[0]' => 1,
                'ids[1]' => 2,
                'ids[2]' => 3,
                'deviceInfo.id' => 1,
                'deviceList[0].id' => 1,
                'deviceList[1].id' => 2,
            ],
        ];

        yield 'three levels of objects' => [['a' => ['b' => ['c' => 1]]], '', ['a.b.c' => 1]];

        yield 'list of lists' => [
            ['m' => [[1, 2], [3]]],
            '',
            ['m[0][0]' => 1, 'm[0][1]' => 2, 'm[1][0]' => 3],
        ];

        // json_encode() sends these as a JSON object, so the server expands them with dots.
        yield 'integer keys that are not a list' => [['p' => [1 => 'a', 2 => 'b']], '', ['p.1' => 'a', 'p.2' => 'b']];

        yield 'integer keys out of order are not a list' => [['p' => [1 => 'a', 0 => 'b']], '', ['p.1' => 'a', 'p.0' => 'b']];

        yield 'explicit prefix on an object' => [['a' => 1], 'root', ['root.a' => 1]];

        yield 'explicit prefix on a list' => [['x', 'y'], 'root', ['root[0]' => 'x', 'root[1]' => 'y']];

        yield 'top-level list without prefix keeps its indexes' => [['x', 'y'], '', ['x', 'y']];

        yield 'top-level list of objects passes its index on as a string prefix' => [[['a' => 1]], '', ['0.a' => 1]];
    }


    /**
     * @param array<int|string, int|string|array<int|string, int|string|array<int|string, int|string>>> $data
     * @param array<int|string, int|string> $expected
     */
    #[DataProvider('provideFlattenCases')]
    public function testFlattenDataExpandsNestedArrays(array $data, string $prefix, array $expected): void
    {
        self::assertSame($expected, (new EcoFlow('', ''))->flattenData($data, $prefix));
    }
}
