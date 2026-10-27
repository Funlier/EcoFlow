<?php

declare(strict_types=1);

namespace MarjovanLier\EcoFlow\Tests\Unit;

use MarjovanLier\EcoFlow\EcoFlow;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * Feeds real EcoFlow responses, recorded from live devices on 2026-10-27 with serials, device names and
 * certificate values replaced, through the public methods and checks every value against the declared types.
 */
final class RecordedResponseTest extends TestCase
{
    private const ENVELOPE_FIELDS = [
        'code' => 'string',
        'message' => 'string',
        'data' => 'array',
        'eagleEyeTraceId' => 'string',
        'tid' => 'string',
    ];

    private const DEVICE_FIELDS = [
        'sn' => 'string',
        'deviceName' => 'string',
        'online' => 'int',
        'productName' => 'string',
    ];


    /**
     * @return iterable<string, array{string}>
     */
    public static function provideQuotaFixtures(): iterable
    {
        yield 'STREAM Ultra: floats and bools' => ['quota-stream-ultra'];
        yield 'PowerStream: task maps four levels deep' => ['quota-powerstream'];
        yield 'Smart Plug: task maps four levels deep' => ['quota-smart-plug'];
        yield 'DELTA 2 Max: lists of ints and lists of maps' => ['quota-delta-2-max'];
        yield 'RIVER 2 Pro: ints only' => ['quota-river-2-pro'];
    }


    #[DataProvider('provideQuotaFixtures')]
    public function testQuotaReadsReturnRecordedValuesWithinTheDeclaredTypes(string $fixture): void
    {
        $body = $this->fixture($fixture);
        $ecoFlow = new EcoFlow('ak', 'sk', new MockHttpClient([new MockResponse($body), new MockResponse($body)]));

        $all = $ecoFlow->getAllQuotaInfo('SN1');
        $params = $ecoFlow->getParams('SN1', ['quotas' => array_keys($all)]);
        ksort($params, SORT_STRING);

        self::assertNotSame([], $all);
        self::assertSame($all, $params);
        $this->assertQuotaValues($all, 1);
    }


    public function testDeviceListFitsTheDeclaredShape(): void
    {
        $ecoFlow = new EcoFlow('ak', 'sk', new MockHttpClient(new MockResponse($this->fixture('device-list'))));

        $devices = $ecoFlow->getDevices();

        $this->assertEnvelope($devices);
        self::assertCount(13, $devices['data'] ?? []);

        foreach ($devices['data'] ?? [] as $device) {
            $types = array_map(get_debug_type(...), $device);
            self::assertEquals(array_intersect_key(self::DEVICE_FIELDS, $types), $types);
        }
    }


    public function testCertificationFitsTheDeclaredShape(): void
    {
        $ecoFlow = new EcoFlow('ak', 'sk', new MockHttpClient(new MockResponse($this->fixture('certification'))));

        $certification = $ecoFlow->getAppCertification();

        $this->assertEnvelope($certification);
        self::assertSame(
            array_fill_keys(['certificateAccount', 'certificatePassword', 'url', 'port', 'protocol'], 'string'),
            array_map(get_debug_type(...), $certification['data'] ?? []),
        );
    }


    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideErrorFixtures(): iterable
    {
        yield '1006 device not allowed' => ['error-device-not-allowed', 'current device is not allowed to get device info'];
        yield '8512 unknown serial' => ['error-unknown-serial', 'no permission to do it'];
        yield '8513 access key invalid' => ['error-access-key-invalid', 'accessKey is invalid'];
        yield '8521 signature wrong' => ['error-signature-wrong', 'signature is wrong'];
        yield '8524 invalid parameter' => ['error-invalid-parameter', 'invalid parameter'];
        yield '8524 parameter empty' => ['error-parameter-empty', 'some parameter is empty: accessKey,nonce,timestamp,sign'];
    }


    #[DataProvider('provideErrorFixtures')]
    public function testRecordedErrorsReachEveryCallerWithTheApiMessage(string $fixture, string $message): void
    {
        $body = $this->fixture($fixture);
        $ecoFlow = new EcoFlow('ak', 'sk', new MockHttpClient([
            new MockResponse($body),
            new MockResponse($body),
            new MockResponse($body),
        ]));

        $devices = $ecoFlow->getDevices();
        $this->assertEnvelope($devices);
        self::assertArrayNotHasKey('data', $devices);
        self::assertSame('Error setting supply priority: ' . $message, $ecoFlow->setParams('SN1', 'CMD', ['a' => 1]));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/^' . preg_quote('Error getting all quota information: ' . $message, '/') . '$/');

        $ecoFlow->getAllQuotaInfo('SN1');
    }


    /**
     * Fails on any envelope key or value type outside the declared shape.
     *
     * @param array<string, array<int|string, int|string|array<string, int|string>>|string> $response
     */
    private function assertEnvelope(array $response): void
    {
        $types = array_map(get_debug_type(...), $response);

        self::assertEquals(array_intersect_key(self::ENVELOPE_FIELDS, $types), $types);
    }


    /**
     * Fails on any leaf that is not bool, float, int or string, and on arrays nested deeper than four levels.
     *
     * @param array<int|string, bool|float|int|string|array<int|string, bool|float|int|string|array<int|string, bool|float|int|string|array<int|string, bool|float|int|string>>>> $values
     */
    private function assertQuotaValues(array $values, int $level): void
    {
        self::assertLessThanOrEqual(4, $level, '`data` nests deeper than the declared four array levels.');

        foreach ($values as $value) {
            if (is_array($value)) {
                $this->assertQuotaValues($value, $level + 1);

                continue;
            }

            self::assertContains(get_debug_type($value), ['bool', 'float', 'int', 'string']);
        }
    }


    private function fixture(string $name): string
    {
        $contents = file_get_contents(__DIR__ . '/../Fixtures/' . $name . '.json');
        self::assertIsString($contents);

        return $contents;
    }
}
