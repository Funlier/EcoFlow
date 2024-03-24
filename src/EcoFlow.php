<?php

declare(strict_types=1);

namespace MarjovanLier\EcoFlow;

use DateTime;
use DateTimeZone;
use Exception;
use JsonException;
use Random\RandomException;
use RuntimeException;
use SensitiveParameter;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\Exception\ClientExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\DecodingExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\RedirectionExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\ServerExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;

readonly class EcoFlow
{
    /**
     * Create __constructor.
     */
    public function __construct(
        #[SensitiveParameter]
        private string $accessKey,
        #[SensitiveParameter]
        private string $secretKey
    ) {}


    /**
     * @param array{
     *     sn?: string,
     *     cmdCode?: string,
     *     params?: array<string, string|int>
     * } $data
     */
    public function generateSignature(string $nonce, string $timestamp, array $data): string
    {
        // Flatten, sort, and concatenate the data array.
        $flattenedData = $this->flattenData($data);
        ksort($flattenedData, SORT_STRING);

        // Concatenate accessKey, nonce, and timestamp.
        $signatureBase = http_build_query($flattenedData);
        $signatureBase .= sprintf('&accessKey=%s&nonce=%s&timestamp=%s', $this->accessKey, $nonce, $timestamp);

        $signatureBase = ltrim($signatureBase, '&');

        // Encrypt with HMAC-SHA256 and secretKey.
        $signatureBytes = hash_hmac('sha256', $signatureBase, $this->secretKey, true);

        // Convert bytes to hexadecimal string.
        return bin2hex($signatureBytes);
    }


    /**
     * Flatten a multi-dimensional array into a single level array.
     *
     * @param array<int|string, array<int|string, array<int, string>|int|string>|string>|array<string, int|string> $data
     *
     * @return array<int|string, int|string>
     */
    public function flattenData(array $data, string $prefix = ''): array
    {
        $flattened = [];

        foreach ($data as $key => $value) {
            if ($key === 0) {
                $key = '';
            }

            $newKey = $prefix === '' ? $key : sprintf('%s.%s', $prefix, $key);
            $newKey = is_string($newKey) ? rtrim($newKey, '.') : (string) $newKey;

            if (is_array($value)) {
                // Recursive call for nested arrays.
                $flattened = array_merge($flattened, $this->flattenData($value, $newKey));

                continue;
            }

            // Append to a flattened array.
            $flattened[$newKey] = $value;
        }

        return $flattened;
    }


    /**
     * @param array<string, string> $headers
     * @param array<string, array<string, int|string>|string> $params
     *
     * @return array{
     *      code: string,
     *      message?: string,
     *      data: array<int, array{sn?: string, deviceName?: string, online?: bool}>,
     *      eagleEyeTraceId: string,
     *      tid: string
     *  }
     *
     * @throws ClientExceptionInterface
     * @throws DecodingExceptionInterface
     * @throws JsonException
     * @throws TransportExceptionInterface
     * @throws RedirectionExceptionInterface
     * @throws ServerExceptionInterface
     */
    public function makeRequest(
        string $url,
        string $method,
        #[SensitiveParameter]
        array $headers,
        array $params = []
    ): array {
        $httpClient = HttpClient::create();

        $options = ['headers' => $headers];

        if ($params !== [] && $method === 'GET') {
            $options['query'] = $params;
        }

        if ($params !== [] && in_array($method, ['POST', 'PUT', 'PATCH'], true)) {
            $options['body'] = json_encode($params, JSON_THROW_ON_ERROR);
        }

        /**
         * @var array{
         *       code: string,
         *       message?: string,
         *       data: array<int, array{sn?: string, deviceName?: string, online?: bool}>,
         *       eagleEyeTraceId: string,
         *       tid: string
         *   } $request
         */
        $request = $httpClient->request($method, $url, $options)->toArray();

        return $request;
    }


    /**
     * @return array<string, array<string, array<string, int>|int|string>|int|string>
     *
     * @throws DecodingExceptionInterface|Exception|JsonException|RandomException|TransportExceptionInterface
     *
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function getAllQuotaInfo(string $deviceSN): array
    {
        $nonce = $this->createNonce();
        $timestamp = $this->createTimestamp();

        $params = ['sn' => $deviceSN];

        $signature = $this->generateSignature($nonce, $timestamp, $params);

        $url = 'https://api-e.ecoflow.com/iot-open/sign/device/quota/all';
        $headers = [
            'accessKey' => $this->accessKey,
            'nonce' => $nonce,
            'sign' => $signature,
            'timestamp' => $timestamp,
        ];

        /**
         * @var array{
         *     code: string,
         *     message: string,
         *     data: array<string, int|string|array<string, int|string|array<string, int>>>
         * } $response
         */
        $response = $this->makeRequest($url, 'GET', $headers, $params);

        if ($response['code'] === '0') {
            $data = $response['data'];

            ksort($data, SORT_STRING);

            return $data;
        }

        throw new RuntimeException('Error getting all quota information: ' . $response['message']);
    }


    /**
     * @param array<string, int|string> $params
     *
     * @throws DecodingExceptionInterface|Exception|RandomException|TransportExceptionInterface
     *
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function setParams(string $deviceSN, string $cmdCode, array $params = []): string
    {
        $nonce = $this->createNonce();
        $timestamp = $this->createTimestamp();

        $data = [
            'cmdCode' => $cmdCode,
            'params' => $params,
            'sn' => $deviceSN,
        ];

        $signature = $this->generateSignature($nonce, $timestamp, $data);

        $url = 'https://api-e.ecoflow.com/iot-open/sign/device/quota';
        $headers = [
            'accessKey' => $this->accessKey,
            'Content-Type' => 'application/json;charset=UTF-8',
            'nonce' => $nonce,
            'sign' => $signature,
            'timestamp' => $timestamp,
        ];

        $response = $this->makeRequest($url, 'PUT', $headers, $data);

        if (isset($response['code']) && $response['code'] === '0') {
            return 'Supply priority set successfully.';
        }

        if (isset($response['message'])) {
            return 'Error setting supply priority: ' . $response['message'];
        }

        return 'Something went wrong';
    }


    /**
     * @param array<string, int|string> $params
     *
     * @throws ClientExceptionInterface
     * @throws DecodingExceptionInterface
     * @throws JsonException
     * @throws RandomException
     * @throws RedirectionExceptionInterface
     * @throws ServerExceptionInterface
     * @throws TransportExceptionInterface
     *
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function getParams(string $deviceSN, array $params = []): string
    {
        $nonce = $this->createNonce();
        $timestamp = $this->createTimestamp();

        $data = [
            'params' => $params,
            'sn' => $deviceSN,
        ];

        $signature = $this->generateSignature($nonce, $timestamp, $data);

        $url = 'https://api-e.ecoflow.com/iot-open/sign/device/quota';

        $headers = [
            'Accept' => 'application/json',
            'accessKey' => $this->accessKey,
            'Content-Type' => 'application/json;charset=UTF-8',
            'nonce' => $nonce,
            'sign' => $signature,
            'timestamp' => $timestamp,
        ];

        $response = $this->makeRequest($url, 'POST', $headers, $data);

        if (isset($response['code']) && $response['code'] === '0') {
            return 'Supply priority retrieved successfully.';
        }

        if (isset($response['message'])) {
            return 'Error getting supply priority: ' . json_encode($response, JSON_THROW_ON_ERROR);
        }

        return 'Something went wrong. ' . json_encode($response, JSON_THROW_ON_ERROR);
    }


    /**
     * @return array{
     *     code: string,
     *     message?: string,
     *     data: array<int, array{
     *         sn?: string,
     *         deviceName?: string,
     *         online?: bool,
     *     }>,
     *     eagleEyeTraceId: string,
     *     tid: string
     * }
     *
     * @psalm-suppress PossiblyUnusedMethod
     *
     * @throws DecodingExceptionInterface|Exception|RandomException|TransportExceptionInterface
     */
    public function getDevices(): array
    {
        $nonce = $this->createNonce();
        $timestamp = $this->createTimestamp();

        $signature = $this->generateSignature($nonce, $timestamp, []);

        $url = 'https://api-e.ecoflow.com/iot-open/sign/device/list';
        $headers = [
            'accessKey' => $this->accessKey,
            'Content-Type' => 'application/json',
            'nonce' => $nonce,
            'sign' => $signature,
            'timestamp' => $timestamp,
        ];

        return $this->makeRequest($url, 'GET', $headers);
    }


    /**
     * @throws RandomException
     */
    private function createNonce(): string
    {
        return (string) random_int(100000, 999999);
    }


    /**
     * Returns the current timestamp in milliseconds. in long type.
     * Like  1672382607378.
     *
     * @throws Exception
     */
    private function createTimestamp(): string
    {
        $dateTime = new DateTime((string) null, new DateTimeZone('UTC'));
        $formatted = (int) $dateTime->format('U.u');

        return (string) round($formatted * 1000);
    }
}
