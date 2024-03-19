<?php

declare(strict_types=1);

namespace MarjovanLier\EcoFlow;

use SensitiveParameter;

class EcoFlow
{
    /**
     * @param array{
     *     sn: string,
     *     params?: array<string, string|int>
     * } $data
     */
    public function generateSignature(
        #[SensitiveParameter]
        string $accessKey,
        #[SensitiveParameter]
        string $secretKey,
        string $nonce,
        string $timestamp,
        array $data
    ): string {
        // Flatten, sort, and concatenate the data array.
        $flattenedData = $this->flattenData($data);
        ksort($flattenedData, SORT_STRING);
        $queryString = http_build_query($flattenedData);

        // Concatenate accessKey, nonce, and timestamp.
        $signatureBase = $queryString . sprintf('&accessKey=%s&nonce=%s&timestamp=%s', $accessKey, $nonce, $timestamp);

        // Encrypt with HMAC-SHA256 and secretKey.
        $signatureBytes = hash_hmac('sha256', $signatureBase, $secretKey, true);

        // Convert bytes to hexadecimal string.
        return bin2hex($signatureBytes);
    }


    /**
     * Flatten a multi-dimensional array into a single level array.
     *
     * @param array<string, array<string, int|string>|string>|array<string, int|string> $data
     *
     * @return array<string, int|string>
     */
    public function flattenData(array $data, string $prefix = ''): array
    {
        $flattened = [];

        foreach ($data as $key => $value) {
            $newKey = $prefix === '' ? $key : sprintf('%s.%s', $prefix, $key);

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
}
