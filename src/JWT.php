<?php

namespace Simples\Security;

use Simples\Helper\JSON;
use Simples\Http\Error\SimplesForbiddenError;

/**
 * Class Jwt
 * @package Simples\Security
 */
abstract class JWT
{
    /**
     * @param array $data
     * @param string $secret
     * @return string
     */
    public static function create(array $data, string $secret): string
    {
        $header = base64_encode(json_encode(['type' => 'JWT', 'alg' => 'HS256']));

        $payload = base64_encode(Encryption::encode(JSON::encode($data), $secret));

        $signature = base64_encode(hash_hmac('sha256', "{$header}.{$payload}", $secret, true));

        return "{$header}.{$payload}.{$signature}";
    }

    /**
     * @param string $token
     * @param string $secret
     * @return array
     * @throws SimplesForbiddenError
     */
    public static function payload(string $token, string $secret): array
    {
        if (!static::verify($token, $secret)) {
            throw new SimplesForbiddenError("The token '{$token}' is invalid");
        }
        $peaces = explode('.', $token);
        if (count($peaces) !== 3) {
            throw new SimplesForbiddenError("The token '{$token}' is invalid");
        }
        return (array)JSON::decode(Encryption::decode(base64_decode($peaces[1]), $secret));
    }

    /**
     * @param string $token
     * @param string $secret
     * @return bool
     */
    public static function verify(string $token, string $secret): bool
    {
        $peaces = explode('.', $token);
        if (count($peaces) < 3) {
            return false;
        }
        $header = $peaces[0];
        $payload = $peaces[1];
        $signature = $peaces[2];
        $hash = base64_encode(hash_hmac('sha256', "{$header}.{$payload}", $secret, true));

        return hash_equals($signature, $hash);
    }
}
