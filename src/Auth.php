<?php

namespace Simples\Security;

use Simples\Http\Kernel\App;

/**
 * Class Auth
 * @package Simples\Security
 */
abstract class Auth
{
    /**
     * @var array
     */
    private static $data;

    /**
     * @param string $password
     * @return string
     */
    public static function crypt(string $password): string
    {
        return password_hash($password, PASSWORD_DEFAULT);
    }

    /**
     * @param string $password
     * @param string $candidate
     * @return bool
     */
    public static function match(string $password, string $candidate): bool
    {
        return password_verify($password, $candidate);
    }

    /**
     * @return string
     */
    public static function getToken()
    {
        return App::request()->getHeader(env('AUTH_TOKEN'));
    }

    /**
     * @param array $options
     * @return string
     */
    public static function createToken(array $options = []): string
    {
        return JWT::create($options, env('SECURITY'));
    }

    /**
     * @param string $property
     * @return string
     */
    public static function getTokenValue(string $property): string
    {
        $token = self::getToken();
        if (!$token) {
            return '';
        }
        return off(JWT::payload($token, env('SECURITY')), $property);
    }

    /**
     * Add an user to Auth Session
     * @param mixed $data
     */
    public static function register($data)
    {
        static::$data = $data;
    }

    /**
     * Remove the user of Auth Session
     */
    public static function unRegister()
    {
        static::$data = null;
    }

    /**
     * @return array
     */
    public static function getAll(): array
    {
        return static::$data;
    }

    /**
     * @param string $property
     * @return mixed
     */
    public static function get(string $property)
    {
        return static::$data[$property] ?? null;
    }

}
