<?php

namespace Teamone\Crypt;

use Teamone\Crypt\Crypt\CryptComplex;
use Teamone\Crypt\Crypt\CryptSimple;
use Teamone\Crypt\Hash\Hash;
use Teamone\Crypt\Password\PasswordHash;
use Teamone\Crypt\Rsa\Rsa;
use Teamone\Crypt\Rsa\RsaContrary;

abstract class CryptProvider
{
    public static function createHash(array $params = []): CryptVerify
    {
        if (empty($params)) {
            return new Hash();
        }

        return new Hash(...$params);
    }

    public static function createPasswordHash(array $params = []): CryptVerify
    {
        if (empty($params)) {
            return new PasswordHash();
        }

        return new PasswordHash(...$params);
    }

    public static function createCryptSimple(array $params = []): Crypt
    {
        if (empty($params)) {
            return new CryptSimple();
        }
        return new CryptSimple(...$params);
    }

    public static function createCryptComplex(array $params = []): Crypt
    {
        if (empty($params)) {
            return new CryptComplex();
        }
        return new CryptComplex(...$params);
    }

    public static function createRsa(array $params = []): Crypt
    {
        if (empty($params)) {
            return new Rsa();
        }
        return new Rsa(...$params);
    }

    public static function createRsaContrary(array $params = []): Crypt
    {
        if (empty($params)) {
            return new RsaContrary();
        }
        return new RsaContrary(...$params);
    }

}
