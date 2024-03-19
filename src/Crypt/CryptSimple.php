<?php

namespace Teamone\Crypt\Crypt;

use Teamone\Crypt\Crypt;
use Teamone\Crypt\Exceptions\CryptException;

class CryptSimple implements Crypt
{
    /**
     * string 盐值算法
     */
    public const ALGORITHM_SHA256 = 'sha256';

    /**
     * @var string 加密算法
     */
    private $cipherAlgorithm;
    /**
     * @var int 盐值长度
     */
    private $saltSize;

    public function __construct(string $cipherAlgorithm = 'aes-128-cbc', int $saltSize = 32)
    {
        if (!in_array($cipherAlgorithm, $this->getAlgorithms())) {
            throw new CryptException('Not Support Algo');
        }

        $this->cipherAlgorithm = $cipherAlgorithm;
        $this->saltSize        = $saltSize;
    }

    public function encrypt(string $data, string $password): string
    {
        // 生成一个加密安全的随机盐
        $salt   = random_bytes($this->saltSize);
        $salted = $this->genSalt($password, $salt);
        $key    = $this->subKey($salted);

        $length = openssl_cipher_iv_length($this->cipherAlgorithm);

        $strongResult = false;

        $iv = openssl_random_pseudo_bytes($length, $strongResult);
        if ($iv === false) {
            throw new CryptException("Generated string of bytes on failure.");
        }

        if ($strongResult === false) {
            throw new CryptException("Generated strong result on failure.");
        }

        $ciphertextRaw = openssl_encrypt($data, $this->cipherAlgorithm, $key, OPENSSL_RAW_DATA, $iv);

        $hmac = hash_hmac(self::ALGORITHM_SHA256, $ciphertextRaw, $key, true);

        return base64_encode($salt . $iv . $hmac . $ciphertextRaw);
    }

    public function decrypt(string $data, string $password): string
    {
        $ciphertext        = base64_decode($data);
        $salt              = substr($ciphertext, 0, $this->saltSize);
        $ciphertext        = substr($ciphertext, $this->saltSize);
        $salted            = $this->genSalt($password, $salt);
        $key               = $this->subKey($salted);
        $length            = openssl_cipher_iv_length($this->cipherAlgorithm);
        $iv                = substr($ciphertext, 0, $length);
        $sha2len           = 32;
        $hmac              = substr($ciphertext, $length, $sha2len);
        $ciphertextRaw     = substr($ciphertext, $length + $sha2len);
        $originalPlaintext = openssl_decrypt($ciphertextRaw, $this->cipherAlgorithm, $key, OPENSSL_RAW_DATA, $iv);
        $calcMac           = hash_hmac(self::ALGORITHM_SHA256, $ciphertextRaw, $key, true);

        // 可防止时序攻击的字符串比较
        if (!hash_equals($hmac, $calcMac)) {
            throw new CryptException("The two strings are not equal");
        }

        return $originalPlaintext;
    }

    protected function subKey(string $salted): string
    {
        return substr($salted, 0, 32);
    }

    protected function genSalt(string $password, string $salt): string
    {
        $salted = '';
        $dx     = '';
        while (strlen($salted) < 128) {
            $dx     = hash(self::ALGORITHM_SHA256, $dx . $password . $salt, true);
            $salted .= $dx;
        }

        return $salted;
    }

    public function getAlgorithms(): array
    {
        return openssl_get_cipher_methods();
    }
}
