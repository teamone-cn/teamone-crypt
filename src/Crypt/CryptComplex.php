<?php

namespace Teamone\Crypt\Crypt;

use ParagonIE\ConstantTime\Encoding;
use Teamone\Crypt\Crypt;
use Teamone\Crypt\CryptUtil;
use Teamone\Crypt\Exceptions\CryptException;

class CryptComplex implements Crypt
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

    public function __construct(string $cipherAlgorithm = 'aes-256-cbc', int $saltSize = 64)
    {
        if (!in_array($cipherAlgorithm, $this->getAlgorithms())) {
            throw new CryptException('Not Support Algo');
        }

        $this->cipherAlgorithm = $cipherAlgorithm;
        $this->saltSize        = $saltSize;
    }

    public function encrypt(string $data, string $password): string
    {
        // 生成一个加密安全的随机盐值
        $salt = $this->getPseudoSalt($this->saltSize);
        // 将盐值和密码组合生成加密的盐值
        $salted = $this->genSalt($password, $salt);
        $key    = CryptUtil::hashPbkdf2($password, $salted, self::ALGORITHM_SHA256, 2000, 64, true);

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

        $encode = $salt . $iv . $hmac . $ciphertextRaw;

        return class_exists(Encoding::class) ? Encoding::base64Encode($encode) : base64_encode($encode);
    }

    public function decrypt(string $data, string $password): string
    {
        $ciphertext = base64_decode($data);
        $salt       = substr($ciphertext, 0, $this->saltSize);
        $ciphertext = substr($ciphertext, $this->saltSize);
        $salted     = $this->genSalt($password, $salt);
        $key        = CryptUtil::hashPbkdf2($password, $salted, self::ALGORITHM_SHA256, 2000, 64, true);

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

    /**
     * @desc
     * @param int $size
     * @return string
     * @throws CryptException
     */
    protected function getPseudoSalt(int $size): string
    {
        $isSourceString = false;

        $bytes = openssl_random_pseudo_bytes($size, $isSourceString);

        if (false === $bytes || false === $isSourceString) {
            throw new CryptException("IV generated failure.");
        }

        return $bytes;
    }

    public function getAlgorithms(): array
    {
        return openssl_get_cipher_methods();
    }
}
