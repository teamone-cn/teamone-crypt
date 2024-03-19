<?php

namespace Teamone\Crypt\Rsa;

use Teamone\Crypt\Crypt;
use Teamone\Crypt\Exceptions\RsaException;

abstract class RsaAbstract implements Crypt
{
    /**
     * @var array 配置
     */
    protected $config;
    /**
     * @var string 私钥
     */
    protected $privateKey;
    /**
     * @var string 公钥
     */
    protected $publicKey;

    public function __construct(string $algo = 'sha512', int $length = 4096)
    {
        $this->config = [
            // 算法
            "digest_alg"       => $algo,
            // 字节数  512 1024 2048  4096 等，此处长度与加密的字符串长度有关
            "private_key_bits" => $length,
            // 加密类型
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ];

        $openSSLAsymmetricKey = openssl_pkey_new($this->config);
        if ($openSSLAsymmetricKey === false) {
            throw new RsaException("OpenSSL int fail.");
        }

        // 提取私钥
        $exported = openssl_pkey_export($openSSLAsymmetricKey, $privateKey);
        if ($exported === false) {
            throw new RsaException("OpenSSL Export fail.");
        }
        // 保存私钥
        $this->privateKey = $privateKey;

        // 生成公钥
        $publicKey = openssl_pkey_get_details($openSSLAsymmetricKey);
        if ($publicKey === false) {
            throw new RsaException("OpenSSL Public Key fail.");
        }
        // 保存公钥
        $this->publicKey = $publicKey["key"];
    }

    public function getConfig(): array
    {
        return $this->config;
    }

    public function getPrivateKey(): string
    {
        return $this->privateKey;
    }

    public function getPublicKey(): string
    {
        return $this->publicKey;
    }
}
