<?php

namespace Teamone\CryptTest;

use PHPUnit\Framework\TestCase;
use Teamone\Crypt\CryptProvider;
use Teamone\Crypt\Rsa\RsaAbstract;

class CryptTest extends TestCase
{
    public function setUp(): void
    {

    }

    // Hash 明文加密及解密
    public function testHash()
    {
        $crypt = CryptProvider::createHash();
        // 明文
        $data = 'hello Jukit .*?!';
        // 密码
        $password = '123456';
        // 加密
        $secure = $crypt->encrypt($data, $password);
        // 解密
        $verify = $crypt->verify($secure, $secure);

        $this->assertEquals($verify, true);

    }

    // Password Hash 密码加密
    public function testPasswordHash()
    {
        $crypt = CryptProvider::createPasswordHash();
        // 密码
        $password = '123456';
        // 密码加密
        $secure = $crypt->encrypt($password);
        // 验证
        $verify = $crypt->verify($secure, $password);

        $this->assertEquals($verify, true);
    }

    // Openssl 明文加密及解密
    public function testCryptSimple()
    {
        $crypt = CryptProvider::createCryptSimple();
        // 明文
        $data = 'hello Jukit .*?!';
        // 密码
        $password = '123456';
        // 加密
        $secure = $crypt->encrypt($data, $password);
        // 解密
        $text = $crypt->decrypt($secure, $password);

        $this->assertEquals($text, $data);
    }

    // Openssl 明文加密及解密
    public function testCryptComplex()
    {
        $crypt = CryptProvider::createCryptComplex();
        // 明文
        $data = 'hello Jukit .*?!';
        // 密码
        $password = '123456';
        // 加密
        $secure = $crypt->encrypt($data, $password);
        // 解密
        $text = $crypt->decrypt($secure, $password);

        $this->assertEquals($text, $data);
    }

    // Rsa 公钥、私钥，加密及解密
    public function testRsa()
    {
        /** @var RsaAbstract $crypt */
        $crypt = CryptProvider::createRsa();
        // 明文
        $data = 'hello Jukit .*?!';
        // 使用私钥加密
        $secure = $crypt->encrypt($data, $crypt->getPrivateKey());
        // 使用公钥解密
        $text = $crypt->decrypt($secure, $crypt->getPublicKey());

        $this->assertEquals($text, $data);
    }

    // Rsa 公钥、私钥，加密及解密
    public function testRsaContrary()
    {
        /** @var RsaAbstract $crypt */
        $crypt = CryptProvider::createRsaContrary();
        // 明文
        $data = 'hello Jukit .*?!';
        // 使用公钥加密
        $secure = $crypt->encrypt($data, $crypt->getPublicKey());
        // 使用私钥解密
        $text = $crypt->decrypt($secure, $crypt->getPrivateKey());

        $this->assertEquals($text, $data);
    }

    // Rsa 公钥、私钥保存
    public function testRsaPem()
    {
        /** @var RsaAbstract $crypt */
        $crypt = CryptProvider::createRsa();

        $data = 'hello Jukit .*?!';

        // 公钥
        $publicKey = $crypt->getPublicKey();
        // 私钥
        $privateKey = $crypt->getPrivateKey();
        // 加密
        $secure = $crypt->encrypt($data, $privateKey);
        // 解密
        $text = $crypt->decrypt($secure, $publicKey);

        $this->assertEquals($text, $data);

        // 保存公私钥
        file_put_contents(__DIR__ . '/public_key.pem', $publicKey);
        file_put_contents(__DIR__ . '/private_key.pem', $privateKey);
        file_put_contents(__DIR__ . '/secure.txt', $secure);
    }

}
