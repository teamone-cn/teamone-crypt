# TeamOne PHP Crypt 加密解密库

## 项目简介

TeamOne PHP Crypt 加密解密库是一个功能丰富、易于使用的 PHP 库，专门设计用于实现各种加密和解密操作。

它提供了多种加密和解密算法的支持，包括 Hash 加密解密、Password Hash 加密、Openssl 加密解密等，让开发人员能够轻松地在其 PHP 项目中实现数据的安全存储和传输。

由于 PHP Crypt 加密解密库支持 Openssl 加密解密，因此加密后的数据可以在其他支持 Openssl 加密的编程语言中进行解密，例如，在 PHP 加密后，可以在 Java 中进行解密，反之亦然。这种特性增强了该库的通用性和跨平台兼容性，使得加密的数据可以在不同的编程语言和平台之间进行安全的传输和共享。

通过使用 Openssl 加密算法，PHP Crypt 加密解密库提供了一种标准化的加密方式，使得加密数据可以在不同编程语言和平台上进行可靠的解密操作。这使得开发人员能够更加灵活地选择不同的技术栈和工具，而不必担心数据的安全性和完整性问题。

因此，PHP Crypt 加密解密库不仅适用于纯 PHP 环境，还可以与其他编程语言相互配合，实现更加复杂和多样化的应用场景。无论是在 PHP 还是在其他支持 Openssl 加密的编程语言中，都可以轻松地对加密数据进行解密操作，从而实现跨平台和跨语言的数据安全交互。

## 项目特点

1. 多种加密算法支持：该库支持多种常见的加密算法，包括 Hash 加密解密、Password Hash 加密、Openssl 加密解密等，覆盖了常见的加密需求。
2. 简单易用：设计简洁，接口清晰易懂，开发人员可以轻松地集成到他们的 PHP 项目中，并快速实现加密和解密功能。
3. 灵活性：支持自定义配置，开发人员可以根据项目需求调整加密算法的参数，以达到最佳的安全性和性能。
4. 安全性保障：采用了现代加密技术，保障用户数据的安全性，防止数据泄露和篡改。
5. 开源免费：完全开源免费，遵循常见的开源协议，任何人都可以免费使用、修改和分发该库。
6. 通用性和跨平台兼容性：在 PHP 加密后，可以在 Java 中进行解密，反之亦然。

## 主要功能

1. Hash 加密解密：支持常见的 Hash 算法，如 MD5、SHA1、SHA256 等，用于对数据进行单向加密和解密。
2. Password Hash 加密：提供了对密码进行安全哈希加密的功能，可用于存储用户密码。
3. Openssl 加密解密：支持 Openssl 库提供的各种对称加密算法和非对称加密算法，用于数据的对称加密和非对称加密。

## 单元测试

- 执行 Rsa 公钥、私钥，加密及解密 

````shell
./vendor/bin/phpunit ./test/CryptTest.php --filter testRsa$
````

## Hash 明文加密及解密

````php
use Teamone\Crypt\CryptProvider;

$crypt = CryptProvider::createHash();
// 明文
$data = 'hello Jukit .*?!';
// 密码
$password = '123456';
// 加密
$secure = $crypt->encrypt($data, $password);
// 解密
$verify = $crypt->verify($secure, $secure);
````

## Password Hash 密码加密

````php
use Teamone\Crypt\CryptProvider;

$crypt = CryptProvider::createPasswordHash();
// 密码
$password = '123456';
// 密码加密
$secure = $crypt->encrypt($password);
// 验证
$verify = $crypt->verify($secure, $password);
````

## Openssl 明文加密及解密

````php
use Teamone\Crypt\CryptProvider;

$crypt = CryptProvider::createCryptSimple();
// 明文
$data = 'hello Jukit .*?!';
// 密码
$password = '123456';
// 加密
$secure = $crypt->encrypt($data, $password);
// 解密
$text = $crypt->decrypt($secure, $password);
````

## Openssl 明文加密及解密

````php
use Teamone\Crypt\CryptProvider;

$crypt = CryptProvider::createCryptComplex();
// 明文
$data = 'hello Jukit .*?!';
// 密码
$password = '123456';
// 加密
$secure = $crypt->encrypt($data, $password);
// 解密
$text = $crypt->decrypt($secure, $password);
````

## Rsa 公钥、私钥，加密及解密

````php
use Teamone\Crypt\CryptProvider;

/** @var RsaAbstract $crypt */
$crypt = CryptProvider::createRsa();
// 明文
$data = 'hello Jukit .*?!';
// 使用私钥加密
$secure = $crypt->encrypt($data, $crypt->getPrivateKey());
// 使用公钥解密
$text = $crypt->decrypt($secure, $crypt->getPublicKey());
````

## Java 解密案例

在 PHP 中使用 RSA 进行加密后，调用者需要将公钥自行保存，用于在其它程序中使用公钥进行解密。

这里，我们使用PHP生成的公钥，使用 Java 程序进行解密。

````Java
package org.example.second;

import javax.crypto.Cipher;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RsaDecryptor {

    public static void main(String[] args) throws IOException {

        // 公钥
        Path path = Paths.get("./pem/public_key.pem");
        String publicKeyString = Files.readString(path);

        // 密文
        Path pathSecure = Paths.get("./pem/secure.txt");
        String encryptedData = Files.readString(pathSecure);

        try {
            // 解码公钥
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replace("\n", ""));

            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            // 解密
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, publicKey);

            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));

            String decryptedData = new String(decryptedBytes, StandardCharsets.UTF_8);

            System.out.println("解密后的明文: " + decryptedData);

        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
    }
}
/* 输出 
解密后的明文: hello world .*?!
*/
````



