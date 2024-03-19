# TeamOne Crypt

支持跨平台的加密解密库。

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



