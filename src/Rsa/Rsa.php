<?php

namespace Teamone\Crypt\Rsa;

class Rsa extends RsaAbstract
{
    public function encrypt(string $data, string $password): string
    {
        $privateKey = $password;
        openssl_private_encrypt($data, $encryptedData, $privateKey);
        $encryptedData = base64_encode($encryptedData);

        return $encryptedData;
    }

    public function decrypt(string $data, string $password): string
    {
        $publicKey = $password;
        $encrypted = base64_decode($data);
        openssl_public_decrypt($encrypted, $decrypted, $publicKey);

        return $decrypted;
    }
}
