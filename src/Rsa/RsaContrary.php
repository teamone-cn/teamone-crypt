<?php

namespace Teamone\Crypt\Rsa;

class RsaContrary extends RsaAbstract
{

    public function encrypt(string $data, string $password): string
    {
        $publicKey = $password;
        openssl_public_encrypt($data, $encryptedData, $publicKey);
        $encryptedData = base64_encode($encryptedData);

        return $encryptedData;
    }

    public function decrypt(string $data, string $password): string
    {
        $private_key = $password;
        $encrypted   = base64_decode($data);
        openssl_private_decrypt($encrypted, $decryptedData, $private_key);

        return $decryptedData;
    }

}
