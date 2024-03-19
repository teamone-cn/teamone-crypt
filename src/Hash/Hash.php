<?php

namespace Teamone\Crypt\Hash;

use Teamone\Crypt\CryptVerify;
use Teamone\Crypt\Exceptions\CryptException;

class Hash implements CryptVerify
{
    /**
     * @var string 算法
     */
    private $algo;

    /**
     * @var bool 是否二进制
     */
    private $binary;

    public function __construct(string $algo = 'sha256', bool $binary = false)
    {
        if (!in_array($algo, $this->getAlgorithms())) {
            throw new CryptException('Not Support Algo');
        }

        $this->algo   = $algo;
        $this->binary = $binary;
    }

    public function encrypt(string $data, string $password): string
    {
        return hash_hmac($this->algo, $data, $password, $this->binary);
    }

    public function decrypt(string $data, string $password): string
    {
        throw new CryptException('Not Support Decrypt');
    }

    public function verify(string $data, string $password): bool
    {
        return hash_equals($data, $password);
    }

    public function getAlgorithms(): array
    {
        return hash_hmac_algos();
    }
}
