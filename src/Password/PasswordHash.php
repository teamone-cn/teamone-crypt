<?php

namespace Teamone\Crypt\Password;

use Teamone\Crypt\CryptVerify;
use Teamone\Crypt\Exceptions\CryptException;

class PasswordHash implements CryptVerify
{
    /**
     * @var string 算法
     */
    private $algo;
    private $options;

    public function __construct(string $algo = '2y', array $options = [])
    {
        if (!in_array($algo, $this->getAlgorithms())) {
            throw new CryptException('Not Support Algo');
        }

        $this->algo    = $algo;
        $this->options = $options;
    }

    public function encrypt(string $data, string $password = null): string
    {
        if (!is_null($password)) {
            throw new CryptException('Not Support Password Params');
        }

        return password_hash($data, $this->algo, $this->options);
    }

    public function decrypt(string $data, string $password): string
    {
        throw new CryptException('Not Support Decrypt');
    }

    public function verify(string $data, string $password): bool
    {
        return password_verify($password, $data);
    }

    public function getAlgorithms(): array
    {
        return password_algos();
    }

    public function getAlgorithmInfo(string $hash): array
    {
        return password_get_info($hash);
    }
}
