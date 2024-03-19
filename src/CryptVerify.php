<?php

namespace Teamone\Crypt;

interface CryptVerify extends Crypt
{
    /**
     * @desc 验证
     * @param string $data 数据
     * @param string $password 密码
     * @return bool
     */
    public function verify(string $data, string $password): bool;
}
