<?php

namespace Teamone\Crypt;

interface Crypt
{
    /**
     * @desc 加密
     * @param string $data 数据
     * @param string $password 密码
     * @return string 密文
     */
    public function encrypt(string $data, string $password): string;

    /**
     * @desc 解密
     * @param string $data 数据
     * @param string $password 密码
     * @return string 明文
     */
    public function decrypt(string $data, string $password): string;
}
