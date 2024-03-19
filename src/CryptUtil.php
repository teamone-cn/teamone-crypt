<?php

namespace Teamone\Crypt;

use Teamone\Crypt\Exceptions\CryptException;

class CryptUtil
{
    public const SEED_NUM = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    public const SEED_NUM_SPECIAL_CHARS = self::SEED_NUM . '!"#$%&\'()*+,-./:;<=>?@[\]^_`{|}~';

    /**
     * @desc 重复指定长度
     * @param string $string
     * @param int $length
     * @param bool $cut
     * @return string
     */
    public static function repeatToLength(string $string, int $length, bool $cut = false): string
    {
        if (strlen($string) >= $length) {
            return $string;
        }

        // 求重复数
        $num = (int)ceil($length / strlen($string));

        $string = str_repeat($string, $num);

        if ($cut) {
            $string = substr($string, 0, $length);
        }

        return $string;
    }

    /**
     * @desc 截取子字符串
     * @param string $str
     * @param int $start
     * @param $length
     * @return string
     */
    public static function substr(string $str, int $start = 0, $length = null): string
    {
        if ($length === 0) {
            return '';
        }

        return mb_substr($str, $start, $length, '8bit');
    }

    /**
     * @desc 字符串长度
     * @param string $binaryString
     * @return int
     */
    public static function strlen(string $binaryString): int
    {
        // 如果需要以字节为单位的字符串长度，则应使用
        return mb_strlen($binaryString, '8bit');
    }

    /**
     * @desc 字符串复制
     * @param string $string
     * @return string
     */
    public static function strcpy(string $string): string
    {
        // 初始化 $new 变量
        $newString = '';
        $len       = mb_strlen($string);
        // 使用除法来计算 $chunk
        $chunk = max($len / 2, 1);
        for ($i = 0; $i < $len; $i += $chunk) {
            $newString .= mb_substr($string, $i, $chunk);
        }
        return $newString;
    }

    /**
     * @desc 生成随机密码
     * @param int $length
     * @param string $seed
     * @return string
     * @throws \Random\RandomException
     */
    public function genRandomPassword(int $length = 20, string $seed = self::SEED_NUM_SPECIAL_CHARS)
    {
        $seedLength = strlen($seed);
        $password   = '';
        $random     = str_split(random_bytes($length));
        do {
            $shift    = ord(array_pop($random));
            $password .= $seed[$shift % $seedLength];
        } while (!empty($random));

        return $password;
    }

    /**
     * @desc PBKDF2密钥派生函数，由RSA的PKCS定义 #5: https://www.ietf.org/rfc/rfc2898.txt
     * @param string $password 密码
     * @param string $salt 密码中唯一的盐
     * @param string $algorithm 要使用的哈希算法。建议:SHA256 | SHA512
     * @param int $iterations 迭代计算。越高越好，但速度越慢。建议:至少1000
     * @param int $length 派生键的长度(以字节为单位)
     * @param bool $binary 如果为true，则以原始二进制格式返回密钥。否则进行十六进制编码
     * @return string
     * @throws CryptException
     */
    public static function hashPbkdf2(
        string $password,
        string $salt,
        string $algorithm = 'SHA256',
        int    $iterations = 12000,
        int    $length = 64,
        bool   $binary = false): string
    {
        $algorithm = strtolower($algorithm);

        if (!in_array($algorithm, hash_algos(), true)) {
            throw new CryptException('PBKDF2 ERROR: Invalid hash algorithm.');
        }

        if ($iterations <= 0 || $length <= 0) {
            throw new CryptException('PBKDF2 ERROR: Invalid parameters.');
        }

        return hash_pbkdf2($algorithm, $password, $salt, $iterations, $length, $binary);
    }

    /**
     * @desc PBKDF2密钥派生函数，由RSA的PKCS定义 #5: https://www.ietf.org/rfc/rfc2898.txt
     * @param string $password 密码
     * @param string $salt 密码中唯一的盐
     * @param string $algorithm 要使用的哈希算法。建议:SHA256
     * @param int $iterations 迭代计算。越高越好，但速度越慢。建议:至少1000
     * @param int $length 派生键的长度(以字节为单位)
     * @param bool $binary 如果为true，则以原始二进制格式返回密钥。否则进行十六进制编码
     * @return string
     * @throws CryptException
     */
    public static function pbkdf2(
        string $password,
        string $salt,
        string $algorithm = 'SHA256',
        int    $iterations = 12000,
        int    $length = 64,
        bool   $binary = false): string
    {
        if (!in_array($algorithm, hash_algos(), true)) {
            throw new CryptException('Not Support Decrypt');
        }

        if ($iterations <= 0 || $length <= 0) {
            $iterations = 20000;
            $length     = 128;
        }

        $hash_length = strlen(hash($algorithm, "", true));
        $block_count = ceil($length / $hash_length);

        $output = "";
        for ($i = 1; $i <= $block_count; $i++) {
            $last = $salt . pack("N", $i);
            $last = $xorSum = hash_hmac($algorithm, $last, $password, true);
            for ($j = 1; $j < $iterations; $j++) {
                $xorSum ^= ($last = hash_hmac($algorithm, $last, $password, true));
            }
            $output .= $xorSum;
        }

        if ($binary) {
            return substr($output, 0, $length);
        }

        return base64_encode(substr($output, 0, $length));
    }
}
