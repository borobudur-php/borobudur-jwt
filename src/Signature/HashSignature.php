<?php
/**
 * This file is part of the Borobudur-Jwt package.
 *
 * (c) 2016 Hexacodelabs <http://hexacodelabs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Borobudur\Jwt\Signature;

/**
 * @author      Iqbal Maulana <iq.bluejack@gmail.com>
 * @created     5/13/16
 */
class HashSignature implements SignatureInterface
{
    /**
     * @const string
     */
    const HS256 = 'HS256';

    /**
     * @const string
     */
    const HS384 = 'HS384';

    /**
     * @const string
     */
    const HS512 = 'HS512';

    /**
     * @var array
     */
    protected static $algorithms = array(
        HashSignature::HS256 => 'sha256',
        HashSignature::HS384 => 'sha384',
        HashSignature::HS512 => 'sha512',
    );

    /**
     * {@inheritdoc}
     */
    public function sign($message, $key, $algorithm = null)
    {
        if ($this->match($algorithm)) {
            return hash_hmac(static::$algorithms[strtoupper($algorithm)], $message, $key, true);
        }

        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function verify($signature, $message, $key, $algorithm = null)
    {
        if ($this->match($algorithm)) {
            return $signature === $this->sign($message, $key, $algorithm);
        }

        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function match($algorithm)
    {
        return isset(static::$algorithms[strtoupper($algorithm)]);
    }
}
