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

use Borobudur\Jwt\Exception\Exception;

/**
 * @author      Iqbal Maulana <iq.bluejack@gmail.com>
 * @created     5/13/16
 */
class RsaSignature implements SignatureInterface
{
    /**
     * @const string
     */
    const RS256 = 'RS256';

    /**
     * @const string
     */
    const RS384 = 'RS384';

    /**
     * @const string
     */
    const RS512 = 'RS512';

    /**
     * @var array
     */
    protected static $algorithms = array(
        RsaSignature::RS256 => 'sha256',
        RsaSignature::RS384 => 'sha384',
        RsaSignature::RS512 => 'sha512',
    );

    /**
     * {@inheritdoc}
     */
    public function sign($message, $key, $algorithm = null)
    {
        if ($this->match($algorithm)) {
            if (openssl_sign($message, $signature, $key, static::$algorithms[strtoupper($algorithm)])) {
                return $signature;
            }

            throw new Exception('OpenSSL unable to sign data');
        }

        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function verify($signature, $message, $key, $algorithm = null)
    {
        if ($this->match($algorithm)) {
            return 1 === openssl_verify($message, $signature, $key, static::$algorithms[strtoupper($algorithm)]);
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
