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
interface SignatureInterface
{
    /**
     * Sign a string with a given key and algorithm.
     *
     * @param string      $message
     * @param string      $key
     * @param string|null $algorithm
     *
     * @return string
     */
    public function sign($message, $key, $algorithm = null);

    /**
     * Verify a signature with the message, key and method. Not all methods
     * are symmetric, so we must have a separate verify and sign method.
     *
     * @param string      $signature
     * @param string      $message
     * @param string      $key
     * @param string|null $algorithm
     *
     * @return bool
     */
    public function verify($signature, $message, $key, $algorithm = null);

    /**
     * Match algorithm use the signature.
     *
     * @param string $algorithm
     *
     * @return bool
     */
    public function match($algorithm);
}
