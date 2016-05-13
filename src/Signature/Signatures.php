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
class Signatures implements SignatureInterface
{
    /**
     * @var SignatureInterface[]
     */
    protected $signatures = array();

    /**
     * Constructor.
     */
    public function __construct()
    {
        $this->signatures = array(
            new HashSignature(),
            new RsaSignature(),
        );
    }

    /**
     * {@inheritdoc}
     */
    public function sign($message, $key, $algorithm = null)
    {
        if (null !== $signature = $this->getSignature($algorithm)) {
            return $signature->sign($message, $key, $algorithm);
        }

        throw new Exception(sprintf('Algorithm "%s" not supported.', $algorithm));
    }

    /**
     * {@inheritdoc}
     */
    public function verify($signature, $message, $key, $algorithm = null)
    {
        if (null !== $sign = $this->getSignature($algorithm)) {
            return $sign->verify($signature, $message, $key, $algorithm);
        }

        throw new Exception(sprintf('Algorithm "%s" not supported.', $algorithm));
    }

    /**
     * {@inheritdoc}
     */
    public function match($algorithm)
    {
        return null !== $this->getSignature($algorithm);
    }

    /**
     * @param $algorithm
     *
     * @return SignatureInterface|null
     */
    protected function getSignature($algorithm)
    {
        foreach ($this->signatures as $signature) {
            if ($signature->match($algorithm)) {
                return $signature;
            }
        }

        return null;
    }
}
