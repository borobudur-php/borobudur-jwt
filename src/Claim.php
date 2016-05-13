<?php
/**
 * This file is part of the Borobudur-Jwt package.
 *
 * (c) 2016 Hexacodelabs <http://hexacodelabs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Borobudur\Jwt;

/**
 * @author      Iqbal Maulana <iq.bluejack@gmail.com>
 * @created     5/13/16
 */
class Claim
{
    /**
     * @var array
     */
    protected $claims = array();

    /**
     * Constructor.
     *
     * @param array $claims
     */
    public function __construct(array $claims = array())
    {
        $this->claims = $claims;
    }

    /**
     * @param string $id
     *
     * @return Claim
     */
    public function setId($id)
    {
        return $this->set('jti', $id);
    }

    /**
     * @return string|null
     */
    public function getId()
    {
        return $this->get('jti');
    }

    /**
     * @param string $issuer
     *
     * @return Claim
     */
    public function setIssuer($issuer)
    {
        return $this->set('iss', $issuer);
    }

    /**
     * @return string|null
     */
    public function getIssuer()
    {
        return $this->get('iss');
    }

    /**
     * @param string $audience
     *
     * @return Claim
     */
    public function setAudience($audience)
    {
        return $this->set('aud', $audience);
    }

    /**
     * @return string|null
     */
    public function getAudience()
    {
        return $this->get('aud');
    }

    /**
     * @param string $subject
     *
     * @return Claim
     */
    public function setSubject($subject)
    {
        return $this->set('sub', $subject);
    }

    /**
     * @return string|null
     */
    public function getSubject()
    {
        return $this->get('sub');
    }

    /**
     * @param int $time
     *
     * @return Claim
     */
    public function setIssuedAt($time)
    {
        return $this->set('iat', $time);
    }

    /**
     * @return int|null
     */
    public function getIssuedAt()
    {
        return $this->get('iat');
    }

    /**
     * @param int $time
     *
     * @return Claim
     */
    public function setNotBefore($time)
    {
        return $this->set('nbf', $time);
    }

    /**
     * @return int|null
     */
    public function getNotBefore()
    {
        return $this->get('nbf');
    }

    /**
     * @param int $time
     *
     * @return Claim
     */
    public function setExpires($time)
    {
        return $this->set('exp', $time);
    }

    /**
     * @return int|null
     */
    public function getExpires()
    {
        return $this->get('exp');
    }

    /**
     * @param int $issuedAt
     * @param int $notBefore
     * @param int $expires
     *
     * @return Claim
     */
    public function setCurrentTime($issuedAt, $notBefore, $expires)
    {
        $this->setIssuedAt($issuedAt);
        $this->setNotBefore($notBefore);
        $this->setExpires($expires);

        return $this;
    }

    /**
     * @param string $index
     * @param mixed  $value
     *
     * @return Claim
     */
    public function set($index, $value)
    {
        $this->claims[$index] = $value;

        return $this;
    }

    /**
     * @param string     $index
     * @param mixed|null $default
     *
     * @return mixed|null
     */
    public function get($index, $default = null)
    {
        if ($this->has($index)) {
            return $this->claims[$index];
        }

        return $default;
    }

    /**
     * @param string $index
     *
     * @return bool
     */
    public function has($index)
    {
        return array_key_exists($index, $this->claims);
    }

    /**
     * @return array
     */
    public function toArray()
    {
        return $this->claims;
    }
}
