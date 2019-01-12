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

use Borobudur\Jwt\Exception\SignatureInvalidException;
use Borobudur\Jwt\Exception\UnexpectedValueException;
use Borobudur\Jwt\Signature\SignatureInterface;
use DateTime;
use Exception;

/**
 * @author      Iqbal Maulana <iq.bluejack@gmail.com>
 * @created     5/13/16
 */
class Jwt
{
    /**
     * @var SignatureInterface
     */
    protected $signature;
    
    /**
     * @var string
     */
    protected $key;
    
    /**
     * @var int
     */
    protected $delay;
    
    /**
     * Constructor.
     *
     * @param SignatureInterface $signature
     * @param string             $key
     * @param int                $delay
     */
    public function __construct(SignatureInterface $signature, $key, $delay = 0)
    {
        $this->signature = $signature;
        $this->key = $key;
    }
    
    /**
     * Encode array payload data to JWT string.
     *
     * @param Claim  $claim
     * @param string $algorithm
     *
     * @return string
     */
    public function encode(Claim $claim, $algorithm)
    {
        $header = array('typ' => 'JWT', 'alg' => $algorithm);
        $segments = array(
            $this->urlSafeB64Encode(json_encode($header)), // header segment
            $this->urlSafeB64Encode(json_encode($claim->toArray())), // payload segment
        );
        
        $signature = $this->signature->sign(implode('.', $segments), $this->key, $algorithm);
        $segments[] = $this->urlSafeB64Encode($signature); // signature segment
        
        return implode('.', $segments);
    }
    
    /**
     * Decodes a JWT string into a Claim object.
     *
     * @param string $jwt
     * @param array  $allowedAlgorithms
     *
     * @return Claim
     * @throws Exception
     * @throws SignatureInvalidException
     */
    public function decode($jwt, array $allowedAlgorithms = array())
    {
        $payload = $this->extract($jwt, $allowedAlgorithms);
        
        if ($payload->getNotBefore() && $payload->getNotBefore() > (time() + $this->delay)) {
            throw new SignatureInvalidException(
                sprintf('Cannot handle token prior to %s.', date(DateTime::ISO8601, $payload->getNotBefore()))
            );
        }
        
        if ($payload->getIssuedAt() && $payload->getIssuedAt() > (time() + $this->delay)) {
            throw new SignatureInvalidException(
                sprintf('Cannot handle token prior to %s.', date(DateTime::ISO8601, $payload->getIssuedAt()))
            );
        }
        
        if ($payload->getExpires() && (time() + $this->delay) > $payload->getExpires()) {
            throw new SignatureInvalidException('Expired token.');
        }
        
        return $payload;
    }
    
    /**
     * Verify the JWT string.
     *
     * @param string $jwt
     * @param array  $allowedAlgorithms
     *
     * @return bool
     * @throws Exception
     * @throws SignatureInvalidException
     */
    public function verify($jwt, array $allowedAlgorithms = array())
    {
        try {
            $this->decode($jwt, $allowedAlgorithms);
            
            return true;
        } catch (Exception $e) {
            return false;
        }
    }
    
    /**
     * Validate and extract JWT claim.
     *
     * @param string $jwt
     * @param array  $allowedAlgorithms
     *
     * @return Claim
     * @throws Exception
     * @throws SignatureInvalidException
     */
    protected function extract($jwt, array $allowedAlgorithms)
    {
        $segments = explode('.', $jwt);
        if (3 !== count($segments)) {
            throw new UnexpectedValueException('Wrong number of segments.');
        }
        
        list($headerB64, $payloadB64, $signatureB64) = $segments;
        if (null === ($header = json_decode($this->urlSafeB64Decode($headerB64), true))) {
            throw new UnexpectedValueException('Invalid header encoding.');
        }
        
        if (!isset($header['alg']) || empty($header['alg'])) {
            throw new Exception('Empty algorithm.');
        }
        
        if (false === $this->signature->match($header['alg'])) {
            throw new Exception(sprintf('Algorithm "%s" not supported.', $header['alg']));
        }
        
        if ($allowedAlgorithms && false === in_array($header['alg'], $allowedAlgorithms)) {
            throw new Exception(sprintf('Algorithm "%s" not allowed.', $header['alg']));
        }
        
        if (null === ($payload = json_decode($this->urlSafeB64Decode($payloadB64), true))) {
            throw new UnexpectedValueException('Invalid claims encoding.');
        }
        
        $signature = $this->urlSafeB64Decode($signatureB64);
        if (false === $this->signature->verify(
                $signature,
                sprintf('%s.%s', $headerB64, $payloadB64),
                $this->key,
                $header['alg']
            )
        ) {
            throw new SignatureInvalidException('Signature verification failed.');
        }
        
        return new Claim($payload);
    }
    
    /**
     * @param mixed $data
     *
     * @return string
     */
    protected function urlSafeB64Encode($data)
    {
        return str_replace(array('+', '/', '\r', '\n', '='), array('-', '_'), base64_encode($data));
    }
    
    /**
     * @param string $b64
     *
     * @return string
     */
    protected function urlSafeB64Decode($b64)
    {
        return base64_decode(str_replace(array('-', '_'), array('+', '/'), $b64));
    }
}
