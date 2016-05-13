<?php
/**
 * This file is part of the Borobudur-Jwt package.
 *
 * (c) 2016 Hexacodelabs <http://hexacodelabs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Borobudur\Jwt\Test;

use Borobudur\Jwt\Claim;
use Borobudur\Jwt\Jwt;
use Borobudur\Jwt\Signature\HashSignature;
use Borobudur\Jwt\Signature\Signatures;

/**
 * @author      Iqbal Maulana <iq.bluejack@gmail.com>
 * @created     5/13/16
 */
class JwtTest extends \PHPUnit_Framework_TestCase
{
    public function testSign()
    {
        $jwt = new Jwt(new Signatures, 'hello world');
        $token = $jwt->encode(new Claim(array('user' => 'iqbal')), HashSignature::HS256);

        $this->assertTrue($jwt->verify($token));
        $this->assertTrue($jwt->decode($token)->has('user'));
        $this->assertSame('iqbal', $jwt->decode($token)->get('user'));

        $jwt = new Jwt(new Signatures, 'hello');

        $this->assertFalse($jwt->verify($token));
    }
}
