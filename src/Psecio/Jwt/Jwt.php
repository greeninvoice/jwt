<?php

namespace Psecio\Jwt;

use InvalidArgumentException;
use Psecio\Jwt\Claim\Custom;
use Psecio\Jwt\Exception\InvalidKeyException;
use Psecio\Jwt\Exception\SignatureErrorException;
use RuntimeException;
use stdClass;

class Jwt
{
    /**
     * Set of claims for the current JWT object
     * @var ClaimsCollection
     */
    private $claims;

    /**
     * Current header for JWT object
     * @var Header
     */
    private $header;

    /**
     * Initialize the object and set the header and claims collection
     *    Empty claims collection is set if none is given
     *
     * @param Header $header Header instance to set on JWT object
     * @param ClaimsCollection $collection Claims collection [optional]
     */
    public function __construct(Header $header, ClaimsCollection $collection = null)
    {
        $this->setHeader($header);
        if ($collection == null) {
            $collection = new ClaimsCollection();
        }
        $this->setClaims($collection);
    }

    /**
     * Set the header instance
     *
     * @param Header $header [description]
     * @return Jwt Current Jwt instance
     */
    public function setHeader(Header $header)
    {
        $this->header = $header;
        return $this;
    }

    /**
     * Get the currently assigned header instance
     *
     * @return Header Header object instance
     */
    public function getHeader()
    {
        return $this->header;
    }

    /**
     * Add a Claim to the current collection
     *
     * @param Claim $claim Claim instance to add
     * @return Jwt Current Jwt instance
     */
    public function addClaim(Claim $claim)
    {
        $this->claims->add($claim);
        return $this;
    }

    /**
     * Get the current claims collection
     *
     * @return ClaimsCollection instance
     */
    public function getClaims()
    {
        return $this->claims;
    }

    /**
     * Set the claims collection
     *
     * @param ClaimsCollection $collection Claims collection instance
     * @return Jwt Current Jwt instance
     */
    public function setClaims(ClaimsCollection $collection)
    {
        $this->claims = $collection;
        return $this;
    }

    /**
     * Encode the data, either given or from current object
     *
     * @param string $claims Claims string to encode [optional]
     * @param bool $addIssued
     * @return string Encoded data, appended by periods
     */
    public function encode($claims = null, $addIssued = false)
    {
        $header = $this->getHeader();
        $claimData = $this->getClaims()->toArray();

        // If we don't have an "issued at" make one
        if (!isset($claimData['iat']) && $addIssued === true) {
            $claimData['iat'] = time();
        }
        ksort($claimData);

        $claims = ($claims !== null)
            ? $claims
            : $this->base64Encode(
                json_encode($claimData, JSON_UNESCAPED_SLASHES)
            );

        $headerData = $header->toArray();
        ksort($headerData);

        $sections = array(
            $this->base64Encode(json_encode($headerData, JSON_UNESCAPED_SLASHES)),
            $claims
        );

        $signWith = implode('.', $sections);
        $signature = $this->sign(
            $signWith,
            $header->getKey()
        );

        if ($signature !== null) {
            $sections[] = $this->base64Encode($signature);
        }

        $result = implode('.', $sections);

        return $result;
    }

    /**
     * Decode the data with the given key
     *    Optional "verify" parameter validates the signature as well (default is on)
     *
     * @param string $data Data to decode (entire JWT data string)
     * @param boolean $verify Verify the signature on the data [optional]
     * @return stdClass Decoded claims data
     * @throws Exception\BadSignatureException If signature doesn't verify
     * @throws Exception\DecodeException If invalid number of sections
     */
    public function decode($data, $verify = true)
    {
        $sections = explode('.', $data);
        if (count($sections) < 3) {
            throw new Exception\DecodeException('Invalid number of sections (<3)');
        }

        list($header, $claims, $signature) = $sections;
        $header = json_decode($this->base64Decode($header));
        $claims = json_decode($this->base64Decode($claims));
        $signature = $this->base64Decode($signature);
        $key = $this->getHeader()->getKey();

        if ($verify === true) {
            if ($this->verify($key, $header, $claims, $signature) === false) {
                throw new Exception\BadSignatureException('Signature did not verify');
            }
        }

        return $claims;
    }

    /**
     * Encrypt the data with the given key (and algorithm/IV)
     *
     * @param string $algorithm Algorithm to use for encryption
     * @param string $iv IV for encrypting data
     * @param string $key
     * @return string Encrypted string
     * @throws RuntimeException If OpenSSL is not enabled
     */
    public function encrypt($algorithm, $iv, $key)
    {
        if (!function_exists('openssl_encrypt')) {
            throw new RuntimeException('Cannot encrypt data, OpenSSL not enabled');
        }

        $data = json_encode($this->getClaims()->toArray(), JSON_UNESCAPED_SLASHES);

        $claims = $this->base64Encode(openssl_encrypt(
            $data, $algorithm, $key, false, $iv
        ));

        return $this->encode($claims);
    }

    /**
     * Decrypt given data wtih given key (and algorithm/IV)
     *
     * @param string $data Data to decrypt
     * @param string $algorithm Algorithm to use for decrypting the data
     * @param string $iv
     * @param string $key
     * @return string Decrypted data
     * @throws Exception\DecodeException If incorrect number of sections is provided
     * @throws RuntimeException If OpenSSL is not installed
     */
    public function decrypt($data, $algorithm, $iv, $key)
    {
        if (!function_exists('openssl_encrypt')) {
            throw new RuntimeException('Cannot encrypt data, OpenSSL not enabled');
        }

        // Decrypt just the claims
        $sections = explode('.', $data);
        if (count($sections) < 3) {
            throw new Exception\DecodeException('Invalid number of sections (<3)');
        }

        $claims = openssl_decrypt(
            $this->base64Decode($sections[1]), $algorithm, $key, false, $iv
        );

        return json_decode($claims);
    }

    /**
     * Verify the signature on the JWT message
     *
     * @param string $key Key used for hashing
     * @param stdClass $header Header data (object)
     * @param stdClass $claims Set of claims
     * @param string $signature Signature string
     * @return boolean Pass/fail of verification
     * @throws Exception\ExpiredException If the message has expired
     * @throws Exception\DecodeException If Audience is not defined
     * @throws Exception\DecodeException Processing before time not allowed
     * @throws Exception\DecodeException If no algorithm is specified
     */
    public function verify($key, $header, $claims, $signature)
    {
        if (empty($header->alg)) {
            throw new Exception\DecodeException('Invalid header: no algorithm specified');
        }

        if (isset($claims->aud) && empty($claims->aud)) {
            throw new Exception\DecodeException('Audience cannot be empty [aud]');
        }

        // If "expires at" defined, check against time
        if (isset($claims->exp) && $claims->exp <= time()) {
            throw new Exception\ExpiredException('Message has expired');
        }

        // If a "not before" is provided, validate the time
        if (isset($claims->nbf) && $claims->nbf > time()) {
            throw new Exception\DecodeException(
                'Cannot process prior to ' . date('m.d.Y H:i:s', $claims->nbf) . ' [nbf]'
            );
        }

//        $algorithm = $header->alg;
        $signWith = implode('.', array(
            $this->base64Encode(json_encode($header, JSON_UNESCAPED_SLASHES)),
            $this->base64Encode(json_encode($claims, JSON_UNESCAPED_SLASHES))
        ));
        return
            $this->verifySignature($signWith, $key, $signature);
    }

    /**
     * Base64 encode data and prepare for the URL
     *    NOTE: The "=" is removed as it's just padding in base64
     *  and not needed.
     *
     * @param string $data Data string
     * @return string Formatted data
     */
    public function base64Encode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Base64 decode (and url decode) the given data
     *
     * @param string $data Data to decode
     * @return string Decoded data
     */
    public function base64Decode($data)
    {
        $decoded = str_pad(
            $data,
            4 - (strlen($data) % 4),
            '='
        );
        return base64_decode(strtr($decoded, '-_', '+/'));
    }

    /**
     * Generate the signature with the given data, key and algorithm
     *
     * @param string $signWith Data to sign hash with
     * @param string $key Key for signing
     * @return string Generated signature hash
     */
    public function sign($signWith, $key)
    {
        $hashType = $this->getHeader()->getAlgorithm();

        $hash = '\\Psecio\\Jwt\\HashMethod\\' . $hashType;
        if (class_exists($hash) === false) {
            throw new InvalidArgumentException('Invalid hash type: ' . $hashType);
        }

        /** @var HashMethod $hash */
        $hash = new $hash();

        if ($hash->getKeyType() === 'HMAC') {
            $signature = hash_hmac(
                $hash->getAlgorithm(),
                $signWith,
                $key,
                true
            );
        } else {
            if ($hash->isValidKey($key) === false) {
                throw new InvalidKeyException('Invalid key provided');
            }
            openssl_sign(
                $signWith,
                $signature,
                $key,
                $hash->getAlgorithm()
            );
        }

        if ($signature === false) {
            throw new SignatureErrorException('Error signing with provided key');
        }

        return $signature;
    }

    /**
     * Generate the signature with the given data, key and algorithm
     *
     * @param string $signWith Data to sign hash with
     * @param string $key Key for signing
     * @param string $expectedSignature
     * @return bool
     */
    public function verifySignature($signWith, $key, $expectedSignature)
    {
        $hashType = $this->getHeader()->getAlgorithm();

        $hash = '\\Psecio\\Jwt\\HashMethod\\' . $hashType;
        if (class_exists($hash) === false) {
            throw new InvalidArgumentException('Invalid hash type: ' . $hashType);
        }
        /** @var HashMethod $hash */
        $hash = new $hash();

        if ($hash->getKeyType() === 'HMAC') {
            $actualSignature = hash_hmac(
                $hash->getAlgorithm(),
                $signWith,
                $key,
                true
            );
            return hash_equals($actualSignature, $expectedSignature);
        } else {
            if ($hash->isValidKey($key) === false) {
                throw new InvalidKeyException('Invalid key provided');
            }
            return openssl_verify(
                    $signWith,
                    $expectedSignature,
                    $key,
                    $hash->getAlgorithm()
                ) == 1;
        }
    }

    /**
     * Magic method for setting claims by name
     *    Ex. "issuedAt()" calls Claims\IssuedAt
     *
     * @param string $name Function name
     * @param array $args Arguments to pass
     * @return Jwt instance
     * @throws InvalidArgumentException If invalid claim type
     */
    public function __call($name, $args)
    {
        // see if it matches one of our claim types
        $className = "\\Psecio\\Jwt\\Claim\\" . ucwords($name);
        if (class_exists($className)) {
//            $type = (isset($args[1])) ? $args[1] : null;
            $claim = new $className($args[0]);
            $this->addClaim($claim);
            return $this;
        } else {
            throw new InvalidArgumentException('Invalid claim type "' . $name . '"');
        }
    }

    /**
     * See if a claim type matches the requested property
     *
     * @param string $name Property name
     * @return mixed Either a null if not found or the matching data
     */
    public function __get($name)
    {
        foreach ($this->getClaims() as $claim) {
            if ($claim->getName() === $name) {
                return $claim->getValue();
            }
        }
        return null;
    }

    /**
     * Allow for the insertion of multiple custom values at once
     *
     * @param string|array $value Either a string for a single claim or array for multiple
     * @param string $name Name of claim to use if string given for "name" [optional]
     * @return Jwt instance
     */
    public function custom($value, $name = null)
    {
        $value = (!is_array($value)) ? array($name => $value) : $value;
        foreach ($value as $type => $tValue) {
            $claim = new Custom($tValue, $type);
            $this->addClaim($claim);
        }
        return $this;
    }
}