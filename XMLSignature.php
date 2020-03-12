<?php

class XMLSignature {

    /**
     * useful namespaces
     */
    public const NS = [
        "WSSE" => "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
        "WSU" => "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
        "DS" => "http://www.w3.org/2000/09/xmldsig#",
        "EC" => "http://www.w3.org/2001/10/xml-exc-c14n#",
        "SOAPENV" => "http://schemas.xmlsoap.org/soap/envelope/"
    ];

    /**
     * required digest algorithms
     */
    public const DIGEST_ALGORITHM = [
        "sha1" => "http://www.w3.org/2000/09/xmldsig#sha1",
        "sha256" => "http://www.w3.org/2001/04/xmlenc#sha256"
    ];

    /**
     * required encoding algorithms
     */
    public const ENCODING_ALGORITHM = [
        "base64" => "http://www.w3.org/2000/09/xmldsig#base64"
    ];

    /**
     * required MAC algorithms
     */
    public const MAC_ALGORITHM = [
        "hmac-sha256" => "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
        "hmac-sha1" => "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"
    ];

    /**
     * required signature algorithms
     */
    public const SIGNATURE_ALGORITHM = [
        "rsa-sha1" => "http://www.w3.org/2000/09/xmldsig#rsa-sha1", //OPENSSL_ALGO_SHA1,
        "rsa-sha256" => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", //OPENSSL_ALGO_SHA256,
        "ecdsa-sha256" => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", // 
        "dsa-sha1" => "http://www.w3.org/2000/09/xmldsig#dsa-sha1" // 
    ];
    private const SIGN_OPENSSL = [
        "rsa-sha1" => OPENSSL_ALGO_SHA1,
        "rsa-sha256" => OPENSSL_ALGO_SHA256
    ];

    /**
     * required canonicalitation algorithms
     */
    public const CANONICALIZATION_ALGORITHM = [
        "exclusive-1.0" => "http://www.w3.org/2001/10/xml-exc-c14n#",
        "canon-1.0" => "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
        "canon-1.1" => "http://www.w3.org/2006/12/xml-c14n11"
    ];

    /**
     * usefull xpath
     */
    private const XPATH = [
        "Envelope" => "/soapenv:Envelope",
        "Header" => "/soapenv:Envelope/soapenv:Header",
        "Body" => "/soapenv:Envelope/soapenv:Body",
        "Security" => "/soapenv:Envelope/soapenv:Header/wsse:Security",
        "BinarySecurityToken" => "/soapenv:Envelope/soapenv:Header/wsse:Security/ds:Signature",
        "Signature" => "/soapenv:Envelope/soapenv:Header/wsse:Security/wsse:Signature",
        "SignatureValue" => "/soapenv:Envelope/soapenv:Header/wsse:Security/ds:Signature/ds:SignatureValue",
        "SignatureMethod" => "/soapenv:Envelope/soapenv:Header/wsse:Security/ds:Signature/ds:SignatureMethod",
        "SignedInfo" => "/soapenv:Envelope/soapenv:Header/wsse:Security/ds:Signature/ds:SignedInfo",
        "KeyInfo" => "/soapenv:Envelope/soapenv:Header/wsse:Security/ds:Signature/ds:KeyInfo",
        "Reference" => "/soapenv:Envelope/soapenv:Header/wsse:Security/ds:Signature/ds:SignedInfo/ds:Reference"
    ];

    /**
     * the reference to XML document, for sign or verify signature
     * @var DOMDocument 
     */
    private $document = null;

    /**
     * XPath engine for referenced XML document
     * @var DOMXPath 
     */
    private $xpath = null;

    /**
     * list of references to trusted certificates
     * @var resource[] 
     */
    private $trusted_keys = [];

    /**
     * reference to private certificate for informational service
     * @var resource 
     */
    private $private_key = null;

    /**
     * reference to public certificate for informational service
     * @var resource 
     */
    private $public_key = null;

    /**
     * token part from public string
     * @var string 
     */
    private $token = null;

    /**
     * Common Name of private / public certificate issuer
     * @var string 
     */
    private $issuer_name = null;

    /**
     * serial number of private / public certificate
     * @var string 
     */
    private $serial_number = null;

    /**
     * digest algorithm
     * @var string
     */
    private $digest_algorithm = "sha1";

    /**
     * algorithm for signing / verifying signature
     * @var integer 
     */
    private $signature_algorithm = "rsa-sha1";

    /**
     * canonicalization algorithm
     * @var string 
     */
    private $canonicalization_algorithm = "exclusive-1.0";
    private $binary_token = false;

    public function __construct(array $options) {
        if (empty($options["private_key_path"]) === false) {
            $this->privateKey($options["private_key_path"], $options["passkey"]);
        }
        if (empty($options["public_key_path"]) === false) {
            $this->publicKey($options["public_key_path"]);
        }
        if (empty($options["trusted_key_path"]) === false) {
            foreach ($options["trusted_key_path"] as $trusted_key_path) {
                $this->trustedKey($trusted_key_path);
            }
        }
        $this->digest_algorithm = (empty($options["digest_algorithm"])) ? "sha1" : $options["digest_algorithm"];
        $this->signature_algorithm = (empty($options["signature_algorithm"])) ? "rsa-sha1" : $options["signature_algorithm"];
        $this->binary_token = (empty($options["binary_token"])) ? false : $options["binary_token"];
    }

    public function enableDebug(bool $debug) {
        Logger::enableDebug($debug);
    }

    /**
     * register private key
     * @param string $private_key_path
     * @param string $passkey
     */
    public function privateKey(string $private_key_path, string $passkey) {
        $tmp = explode(".", $private_key_path);
        $ext = end($tmp);
        if ($ext === "pfx") {
            $certs = null;
            $result = openssl_pkcs12_read(file_get_contents($private_key_path), $certs, $passkey);
            if ($result === false) {
                throw new SoapFault("fault", "OpenSSL error: " . openssl_error_string());
            }
            $this->private_key = $certs["pkey"];
            $this->public_key = $certs["cert"];
            Logger::writeDebug("pfx loaded: " . print_r($certs, true));
        } else {
            $this->private_key = openssl_pkey_get_private(file_get_contents($private_key_path), $passkey);
        }
    }

    public function publicKey(string $public_key_path) {
        //$this->public_key = openssl_pkey_get_public(file_get_contents($public_key_path));
        $this->public_key = file_get_contents($public_key_path);
        $this->parsePublicKey();
    }

    /**
     * register trusted key
     * @param string $trusted_key_path
     */
    public function trustedKey(string $trusted_key_path) {
        $this->trusted_keys[] = openssl_pkey_get_public(file_get_contents($trusted_key_path));
    }

    /**
     * 
     * @param type $doc
     * @return \DOMDocument
     */
    public function apply($doc): DOMDocument {
        if (is_string($doc)) {
            $clean = preg_replace("/>\s+</", "><", $doc);
            $this->document = new DOMDocument();
            $this->document->loadXML($clean);
        } else {
            $this->document = $doc;
        }
        $this->xpath = $this->initXpath();

        $id = $this->uuid();
        // add id to body
        $body = $this->getNodes(self::XPATH["Body"]);
        $body->setAttributeNS(self::NS["WSU"], "wsu:Id", "ID-{$id}");
        // create header if not exists
        if ($this->xpath->query(self::XPATH["Header"])->length === 0) {
            $envelope = $this->xpath->query(self::XPATH["Envelope"])->item(0);
            $envelope->insertBefore(
                    $this->document->createElementNS(self::NS["SOAPENV"], "soapenv:Header"),
                    $this->xpath->query(self::XPATH["Body"])->item(0));
        }

        $timestampNode = $this->createTimestamp($id);
        $securityNode = $this->document->createElementNS(self::NS["WSSE"], "wsse:Security");
        $signatureNode = $this->document->createElementNS(self::NS["DS"], "ds:Signature");
        $signedInfoNode = $this->createSignedInfo();
        $signatureValueNode = $this->document->createElementNS(self::NS["DS"], "ds:SignatureValue");
        if ($this->binary_token === true) {
            $binarySecurityTokenNode = $this->createBinarySecutiryToken($id);
        }
        $keyInfoNode = $this->createKeyInfo($id);

        $signatureNode->appendChild($signedInfoNode);
        $signatureNode->appendChild($signatureValueNode);
        $signatureNode->appendChild($keyInfoNode);
        if ($this->binary_token === true) {
            $securityNode->appendChild($binarySecurityTokenNode);
        }
        $securityNode->appendChild($timestampNode);
        $securityNode->appendChild($signatureNode);

        $this->getNodes(self::XPATH["Header"])->appendChild($securityNode);
        $signedInfoNode->appendChild($this->createReference($timestampNode));
        $signedInfoNode->appendChild($this->createReference($body));

        $signatureValueNode->textContent = $this->createSignature($signedInfoNode);
        return $this->document;
    }

    private function parsePublicKey() {
        $token_1 = explode("-----END CERTIFICATE-----", $this->public_key, 2)[0];
        $token = explode("-----BEGIN CERTIFICATE-----", $token_1)[1];
        $this->token = str_replace(PHP_EOL, "", $token);
        $parsed = openssl_x509_parse($this->public_key);
        Logger::writeDebug(print_r($parsed, true));
        $this->issuer_name = "CN=" . $parsed["issuer"]["CN"];
        $this->serial_number = $parsed["serialNumber"];
    }

    private function createBinarySecutiryToken($id) {
        Logger::writeDebug("token = " . print_r($token, 1));
        $binarySecurityToken = $this->document->createElementNS(self::NS["WSSE"], "BinarySecurityToken", $this->token);
        $binarySecurityToken->setAttributeNS(self::NS["WSU"], "wsu:Id", "BST-{$id}");
        $binarySecurityToken->setAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
        $binarySecurityToken->setAttribute("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
        return $binarySecurityToken;
    }

    private function createSignature(DOMNode $node) {
        $signatureValue = null;
        openssl_sign($node->C14N(true), $signatureValue, $this->private_key, self::SIGN_OPENSSL[$this->signature_algorithm]);
        $base64 = base64_encode($signatureValue);
        return $base64;
    }

    private function createKeyInfo(string $id): DOMElement {
        $keyInfo = $this->document->createElementNS(self::NS["DS"], "KeyInfo");
        $keyInfo->setAttributeNS(self::NS["WSU"], "wsu:Id", "KI-{$id}");
        $securityTokenReference = $this->document->createElementNS(self::NS["WSSE"], "SecurityTokenReference");
        $securityTokenReference->setAttributeNS(self::NS["WSU"], "wsu:Id", "STR-{$id}");
        if ($this->binary_token === true) {
            $reference = $this->document->createElementNS(self::NS["WSSE"], "Reference");
            $reference->setAttribute("URI", "#BST-{$id}");
            $reference->setAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
            $securityTokenReference->appendChild($reference);
        } else {
            $X509Data = $this->document->createElementNS(self::NS["DS"], "X509Data");
            $X509Data->appendChild($this->document->createElementNS(self::NS["DS"], "X509IssuerName", $this->issuer_name));
            $X509Data->appendChild($this->document->createElementNS(self::NS["DS"], "X509SerialNumber", $this->serial_number));
            $securityTokenReference->appendChild($X509Data);
        }
        $keyInfo->appendChild($securityTokenReference);
        return $keyInfo;
    }

    private function createTimeStamp(string $id): DOMElement {
        $timestamp = $this->document->createElementNS(self::NS["WSU"], "wsu:Timestamp");
        $t = time();
        $created = $this->document->createElementNS(self::NS["WSU"], "wsu:Created");
        $created->textContent = date(DATE_W3C, $t);
        $expires = $this->document->createElementNS(self::NS["WSU"], "wsu:Expires");
        $expires->textContent = date(DATE_W3C, $t + 1800);
        $timestamp->appendChild($created);
        $timestamp->appendChild($expires);
        $timestamp->setAttributeNS(self::NS["WSU"], "wsu:Id", "TS-{$id}");

        return $timestamp;
    }

    private function createSignedInfo(): DOMElement {
        $signedInfo = $this->document->createElementNS(self::NS["DS"], "ds:SignedInfo");
        $canonical = $this->document->createElementNS(self::NS["DS"], "ds:CanonicalizationMethod");
        $canonical->setAttribute("Algorithm", self::CANONICALIZATION_ALGORITHM[$this->canonicalization_algorithm]);
        $signedInfo->appendChild($canonical);
        $signetureMethod = $this->document->createElementNS(self::NS["DS"], "ds:SignatureMethod");
        $signetureMethod->setAttribute("Algorithm", self::SIGNATURE_ALGORITHM[$this->signature_algorithm]);
        $signedInfo->appendChild($signetureMethod);
        return $signedInfo;
    }

    /**
     * reference can be created only for element attached to DOMDocument
     * @param DOMElement $element
     * @return \DOMElement
     */
    private function createReference(DOMElement $element): DOMElement {
        $referenceNode = $this->document->createElementNS(self::NS["DS"], "Reference");
        // #TODO: check if Id exists!
        $value = $element->getAttributeNS(self::NS["WSU"], "Id");
        $referenceNode->setAttribute("URI", "#{$value}");
        $transformsNode = $this->document->createElementNS(self::NS["DS"], "ds:Transforms");
        $transformNode = $this->document->createElementNS(self::NS["DS"], "ds:Transform");
        $transformNode->setAttribute("Algorithm", self::CANONICALIZATION_ALGORITHM[$this->canonicalization_algorithm]);
        $transformsNode->appendChild($transformNode);
        $referenceNode->appendChild($transformsNode);
        $digestMethodNode = $this->document->createElementNS(self::NS["DS"], "ds:DigestMethod");
        $digestMethodNode->setAttribute("Algorithm", self::DIGEST_ALGORITHM[$this->digest_algorithm]);
        $referenceNode->appendChild($digestMethodNode);
        $digest = $this->getDigest($element, $this->digest_algorithm);
        $digestNode = $this->document->createElementNS(self::NS["DS"], "ds:DigestValue", $digest);
        $referenceNode->appendChild($digestNode);
        return $referenceNode;
    }

    public function validate($doc): DOMDocument {
        if (is_string($doc)) {
            $clean = preg_replace("/>\s+</", "><", $doc);
            $this->document = new DOMDocument();
            $this->document->loadXML($clean);
        } else {
            $this->document = $doc;
        }
        $this->xpath = $this->initXpath();
        $securityNode = $this->getNodes(self::XPATH["Security"]);

        if (count($this->trusted_keys) === 0) {
            throw new SoapFault("fault", "no trusted key exists");
        }
        if ($this->validateReference() === false) {
            throw new SoapFault("fault", "XML reference is not valid");
        }
        if ($this->validateSignature() === false) {
            throw new SoapFault("fault", "XML signature is not valid");
        }
        $this->getNodes("/soapenv:Envelope/soapenv:Header")->removeChild($securityNode);
        return $this->document;
    }

    /**
     * validate references.
     * @return bool
     */
    private function validateReference(): bool {
        Logger::writeDebug("XMLSignature::validateReference");

        $referenceNodes = $this->getNodes(self::XPATH["Reference"], true);
        $result = true;

        foreach ($referenceNodes as $reference) {
            $uri = substr($reference->getAttribute("URI"), 1);
            $data_xpath = "//*[@wsu:Id='{$uri}']";
            $data = $this->getNodes($data_xpath);
            $tmp = explode("#", $this->getNodes("./ds:DigestMethod", false, $reference)->getAttribute("Algorithm"));
            $method = end($tmp);
            $digest = $this->getNodes("./ds:DigestValue", false, $reference)->textContent;
            $prefixList = "";
            if ($this->getNodes("./ds:Transforms/ds:Transform/ec:InclusiveNamespaces/@PrefixList", true, $reference)->length > 0) {
                $prefixList = $this->getNodes("./ds:Transforms/ds:Transform/ec:InclusiveNamespaces/@PrefixList", false, $reference)->nodeValue;
            }
            $calculated = $this->getDigest($data, $method, $prefixList);
            $result = $result && ($calculated === $digest);
        }
        Logger::writeDebug("XMLSignature::validateReference" . ($result ? "passed" : "failed"));
        return $result;
    }

    /**
     * Calculate digest
     * @param DOMNode $node
     * @return string
     */
    private function getDigest(DOMNode $node, string $algorithm, string $prefixList = ""): string {
        $canonical = $node->C14N(true, false, null, explode(" ", $prefixList));
        $digest = openssl_digest($canonical, $algorithm, true);
        $base64 = base64_encode($digest);
        Logger::writeDebug("node = {$node->localName}, calculated digest = {$base64}");
        return $base64;
    }

    /**
     * validate signatures.
     * @return bool
     */
    private function validateSignature(): bool {
        Logger::writeDebug("XMLSignature::validateSignature");

        $signedInfoNode = $this->getNodes(self::XPATH["SignedInfo"]);
        $signatureValue = $this->getNodes(self::XPATH["SignatureValue"])->textContent;
        $prefixList = "";
        if ($this->getNodes(self::XPATH["SignedInfo"] . "/ds:CanonicalizationMethod/ec:InclusiveNamespaces/@PrefixList", true)->length > 0) {
            $prefixList = $this->getNodes(self::XPATH["SignedInfo"] . "/ds:CanonicalizationMethod/ec:InclusiveNamespaces/@PrefixList")->nodeValue;
        }

        Logger::writeDebug("try: " . $this->createSignature($signedInfoNode));
        Logger::writeDebug("Signature Value: " . $signatureValue);
        $decode = base64_decode($signatureValue);
        foreach ($this->trusted_keys as $trusted_key) {
            $result = openssl_verify($signedInfoNode->C14N(true, false, null, explode(" ", $prefixList)), $decode, $trusted_key, self::SIGN_OPENSSL[$this->signature_algorithm]);
            if ($result === 1) {
                Logger::writeDebug("XMLSignature::validateSignature passed");
                return true;
            }
            if ($result === -1) {
                Logger::write("OpenSSL error: " . openssl_error_string());
            }
        }
        Logger::writeDebug("XMLSignature::validateSignature failed");
        return false;
    }

    /**
     * Wrapper under XPATH queries, throws exceptions if result is missed
     * @param string $path
     * @param bool $all
     * @param DOMNode $node
     * @return type
     */
    private function getNodes(string $path, bool $all = false, DOMNode $node = null) {
        $result = $this->xpath->query($path, $node);
        if ($result->length === 0) {
            new SoapFault("fault", "Not found '{$path}'");
        }
        if ($all) {
            return $result;
        }
        return $result->item(0);
    }

    private function uuid() {
        return sprintf('%04X%04X%04X%04X%04X',
                mt_rand(0, 65535),
                mt_rand(0, 65535),
                mt_rand(0, 65535),
                mt_rand(0, 65535),
                mt_rand(0, 65535));
    }

    private function initXpath() {
        $xpath = new DOMXPath($this->document);
        $xpath->registerNamespace("wsse", self::NS["WSSE"]);
        $xpath->registerNamespace("wsu", self::NS["WSU"]);
        $xpath->registerNamespace("ds", self::NS["DS"]);
        $xpath->registerNamespace("ec", self::NS["EC"]);
        $xpath->registerNamespace("soapenv", self::NS["SOAPENV"]);
        return $xpath;
    }

}

/**
 * Simple logger class
 */
class Logger {

    private static $logfile = "debug.log";
    private static $debug = false;

    public static function enableDebug(bool $debug) {
        self::$debug = $debug;
    }

    public static function writeDebug($message) {
        if (self::$debug === true) {
            self::write($message);
        }
    }

    public static function write($message) {
        $stamp = date(DATE_ATOM);
        file_put_contents(self::$logfile, "[ {$stamp} ] : {$message}\n", FILE_APPEND);
    }

    public static function logfilePath($path) {
        if (!empty($path)) {
            self::$logfile = $path;
        }
        return self::$logfile;
    }

}
