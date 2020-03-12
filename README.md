# XmlSignature
Xml Signature Implementation. This class is proposed for SOAP messages signing.

## Properties description

Class _XMLSignature_ can be initialized with an array of options:
 * __private_key_path__ -- path to private certificate. This certificate can be 
  stored in PEM or PFX format.
 * __passkey__ password for private key.
 * __public_key_path__ -- path to public certificate. If PFX private key was used,
  public key will be extracted from PFX store.
 * __trusted_key_path__ -- an array of path to trusted keys. Is useful when Soap
  server has multiple registered clients.
 * __digest_algorithm__ -- Algorithm for digest calculation. Default value is
  `sha1`.
 * __signature_algorithm__ -- Algorithm for digest calculation. Default value is
  `rsa-sha1`.
 * __binary_token__ -- Use binarySecurityToken or not. Default value is `false`.

## Sample

```php
$options = [
    "private_key_path" => "/path/to/private.pem",
    "public_key_path" => "/path/to/public/cer",
    "passkey" => $passkey,
    "trusted_key_path" => [ "/path/to/truested.cer" ]
];

try {
    /* ------- sign ------- */
    $signature = new XMLSignature($options);
    $request = file_get_contents("request_unsigned.xml");
    $raw = $signature->apply($request);
    file_put_contents("request_signed.xml", $raw->C14N(true));
    echo "request signed successful\n";
} catch (Exception $ex) {
    echo "error: {$ex->getCode()}, {$ex->getMessage()}";
}

try {
    /* ------- validate --- */
    $signature = new XMLSignature($options);
    $request = file_get_contents("request_signed.xml");
    $raw = $signature->validate($request);
    file_put_contents("request_validated.xml", $raw->C14N(true));
    echo "request validated successful\n";
} catch (Exception $ex) {
    echo "error: {$ex->getCode()}, {$ex->getMessage()}";
}


```