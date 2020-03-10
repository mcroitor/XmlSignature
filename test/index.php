<?php

include_once '../XMLSignature.php';

$trusted_key_path = "./cert/MPayOfflineSample.cer";
$public_key_path = "./cert/MPayOfflineSample.cer";
$private_key_path = "./cert/MPayOfflineSample.pem";
$passkey = "123456";

$request_unsigned = "./xml/request_unsigned.xml";
$request_signed = "./xml/request_signed.xml";
$request_verified = "./xml/request_verified.xml";

$options = [
    "private_key_path" => $private_key_path,
    "public_key_path" => $public_key_path,
    "passkey" => $passkey,
    "trusted_key_path" => [$trusted_key_path]
];

function testSignDocument($input, $output, $options) {
    Logger::write("========== test " . __FUNCTION__);
    try {
        $signature = new XMLSignature($options);
        $signature->_DEBUG = true;
        /* ------- sign ------- */
        $request = file_get_contents($input);
        $raw = $signature->apply($request);
        // echo $raw->C14N(true);
        file_put_contents($output, $raw->C14N(true));
        echo "echo ".__FUNCTION__." passed!\n";
    } catch (Exception $ex) {
        echo "error: {$ex->getCode()}, {$ex->getMessage()}";
    }
}

function testVerifySignature($input, $output, $options) {
    Logger::write("========== test " . __FUNCTION__);
    try {
        $signature = new XMLSignature($options);
        $signature->_DEBUG = true;

        /* ------- validate --- */
        $request = file_get_contents($input);
        $raw = $signature->validate($request);
        // echo $raw->C14N(true);
        file_put_contents($output, $raw->C14N(true));
        echo "echo ".__FUNCTION__." passed!\n";
    } catch (Exception $ex) {
        echo "error: {$ex->getCode()}, {$ex->getMessage()}";
    }
}

testSignDocument($request_unsigned, $request_signed, $options);
testVerifySignature($request_signed, $request_verified, $options);

$testString = "<soapenv:Envelope xmlns:mpay='https://mpay.gov.md/' xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/'>
    <soapenv:Header/>
    <soapenv:Body wsu:Id='id-73366A2C0A927B059E15831497416694' xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'>
        <mpay:GetOrderDetails>
            <mpay:query>
                <mpay:OrderKey>3BEEA3B3-B2C3-46AC-96F4-44FC4DAA9AED</mpay:OrderKey>
                <mpay:ServiceID>MPaySampleService</mpay:ServiceID>
                <mpay:Language>ro</mpay:Language>
            </mpay:query>
        </mpay:GetOrderDetails>
    </soapenv:Body>
</soapenv:Envelope>";


$result = preg_replace("/>\s+</", "><", $testString);

//echo $result; //str_replace("\n", "", $result);