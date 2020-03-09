<?php

include_once '../XMLSignature.php';

$trusted_key_path = "./cert/MPayOfflineSample.cer";
$private_key_path = "./cert/MPayOfflineSample.pfx";
$passkey = "123456";

$request_unsigned = "./xml/request_unsigned.xml";
$request_signed = "./xml/request_signed.xml";

$options = [
    "private_key_path" => $private_key_path,
    "passkey" => $passkey,
    "trusted_key_path" => [$trusted_key_path]
];

function testSignDocument($input, $output, $options) {
    try {
        $signature = new XMLSignature($options);
        $signature->_DEBUG = true;
        /* ------- sign ------- */
        $request = file_get_contents($input);
        $raw = $signature->apply($request);
        // echo $raw->C14N(true);
        file_put_contents($output, $raw->C14N(true));
    } catch (Exception $ex) {
        echo "error: {$e->getCode()}, {$e->getMessage()}";
    }
}

function testVerifySignature($input, $output, $options) {
    try {
        $signature = new XMLSignature($options);
        $signature->_DEBUG = true;

        /* ------- validate --- */
        $request = file_get_contents($input);
        $raw = $signature->validate($request);
        // echo $raw->C14N(true);
        // file_put_contents($output, $raw->C14N(true));
    } catch (Exception $ex) {
        echo "error: {$e->getCode()}, {$e->getMessage()}";
    }
}

testSignDocument($request_unsigned, $request_signed, $options);
testSignDocument($request_signed, $request_signed, $options);
