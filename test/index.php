<?php

include_once '../XMLSignature.php';

$trusted_key_path = "./cert/MPayOfflineSample.cer";
$private_key_path = "./cert/MPayOfflineSample.pfx";
$passkey = "123456";

$request_unsigned = "./xml/request_unsigned.xml";
$request_signed = "./xml/request_signed.xml";
$request_verified = "./xml/request_verified.xml";

$options = [
    "private_key_path" => $private_key_path,
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
