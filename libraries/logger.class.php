<?php

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
