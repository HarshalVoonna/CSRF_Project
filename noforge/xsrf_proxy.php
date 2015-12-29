<?php
// AliasMatch ^/dummy_site/.*\.php C:/wamp/www/xsrf_proxy.php

$_xx_info['token_name'] = 'xsrf_token'; 
$_xx_info['document_root'] = 'C:/wamp/www';  
$_xx_info['tokentable_file'] = 'C:/wamp/www/token_table'; 
$_xx_info['session_timeout'] = 1500;  
$_xx_info['whitelist'] = array();

$_xx_info['target_app'] = 'default';
$_xx_info['session_name'] = 'PHPSESSID';
$_xx_info['disarm_url'] = 'http://localhost/default.html';

$_xx_info['token_table'] = _xx_load_token_table($_xx_info['tokentable_file']);
$_xx_info['bare_scriptname'] = _xx_extract_scriptname($_SERVER['SCRIPT_NAME']);
$_xx_info['rewrite_allowed'] = true;

if (_xx_request_contains_sid($_xx_info, &$_xx_info['sid']) && !isset($_xx_info['whitelist'][$_xx_info['bare_scriptname']]) ) {
    if (isset($_xx_info['token_table'][$_xx_info['sid']]['token'])) {
        $_xx_info['token'] = _xx_get_token_from_request($_xx_info);
        $_xx_info['expected_token'] = $_xx_info['token_table'][$_xx_info['sid']]['token'];

        // if the request doesn't contain a token
        if ($_xx_info['token'] == -1) {
            echo 'Disarm 1, ' . $_SERVER['REQUEST_URI'] . '<br/>';
            _xx_disarm($_xx_info, $_xx_info['expected_token']);
        }
        // check if the token is associated to the request sid
        if ($_xx_info['token'] != $_xx_info['expected_token']) {
            echo 'Disarm 2, ' . $_SERVER['REQUEST_URI'] . '<br/>';
            _xx_disarm($_xx_info, $_xx_info['expected_token']);
        }
        // update timestamp
        $_xx_info['token_table'][$_xx_info['sid']]['time'] = time();
    }
	else {
        // if we've never seen this SID before, we haven't performed rewriting yet;
        $_xx_info['token'] = _xx_generate_token();
        $_xx_info['token_table'][$_xx_info['sid']]['token'] = $_xx_info['token'];
        $_xx_info['token_table'][$_xx_info['sid']]['time'] = time();
    }
}

// store the token table
_xx_store_token_table($_xx_info['token_table'], $_xx_info['tokentable_file']);

$_xx_info['target_script_complete'] = $_xx_info['document_root'] . $_SERVER['SCRIPT_NAME'];
$_xx_info['target_script_path'] = dirname($_xx_info['target_script_complete']);
$_xx_info['target_script_name'] = basename($_SERVER['SCRIPT_NAME']);

include $_xx_info['target_script_complete'];

// does the request contain a session ID? if it does, the param receives this ID's value
function _xx_request_contains_sid($_xx_info, &$sid_in_request) {
    if (isset($_REQUEST[$_xx_info['session_name']])) {
        $sid_in_request = $_REQUEST[$_xx_info['session_name']];
        return true;
    } else {
        $sid_in_request = null;
        return false;
    }
}

// returns the token (i.e., a string) from the request, or -1 if there is no token
function _xx_get_token_from_request($_xx_info) {
    if (isset($_REQUEST[$_xx_info['token_name']])) {
        return $_REQUEST[$_xx_info['token_name']];
    } else {
        return -1;
    }
}

// returns the token table array
function _xx_load_token_table($filename) {
    if (is_file($filename)) {
        $serialized = file_get_contents($filename);
        return unserialize($serialized);
    } else {
        return array();
    }
}

// writes the token table array to a file
function _xx_store_token_table($token_table, $filename) {
    $file = fopen($filename, 'w');
    fwrite($file, serialize($token_table));
    fclose($file);
}

function _xx_disarm($_xx_info, $expected_token) {
    echo 'It seems that an XSRF attack is taking place...<br/>';
    echo "Please follow this link to <a href='{$_xx_info['disarm_url']}?{$_xx_info['token_name']}=$expected_token'>proceed</a>.";
    exit;
}

// generates a random token (string) and returns it
function _xx_generate_token() {
    return rand(1000000, 10000000);
}

function _xx_extract_scriptname($script_name) {
    $right_end = strrpos($script_name, '?');
    if ($right_end === false) {
        $right_end = strlen($script_name);
    }
    $left_end = strrpos($script_name, '/');
    if ($left_end === false) {
        $left_end = -1;
    }
    $script_name = substr($script_name, $left_end + 1, $right_end - $left_end - 1);
    return $script_name;
}
?>