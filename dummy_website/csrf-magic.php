<?php

$GLOBALS['csrf']['defer'] = false;

$GLOBALS['csrf']['expires'] = 7200;

//error message
$GLOBALS['csrf']['callback'] = 'csrf_callback';

$GLOBALS['csrf']['rewrite-js'] = false;

//secret key
$GLOBALS['csrf']['secret'] = '';

//rewriting on html page
$GLOBALS['csrf']['rewrite'] = true;

//to use IP addresses when binding a user to a token
$GLOBALS['csrf']['allow-ip'] = true;

$GLOBALS['csrf']['cookie'] = '__csrf_cookie';

$GLOBALS['csrf']['user'] = false;

$GLOBALS['csrf']['key'] = false;

/**
 * The name of the magic CSRF token that will be placed in all forms, i.e.
 * <input type="hidden" name="$name" value="CSRF-TOKEN" />
 */
$GLOBALS['csrf']['input-name'] = '__csrf_magic';

$GLOBALS['csrf']['auto-session'] = true;

// FUNCTIONS:
$GLOBALS['csrf']['version'] = '1.0.4';


/**
 * Rewrites <form> to add CSRF tokens to them.
*/

function csrf_ob_handler($buffer, $flags) {

    // to check if the page is *actually* HTML.
    static $is_html = false;
    if (!$is_html) {
        if (stripos($buffer, '<html') !== false) {
            $is_html = true;
        } else {
            return $buffer;
        }
    }
	
    $tokens = csrf_get_tokens();
    $name = $GLOBALS['csrf']['input-name'];
	$input = "<input type='hidden' name='$name' value=\"$tokens\"/>";
    $buffer = preg_replace('#(<form[^>]*method\s*=\s*["\']post["\'][^>]*>)#i', '$1' . $input, $buffer);
    return $buffer;
}

/**
 * Checks if this is a post request, and if it is, checks if the nonce is valid.
 */
function csrf_check($fatal = true) {
	
	//pass the GET request
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') return true;
    
	csrf_start();
    $name = $GLOBALS['csrf']['input-name'];
    $ok = false;
    $tokens = '';
    
	do {
        if (!isset($_POST[$name])) break;
        $tokens = $_POST[$name];
        if (!csrf_check_tokens($tokens)) break;
        $ok = true;
    } while (false);
    
	if ($fatal && !$ok) {
        $callback = $GLOBALS['csrf']['callback'];
        if (trim($tokens, 'A..Za..z0..9:;,') !== '') $tokens = 'hidden';
        $callback($tokens);
        exit;
    }
    
	return $ok;
}

function csrf_get_tokens() {
    $has_cookies = !empty($_COOKIE);

    // if the user hasn't sent any cookies.
    $secret = csrf_get_secret();
    if (!$has_cookies && $secret) {
        $ip = ';ip:' . csrf_hash($_SERVER['IP_ADDRESS']);
    } else {
        $ip = '';
    }
    csrf_start();

    if (session_id()) return 'sid:' . csrf_hash(session_id()) . $ip;

    if ($GLOBALS['csrf']['cookie']) {
        $val = csrf_generate_secret();
        setcookie($GLOBALS['csrf']['cookie'], $val);
        return 'cookie:' . csrf_hash($val) . $ip;
    }

    if ($GLOBALS['csrf']['key']) return 'key:' . csrf_hash($GLOBALS['csrf']['key']) . $ip;

    if (!$secret) return 'invalid';

    if ($GLOBALS['csrf']['user'] !== false) {
        return 'user:' . csrf_hash($GLOBALS['csrf']['user']);
    }

    if ($GLOBALS['csrf']['allow-ip']) {
        return ltrim($ip, ';');
    }
    return 'invalid';
}

function csrf_callback($tokens) {
    
	header($_SERVER['SERVER_PROTOCOL'] . ' 403 Forbidden');
    $data = '';
    
	echo "<html><head><title>CSRF check failed</title></head>
        <body>
        <p>CSRF check failed. Your form session may have expired, or you may not have
        cookies enabled.</p>
        <form method='post' action=''>$data<input type='submit' value='Try again' /></form>
        <p>Debug: $tokens</p></body></html>
";
}

/**
 * Checks if a composite token is valid. Outward facing code should use this
 * instead of csrf_check_token()
 */
function csrf_check_tokens($tokens) {
    if (is_string($tokens)) $tokens = explode(';', $tokens);
    foreach ($tokens as $token) {
        if (csrf_check_token($token)) return true;
    }
    return false;
}

/**
 * Checks if a token is valid.
 */
function csrf_check_token($token) {
    if (strpos($token, ':') === false) return false;
	
    list($type, $value) = explode(':', $token, 2);
    
	if (strpos($value, ',') === false) return false;
    
	list($x, $time) = explode(',', $token, 2);
    
	if ($GLOBALS['csrf']['expires']) {
        if (time() > $time + $GLOBALS['csrf']['expires']) return false;
    }
    
	switch ($type) {
        case 'sid':
            return $value === csrf_hash(session_id(), $time);
    
		case 'cookie':
            $n = $GLOBALS['csrf']['cookie'];
            if (!$n) return false;
            if (!isset($_COOKIE[$n])) return false;
            return $value === csrf_hash($_COOKIE[$n], $time);
        
		case 'key':
            if (!$GLOBALS['csrf']['key']) return false;
            return $value === csrf_hash($GLOBALS['csrf']['key'], $time);
        // We could disable these 'weaker' checks if 'key' was set, but
        // that doesn't make me feel good then about the cookie-based
        // implementation.
		
        case 'user':
            if (!csrf_get_secret()) return false;
            if ($GLOBALS['csrf']['user'] === false) return false;
            return $value === csrf_hash($GLOBALS['csrf']['user'], $time);
        
		case 'ip':
            if (!csrf_get_secret()) return false;
            // do not allow IP-based checks if the username is set, or if
            // the browser sent cookies
            if ($GLOBALS['csrf']['user'] !== false) return false;
            if (!empty($_COOKIE)) return false;
            if (!$GLOBALS['csrf']['allow-ip']) return false;
            return $value === csrf_hash($_SERVER['IP_ADDRESS'], $time);
    }
    return false;
}

/**
 * Sets a configuration value.
 */
function csrf_conf($key, $val) {
    if (!isset($GLOBALS['csrf'][$key])) {
        trigger_error('No such configuration ' . $key, E_USER_WARNING);
        return;
    }
    $GLOBALS['csrf'][$key] = $val;
}

function csrf_start() {
    if ($GLOBALS['csrf']['auto-session'] && !session_id()) {
        session_start();
    }
}

function csrf_get_secret() {
    if ($GLOBALS['csrf']['secret']) return $GLOBALS['csrf']['secret'];
    $dir = dirname(__FILE__);
    $file = $dir . '/csrf-secret.php';
    $secret = '';
    if (file_exists($file)) {
        include $file;
        return $secret;
    }
    if (is_writable($dir)) {
        $secret = csrf_generate_secret();
        $fh = fopen($file, 'w');
        fwrite($fh, '<?php $secret = "'.$secret.'";' . PHP_EOL);
        fclose($fh);
        return $secret;
    }
    return '';
}

function csrf_generate_secret($len = 32) {
    $r = '';
    for ($i = 0; $i < 32; $i++) {
        $r .= chr(mt_rand(0, 255));
    }
    $r .= time() . microtime();
    return sha1($r);
}

function csrf_hash($value, $time = null) {
    if (!$time) $time = time();
    return sha1(csrf_get_secret() . $value . $time) . ',' . $time;
}

// Load user configuration
if (function_exists('csrf_startup')) csrf_startup();

// Initialize our handler
if ($GLOBALS['csrf']['rewrite'])     ob_start('csrf_ob_handler');

// Perform check
if (!$GLOBALS['csrf']['defer'])      csrf_check();
