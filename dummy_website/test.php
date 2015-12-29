<?php 

function csrf_startup() {
    csrf_conf('rewrite-js', 'csrf-magic.js');
}

include dirname(__FILE__) . '/csrf-magic.php';

?>

<html lang="en">
<head>
<title>Test page for csrf-magic</title>
</head>
<body>
<h1>Test page for csrf-magic</h1>
<p>
  This page might be vulnerable to CSRF, but never fear: csrf-magic is here!
</p>

<?php if ($_SERVER['REQUEST_METHOD'] == 'POST') { ?>
<p>Post data:</p>
<pre>
<?php echo htmlspecialchars(var_export($_POST, true)); ?>
</pre>	
<?php } ?>

<form action="" method="post">
  Form field: <input type="text" name="foobar" /><br />
  <input type="submit" value="Submit" />
</form>

<FORM METHOD = "POST" ACTION="">
  Another form field! <INPUT TYPE="TEXT" NAME="BARFOO" /><BR />
  <INPUT TYPE="SUBMIT" value="Submit 2" />
</FORM>

<form action="" method="post">
  This form fails CSRF validation (we cheated and overrode the CSRF token
  later in the form.) <br />
  <input type="text" name="foobar[2]" />
  <input type="submit" name="__csrf_magic" value="invalid" />
</form>

<form action="" method="get">
  This form uses GET and is thus not protected.
  <input type="submit" name="foo" value="Submit" />
</form>

</body>
</html>
