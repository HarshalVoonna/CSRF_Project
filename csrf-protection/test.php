<?php 

include dirname(__FILE__) . '/csrf-magic.php';

?>

<html lang="en">
<head>
<title>Test page for csrf-magic</title>
</head>
<body>
<h1>Test page for csrf-magic</h1>

<?php if ($_SERVER['REQUEST_METHOD'] == 'POST') { ?>
<p>Post data:</p>
<pre>
<?php echo htmlspecialchars(var_export($_POST, true)); ?>
</pre>	
<?php } ?>

<form action="" method="post">
  Form field: <input type="text" name="name_field" /><br />
  <input type="submit" value="Submit" />
</form>


<form action="" method="post">
  This form fails CSRF validation (we overrode the CSRF token
  later in the form.) <br />
  <input type="text" name="foobar" />
  <input type="submit" name="__csrf_magic" value="invalid" />
</form>

<form action="" method="get">
  This form uses GET and is thus not protected.
  <input type="submit" name="foo" value="Submit" />
</form>

</body>
</html>
