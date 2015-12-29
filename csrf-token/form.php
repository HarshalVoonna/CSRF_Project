<?php
session_start();

include('tokengenerator.php');

$result="";

if ( isset( $_POST[ 'field' ] ) )
{
    $result = NoCSRF::check( 'csrf_token' );
}
else
{
    $result = 'Submit button not pressed.';
}

$token = NoCSRF::generate( 'csrf_token' );
?>


<h3><?php echo $result; ?></h3>

    <h2>Form with token protection</h2>

<form name="csrf_form" action="#" method="post">
	<input type="hidden" size="55px" name="csrf_token" value="<?php echo $token; ?>">
    Name <input type="text" name="field" value="name"><br/>
    <br/>
	<input type="submit" value="Send form"><br/>
</form>

<br/>
<br/>
<br/>

    <h2>Form without token protection</h2>

<form name="nocsrf_form" action="#" method="post">
	<input type="hidden" size="55px" name="csrf_token" value="No value">
    Name <input type="text" name="field" value="name"><br/>
	<br/>
    <input type="submit" value="Send form"><br/>
</form>
