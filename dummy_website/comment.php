<?php 

function csrf_startup() {
    csrf_conf('rewrite-js', 'csrf-magic.js');
}

include dirname(__FILE__) . '/csrf-magic.php';

?>

<html lang="en">
<head>
	<meta charset="UTF-8">
	<title>Comment</title>
	<link rel="stylesheet" href="css/layout.css">
</head>
<body>
	<div class="header">
		<div class="logo">
			<img src="images/logo.png" alt="logo">
		</div>
		<div class="nav">
			<ul>
				<li><a href="home.html">Home</a></li>
				<li><a href="blog.html" >Blog</a></li>
				<li><a href="contact.html" >Contact</a></li>
				<li><a href="comment.html"  class="act">Comment</a></li>
			</ul>
		</div>
	</div>
	<div class="wrap">
		<div class="content">
			<h3>Comment</h3>
			<form action="" method="post" >
				<div class="form">

						<div class="item">
							<label for="name">Name<i>*</i>:</label>
							<input id="name" name="name" type="text"/>
						</div>
						<div class="item">
							<label for="email">Email<i>*</i>:</label>
							<input id="email" name="email" type="text"/>
						</div>

						<div class="item">
							<label for="comment">Comment:</label>
							<textarea id="comment" name="comment" ></textarea>
						</div>

				</div>
				<div class="save">
					<input type="submit" value="Submit" />
					<div class="tel">
					</div>
				</div>
			</form>
			
			<?php if ($_SERVER['REQUEST_METHOD'] == 'POST') { ?>
<p>Post data:</p>
<pre>
<?php echo htmlspecialchars(var_export($_POST, true)); ?>
</pre>	
<?php } ?>


		</div>
	</div>
	<div class="footer">
		<div class="info">
			<span class="fl">Copyright 2011-2013  All Right Reserved.</span>
			<span class="fr">Lorem ipsum dolor sit amet</span>
		</div>
	</div>

	<script src="libs/jquery-1.9.1.min.js"></script>
	<script>
		// 输入框placeholder
		window.onload = function() {
			var inputs = $('.wrap .content .form .hasHolder');
			for(var i=0;i<inputs.length;i++){
				$(inputs[i])
				.focus(function(){
					$(this).addClass('noPlaceholder');
				})
				.blur(function(){
					if($(this).val()=== ""){
						$(this).removeClass('noPlaceholder');
					}
				});
			}
		}
	</script>

</body>
</html>