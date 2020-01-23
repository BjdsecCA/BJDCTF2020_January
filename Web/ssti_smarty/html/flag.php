<!DOCTYPE html>
<html>
	<head>
		<title>
			The_mystery_of_ip
		</title>
		<meta charset="utf-8" name="viewport" content="width=device-width, initial-scale=1.0">
		<!-- Bootstrap -->
		<link href="bootstrap/css/bootstrap.min.css" rel="stylesheet" media="screen">
		<link href="css/shana_flag.css" rel="stylesheet" media="screen">
		<script src="jquery/jquery-3.3.1.min.js"></script>
		<script src="bootstrap/js/bootstrap.min.js"></script>

		<!-- HTML5 Shim and Respond.js IE8 support of HTML5 elements and media
        queries -->
        <!-- WARNING: Respond.js doesn't work if you view the page via file://
        -->
        <!--[if lt IE 9]>
            <script src="http://labfile.oss.aliyuncs.com/html5shiv/3.7.0/html5shiv.js">
            </script>
            <script src="http://labfile.oss.aliyuncs.com/respond.js/1.3.0/respond.min.js">
            </script>
        <![endif]-->
    </head>

    <?php
    	require_once('header.php');
		require_once('./libs/Smarty.class.php');
		$smarty = new Smarty();
		if (!empty($_SERVER['HTTP_CLIENT_IP'])) 
		{
		    $ip=$_SERVER['HTTP_CLIENT_IP'];
		}
		elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR']))
		{
		    $ip=$_SERVER['HTTP_X_FORWARDED_FOR'];
		}
		else
		{
		    $ip=$_SERVER['REMOTE_ADDR'];
		}
		//$your_ip = $smarty->display("string:".$ip);
		echo "<div class=\"container panel1\">
					<div class=\"row\">
					<div class=\"col-md-4\">	
					</div>
					<div class=\"col-md-4\">
					<div class=\"jumbotron pan\">
						<div class=\"form-group log\">
							<label><h2>Your IP is : ";
		$smarty->display("string:".$ip);
		echo "				</h2></label>
						</div>		
					</div>
					</div>
					<div class=\"col-md-4\">	
					</div>
					</div>
				</div>";
	?>

	</body>
</html>