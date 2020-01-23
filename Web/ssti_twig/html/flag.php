<!DOCTYPE html>
<html>
	<head>
		<title>
			Cookie_is_so_subtle!
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
		//session_start();
    	require_once('header.php');
		if(!isset($_SESSION['login'])) //没有提交信息
		{
			echo '<div class="container panel1">
					<div class="row">
					<div class="col-md-4">	
					</div>
					<div class="col-md-4">
					<div class="jumbotron pan">
						
						<form id="form1" method="post" accept-charset="utf-8" autocomplete="off" role="form" action="flag.php">
							<div class="form-group log">
		    					<label><h2>Tell me, Who are you?</h2></label>
		  					</div>
							<div class="form-group">
		    					<label for="username">ID</label>
		    					<input type="text" class="form-control" id="username" name="username" placeholder="Username">
		  					</div>
		  		
							<div class="row pt-3">
								<div class="col-md-12">
		  							<button type="submit" form="form1" name="submit" value="submit" class="btn btn-default float-right" >Submit</button>
		  						</div>
		  					</div>
						</form>		
					</div>
					</div>
					<div class="col-md-4">	
					</div>
					</div>
				</div>';
			if(isset($_POST["submit"]) && $_POST["submit"] == "submit")
			{	
				$user = trim($_POST["username"]);
				if( $user == "")
				{
					echo "<script>alert('请确认信息完整性！');history.go(-1);</script>";
				}
				else
				{
					$user = htmlspecialchars($user);
					$_SESSION['user'] = $user;
					$_SESSION['login'] = 1;
					setcookie('user', $_SESSION['user'],time()+(60*30));
		            $home_url = "flag.php";
		            header("Location: ".$home_url);
				}
			}
			/*else if($_POST['token'] !== $_SESSION['token'])
			{
				echo "<script>alert('你好坏！qwq');history.go(-1);</script>";
			}*/
		}
		else
		{
			//echo "<script>alert('您已提交信息，请勿重复提交！');history.go(-1);</script>";
			//$home_url = "index.php";
		    //header("Location: ".$home_url);
		    echo '<div class="container panel1">
					<div class="row">
					<div class="col-md-4">	
					</div>
					<div class="col-md-4">
					<div class="jumbotron pan">';
			include 'vendor/twig/twig/lib/Twig/Autoloader.php';
			Twig_Autoloader::register();
			$loader = new Twig_Loader_String();
			$twig = new Twig_Environment($loader);
			/*if(empty($_COOKIE['user'])){
				$result = $twig->render("guest");
			}else{
				$result = $twig->render($_COOKIE['user']);
			}*/
			try{
				$result = @$twig->render($_COOKIE['user']);
				echo "  <div class=\"form-group log\">
							<label><h2>Hello $result</h2></label>
						</div> ";
			} catch (Exception $e){
				echo "  <div class=\"form-group log\">
							<label><h2>What do you want to do?!</h2></label>
		  			    </div> ";
			}
			echo '	<div class="row pt-3">
						<div class="col-md-12">
		  					<a href="logout.php"><button type="submit" form="form1" name="Logout" value="logout" class="btn btn-default float-right" >Logout</button></a>
		  				</div>
		  			</div>
							
					</div>
					</div>
					<div class="col-md-4">	
					</div>
					</div>
				</div>';
		}
	?>

	</body>
</html>