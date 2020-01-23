<?php
	//session_start();
	if(isset($_SESSION['login']))
	{
		//require_once('function.php');
		$_SESSION = array();
	    session_destroy();
	    setcookie('user', null);
	    Header("Location: flag.php");
	}
	else
	{
		echo "<script>alert('你干嘛！QAQ');history.go(-1);</script>";
	}
?>