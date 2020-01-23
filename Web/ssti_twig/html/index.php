<!DOCTYPE html>
<html>
	<head>
		<title>
			Cookie_is_so_subtle!
		</title>
		<meta charset="utf-8" name="viewport" content="width=device-width, initial-scale=1.0">
		<!-- Bootstrap -->
		<link href="bootstrap/css/bootstrap.min.css" rel="stylesheet" media="screen">
		<link href="css/shana_index.css" rel="stylesheet" media="screen">
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

    <?php require_once('header.php'); ?>

		<h1 id="typetitle" class="post-title poststyle" itemprop="name headline">Welcome to BJDCTF 2020</h1>
		<script>
			var typingbefore = document.getElementById("typetitle").innerText;//获取标题内容
            document.getElementById('typetitle').innerText = "";//将标题内容赋值为空
            var i = 0;
            function typetitle(){
                var typingafter = document.getElementById('typetitle');//获取标题元素
                if(i <= typingbefore.length){
                    typingafter.innerHTML = typingbefore.slice(0,i++)+'|';//将标题内容通过slice()方法返回
                    setTimeout('typetitle()',100);//每100毫秒执行一次
                }else{
                    typingafter.innerHTML = typingbefore;//当标题内容全部返回后，去掉最后的‘|’
                }
            }
            typetitle();
		</script>
