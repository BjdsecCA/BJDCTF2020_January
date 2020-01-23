<?php
header('hint:select * from \'admin\' where password='.'md5($pass,true)');
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        @media all and (min-width:600px) {
            * {
                /*改变width计算为包含边框和内间距*/
                box-sizing: border-box;
            }

            body {
                /*控制页面内容水平和垂直居中*/
                position: relative;
                display: flex;
                height: 550px;
                align-items: center;
                justify-content: center;
                background-size: cover;
                background-repeat: no-repeat;
            }

            /*container*/
            .container {
                border: rgba(240, 235, 235, 0.932) solid 3px;
                box-shadow: 10px 10px 10px rgba(173, 173, 173, 0.61);
                background-color: white;
                width: 30%;
                height: 20%;
                border-radius: 8px;
                position: relative;
            }

            /*container end*/

            /*header*/
            #header h1 {
                position: relative;
                text-align: center;
            }

            /*header end*/
            /*main*/
            .main {
                align-items: center;
                justify-content: center;
                position: relative;
                width: 100%;
                height: 100%;
            }

            .main section {
                width: 50%;
                margin-left: 22%;
            }

            .main section .upload {
                width: 400px;
            }

            .main section .upload .in{
                margin-top: 10%;
                border-radius:10px;
                font-size: 17px;
                color: rgba(44, 44, 44, 0.582);
                font-family: "Microsoft YaHei";
                border: rgba(240, 235, 235, 0.932) solid 3px;
                box-shadow: 10px 10px 10px rgba(173, 173, 173, 0.61);
                background-color: white;
            }

            .main section .upload .give{
                margin-left: 10px;
                border-radius:10px;
                color: rgba(44, 44, 44, 0.582);
                font-size: 17px;
                font-family: "Microsoft YaHei";
                border: white solid 3px;
                background-color: white;
            }

            /*main end*/
        }
    </style>
</head>

<body>
    <div class="container">
        <div id="header">
        </div><!-- /header end -->
        <div class="main">

            <section>
                <form class="upload" action="leveldo4.php" method="GET">
                    <input type="text" id="name" name='password' class="in">
                    <input type="submit" class="give">
                </form>
            </section>
        </div><!-- /main end -->

    </div><!-- /container end -->
    <script src="https://code.jquery.com/jquery-3.1.1.min.js"></script>
</body>

</html>



<?php
error_reporting(0);
$password = $_GET['password'];

if($password == 'ffifdyop')
{
    echo "<script>window.location.replace('./levels91.php')</script>";
}

?>





