<?php
    ob_start();
    function get_hash(){
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()+-';
        $random = $chars[mt_rand(0,73)].$chars[mt_rand(0,73)].$chars[mt_rand(0,73)].$chars[mt_rand(0,73)].$chars[mt_rand(0,73)];//Random 5 times
        $content = uniqid().$random;
        return sha1($content); 
    }
    header("Content-Type: text/html;charset=utf-8");
    echo '<!DOCTYPE html>
    <html>
    <head>
    <meta charset="utf-8">
    <title>Login</title>
    <meta http-equiv="Content-Type" content="text/html;charset=UTF-8">
    <meta name="viewport" content="width=device-width">
    <link href="public/css/base.css" rel="stylesheet" type="text/css">
    <link href="public/css/login.css" rel="stylesheet" type="text/css">
    </head>
    <body>';

    if(isset($_POST['username']) and $_POST['username'] != '' )
    {
        // $_POST['username'];
        $admin = '6d0bc1';
        // 14795508
        if ( $admin == substr(md5($_POST['password']),0,6)) {
            echo "<script>alert('[+] Welcome to manage system')</script>";
            $file_shtml = "public/".get_hash().".shtml";
            $shtml = fopen($file_shtml, "w") or die("Unable to open file!");
            $text = '<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>Document</title>
            </head>
            <body>
                <h1>Hello,'.$_POST['username'].'</h1>
                <br>
                <h2>data: <!--#echo var="DATE_LOCAL"--></h2>
                <br>
                <h2>Client IP: <!--#echo var="REMOTE_ADDR"--></h2>
            </body>
            </html>';
            fwrite($shtml,$text);
            fclose($shtml);
            // echo 'File：',$file_shtml;
            header("Url_Is_Here:".$file_shtml);
            echo "[!] Header  error ...";

        } else {
            echo "<script>alert('[!] Failed')</script>";
            echo '<div class="login">
        <form action="index.php" method="post" id="form">
            <div class="logo"></div>
            <div class="login_form">
                <div class="user">
                    <input class="text_value" value="" name="username" type="text" id="username" placeholder="username">
                    <input class="text_value" value="" name="password" type="password" id="password" placeholder="password">
                </div>
                <button class="button" id="submit" type="submit">submit</button>
            </div>';
        }
    }else
    {
        echo '<div class="login">
        <form action="index.php" method="post" id="form">
            <div class="logo"></div>
            <div class="login_form">
                <div class="user">
                    <input class="text_value" value="" name="username" type="text" id="username" placeholder="username">
                    <input class="text_value" value="" name="password" type="password" id="password" placeholder="username">
                </div>
                <button class="button" id="submit" type="submit">登录</button>
            </div>';
    }
    echo '            <div id="tip"></div>
    <div class="foot">
    bjd.cn
    </div>
    </form>
</div>';
?>
</body>
</html>