<?php
include ("config.php");
SESSION_START();
include("connection.php");

if (!empty($_POST["login"])){		
	$_distAddr = mysql_real_escape_string($_POST["distAddr"]);
    
	if (filter_var($_distAddr, FILTER_VALIDATE_EMAIL)) {
		$_passwordDistAddr = "SELECT passwd, salt FROM distributer WHERE
					address='$_distAddr'";
					
		$_query = mysql_query($_passwordDistAddr, $_link);
		$_result = @mysql_fetch_row($_query);
		
		$_password_salt = mysql_real_escape_string($_POST["password"]) . $_result[1];
		$_hash = hash('sha512', $_password_salt);
		
		if ($_result[0] == $_hash){
			$_SESSION["login"] = 1;
			$_SESSION["distAddr"] = $_distAddr;
			header("Location: entry.php");
        }
        else{
			$_SESSION["login"] = 0;
			echo "wrong password...redirect after 5 seconds...";
			header("refresh:5; url=index.html" );
			mysql_close($_link);
			exit;
        }
	}
	else{
		echo "distributeraddress is not a valid mail address...redirect after 5 seconds...";
		header("refresh:5; url=index.html" );
	}
}  

mysql_close($_link);
?>
