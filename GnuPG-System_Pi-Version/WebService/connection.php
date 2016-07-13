<?php
$_link = mysql_connect($_config['host'], $_config['user'], $_config['password']);

if (!$_link){
	die("no connection to database possible: " . mysql_error());
	}

$_database = mysql_select_db($_config['database'], $_link);
if (!$_database){
	echo "not possible to use database: " . mysql_error();
    mysql_close($_link);      
    exit;                    
    }
?>
