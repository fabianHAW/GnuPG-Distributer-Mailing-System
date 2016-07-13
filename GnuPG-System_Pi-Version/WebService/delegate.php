<?php
putenv('PYTHONPATH=/home/pi/smtpserver/GnuPG-System_Pi-Version/:/usr/local/bin/python3.4');
putenv('PYTHON_EGG_CACHE=/home/pi/.python-eggs');

$py = 'python3.4 /home/pi/smtpserver/GnuPG-System_Pi-Version/WebService/WebInterface.py ';
$cmd = '';
if (isset($_POST['subscribe'])){
	$params = 'subscribe ' . $_POST['mailaddress'] . ' ' . $_POST['distributer'] . ' "' . $_POST['key'] . '"';
	$cmd =  $py . $params;
}
else if (isset($_POST['unsubscribe'])){
	$params = 'unsubscribe ' . $_POST['mailaddress'] . ' ' . $_POST['distributer'] . ' ' . $_POST['delete'];
	$cmd = $py . $params;
}
if ($cmd != ''){
	exec($cmd, $out);
	for ($i = 0; $i < sizeof($out); $i++) {
		echo "$out[$i] <br>";
	}
}
else{
	echo 'Something went wrong, please contact the administrator!';
}
header("refresh:5; url=entry.php" );
?>
