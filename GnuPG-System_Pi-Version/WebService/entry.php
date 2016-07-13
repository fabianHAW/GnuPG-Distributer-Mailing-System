<?php
SESSION_START();

if ($_SESSION["login"] == 0){
	header("Location: index.html");
	exit;
} 
?>

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
  <head>
    <title>GnuPGDistributer</title>
    
    <meta http-equiv="content-type"
     content="text/html; charset=ISO-8859-1">
    
  </head>
<body text="#000000" bgcolor="#ffffee" link="#000099" vlink="#990099" alink="#000099">

<a href="logout.php">Logout</a>

<h4 align="center">
<form name ="subscribe" method="POST" action="delegate.php" >
  <fieldset>
    <legend>Subscribe</legend>
    <table>
      <tr>
        E-Mail: <input name="mailaddress" maxlength="255">
        Distributer: <input name="distributer" value=
        <?php
			echo $_SESSION["distAddr"];
        ?> 
        readonly="readonly"><br>
        <h4 align="center">PGP-Key:</h4> <textarea name="key" rows="20" cols="66"></textarea> <br>
        <input type="hidden" name="subscribe" value="subscribe">
        <input type="submit" value="Submit">
      </tr>
    </table>
  </fieldset>
</form>
</h4>

<h4 align="center">
<form name ="unsubscribe" method="POST" action="delegate.php" >
  <fieldset>
    <legend>Unsubscribe</legend>
    <table>
      <tr>
        E-Mail: <input name="mailaddress" maxlength="255">
        Distributer: <input name="distributer" value=
        <?php
			echo $_SESSION["distAddr"];
		?> 
		readonly="readonly"><br>
        Delete Key From Server? 
        <input type="radio" id="yes" name="delete" value=1><label for="yes">Yes</label> 
        <input type="radio" id="no" name="delete" value=0 checked><label for="no">No</label> 
        <input type="hidden" name="unsubscribe" value="unsubscribe">
        <input type="submit" value="Submit">
      </tr>
    </table>
  </fieldset>
</form>
</h4>

</body>
</html>
