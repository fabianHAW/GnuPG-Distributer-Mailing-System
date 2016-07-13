# GnuPG-Distributer-Mailing-System for Raspberry Pi

## License
This project is under MIT License. You find it [here] (https://github.com/fabianHAW/GnuPG-Distributer-Mailing-System/LICENSE.md).

## Description
This implementation is a GnuPG mailing distributer system written in Python 3.4. It encrypts and signs e-mails with the GnuPG-standard. 
Received e-mails to a distributer address will be re-encrypted by the system for every member on the distributer with the specific public key.
The server was implemented and tested for a Raspberry Pi 2 model B with the OS Raspbian GNU/Linux Version 7 (wheezy). 

There are some e-mail subject commands to trigger the behavoir of a distributer:
- ADDTODIST - add an e-mail address to the distributer in the e-mail header
- CHANGEPK - change the public key of an e-mail address which is on the distributer in the e-mail header
- GETPK - get the public keys of the distributer in the e-mail header
- DELFROMDIST - delete the e-mail address from the distributer in the e-mail header
This e-mails don't need content (only the one of the four subjects), need to be signed and must not be encrypted. 
An administrator also can add and delete user to/from a distributer by using the web service interface. 

E-mails for the distributer members need to be signed and encrypted with the specific public key of the distributer. The system decrypt and verify the e-mail. If everything is right, it catch all the public keys from the members by using the SKS key server. After it, the system signs and encrypts every e-mail with the particular public key and send it to the members.

If something went wrong, the system sends a specific e-mail to the sender.

## Requirements
OS packages:
- python3.4
- gnupg2
- apache2
- mysql-server
- libmysqlclient-dev
- php5
- php5-mysql 
- sks

Python 3.4 libraries:
- gnupg
- mysqlclient
- requests
- dnspython3
- netifaces

## Before starting
Before using the system, you need to create a database with a distributer address and a strong password. After it you need to modify the **.db_conf.cnf** file in *DistributerManagement*.
Create a directory for the GnuPG-keyrings and configure the paths in **GnuPGManager.py**. The are also some paths you may configure in **DistributerManager.py**, **GnuPGSystemLogger.py**, **.log.conf** and **delegate.php**.
For the web service you also need to configure the database connection in the **config.php** file in *WebService*. 

## How to start

*********************************

START/STOP SERVER WITH THE BASH-SCRIPT IN *MailDistributionCenter*

running_script.sh

*********************************

USAGE OF SCRIPT:

START SERVER
./running_script.sh <start> <0|1>

STOP SERVER
./running_script.sh <stop> <0>

0 for start/stop server (which is running) in background
1 for start server not in background

*********************************
