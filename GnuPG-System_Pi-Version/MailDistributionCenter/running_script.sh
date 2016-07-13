#!/bin/bash

# (c) by Fabian Reiber 2016
# This script starts and stops the GnuPG-SMTP server. It is possible to start it as a background process
# or as a front process which blocks the console. 
#
# Parameters:
#				operation (start or stop)
#				running value (0 run as background process, or stop the background process; 1 run as front process)
#
# Possible commands to use: 
#						./running_script.sh start 0
#						./running_script.sh start 1
#						./running_script.sh stop 0

#--------------methods----------------------------
usage(){
	echo "START SERVER"
	echo "$0 <start> <0|1>"
	echo -e "\nSTOP SERVER"
	echo "$0 <stop> <0>"
	echo -e "\n0 for start/stop server in background"
	echo "1 for start server not in background"
}

stop_not_background(){
	echo "press CTRL+C to stop the server"
}

#--------------------------------------------------

RUN_SERVER="python3.4 GnuPGSMTP.py"
OPERATION=$1
RUNNING_VALUE=$2

case $OPERATION in 
	"start")
		#set PYTHON env path
		if [ -n ${PYTHONPATH+x} ]
			then
				PYTHONPATH=$PYTHONPATH:/home/pi/smtpserver/GnuPG-System_Pi-Version/
				export PYTHONPATH
		fi
		if [ $RUNNING_VALUE = 0 ]
			then
				#run in background
				$RUN_SERVER &
		elif [ $RUNNING_VALUE = 1 ]
			then
				#run in front
				stop_not_background
				$RUN_SERVER
		else
			usage
		fi
		;;
	"stop")
		if [ $RUNNING_VALUE = 0 ]
			then
				#kill running background server with SIGTERM
				kill -15 $(ps ax | grep "$RUN_SERVER" | head -1 | awk '{print$1}')
		else
			usage
		fi
		;;
	*)
		usage
		;;
esac
