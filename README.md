# Etekcity
Command line control of Etekcity devices.

Currently just for the VeSyncOutlet7A


**USAGE:Vesync [deviceName] [option] [-l login] [-p password]**

with no arguments reads device info from site and saves to devices.json

deviceName is the name from the app

option is one of

-h print this help

-l login

-p password

if -l or -p is used they override and replace what is in the Etekcity.properties file

-on send turn on

-off send turn of

-reset send turn off, pause 20 seconds, then send turn on

