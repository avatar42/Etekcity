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

Note [Vesync-full-0.0.1-SNAPSHOT.jar](https://github.com/avatar42/Etekcity/blob/main/Releases/Vesync-full-0.0.1-SNAPSHOT.jar) created adds current directory to the classpath so the Etekcity.properties file can be read from there if not packaged with the jar. Obviously the one in the [Releases](https://github.com/avatar42/Etekcity/tree/main/Releases) folder does not contain an Etekcity.properties since that would publicly reveal my login info.
