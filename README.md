# pynwconsole
Python netwitness/rsa security analytics binary protocol console

An attempt to re-create minimum protocol to be able to read /sdk/packets 

Example usage:

C:\Python26\python nwlogin.py  --from "2016-02-10 11:55:00" --to "2016-02-10 11:55:05" -s logdecoder:50004 -u admin -p netwitness --output foo2

Use "-" for output if you want to send to stdout
