winboxHunter
============
Prerequisites:
- Impacket (svn checkout http://impacket.googlecode.com/svn/trunk/ impacket-read-only)
- Ruby

If you are working on a penetration test remotely, its sometimes hard to determine when the users start work or connect their laptops to the network.

winboxHunter is useful if you have managed to capture and cracked a bunch of NTLM credentails and want to run Metasploit against these windows boxes as and when they are connected to the network.

winboxHunter listens for broadcast packets so that when a new winBox is connected to the network, it will use the Impacket scripts (psexec.py and wmiexec.py) to push an executable onto the winBox and runs it.

In the background, winboxHunter runs Metasploit with payload handler (multi/handler) and listens for incoming connections.
- See meterpreter.rc and autorunCmd.rc for more details.

Format of password.txt
- domain/username password

Instructions
- You can either supply your own meterpreter payload executable (payload=windows/meterpreter/reverse_https, rport=8443) using -e or --exe argument
- or you can use the -n or --enableVeil argument to generate a meterpreter payload executable using Veil Evasion

You can run winboxHunter using the below sample command
- ruby winboxHunter.rb -n -f password.txt -v

When you run winboxHunter, a linux screen with the name "msfscreen" will be created and msfconsole will be executed. You can connect to the screen via the below command
- screen -dr msfscreen

![alt tag](https://raw.githubusercontent.com/milo2012/winboxHunter/master/screenshot.png)

