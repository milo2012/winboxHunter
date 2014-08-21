winboxHunter
============

If you are working on a penetration test remotely, its sometimes hard to determine when the users start work or connect their laptops to the network.

winboxHunter is useful if you have managed to capture and cracked a bunch of NTLM credentails and want to run Metasploit against these windows boxes as and when they are connected to the network.

winboxHunter listens for broadcast packets so that when a new winBox is connected to the network, it will use the Impacket scripts (psexec.py and wmiexec.py) to push an executable onto the winBox and runs it.

In the background, winboxHunter runs Metasploit with payload handler (multi/handler) and listens for incoming connections.
- See meterpreter.rc and autorunCmd.rc for more details.

![alt tag](https://raw.githubusercontent.com/milo2012/winboxHunter/master/screenshot.png)

