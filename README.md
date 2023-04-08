# soc_checker.sh
Centre for Cybersecurity Project

Mission:

One of the biggest challenges in managing SOC teams is keeping the teams alerted. An incident that is not properly managed can bring an organization great damage.
Creating an automatic attack system will allow the SOC manager to check the team's vigilance.

Objective:

An automatic program to be used by the SOC Manager. The script will allow the Administrator to choose different types of attacks.

Usage:
	
		bash soc_checker.sh
		
Attack Options:
	
[1] Nmap Scan   (Discover and map network devices and services)

[2] Brute-force Login Credentials   (Guessing login credentials repeatedly)
  
[3] Man-in-the-Middle Attack   (Intercepting communication between two points)
  
[4] Denial-of-Service Attack   (Flooding network or system to disrupt service)
  
[5] Reverse Shell (Target: Windows OS)  (Infiltrating a target system via Malicious Payload)
  
[6] Zero Logon Attack Test on Domain Controller   (Testing a vulnerability CVE-2020-1472)

Note:

1) Results will be saved as 'soc_checker_results.txt' in current folder.
2) Activity will be logged at '/var/log/soc_checker.log'.
