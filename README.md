# stomp_digity
Stomp_digity.py takes in the name of an Nmap grepable result file and (optionally) the name of the desired excel .xls output file. 
It parses the portscan file, extracts information about open ports, OS guesses, FQDN, etc. and then populates the excel spreadsheet. 
Perfect for easy cut-n-pasting into reports.

Requirements:

OpenPyXL

Type pip install openpyxl in windows command prompt

Usage example:

C:\>stomp_digity.py nmapresults.gnmap


