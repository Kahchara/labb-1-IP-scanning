import nmap
import sys
scanner = nmap.PortScanner()

print("Welcome to my nmap tool :)")
print("---------------------------------------------------")
resp1 = input("""Would you like to type in the ip-adress or import it from a document?
                 1) Type in the adress
                 2) Import from a document\n""")

if resp1 == '1':
    ip_add_list = [input("Which IP would you like to scan?\n")]
elif resp1 == '2':
    doc_name = input('What is the name of the document you wish to scan?\n')
    try:
        with open(f"{doc_name}", "r") as file:
            ip_add_list = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"Error: The file '{doc_name}' was not found. Please check the file name and try again.")
        sys.exit()

print(f"IP Addresses: {ip_add_list}")

def validate_ports(ports):
    try:
        start, end = ports.split('-')
        start, end = int(start), int(end)
        if start > end:
            raise ValueError("Start port must be less than or equal to end port.")
        return True
    except ValueError:
        return False

resp2 = input("""\nWhat type of scan do you wish to run?
                1) SYN ACK Scan
                2) UDP Scan
                3) Comprehensive Scan\n""")
print("You have chosen option:", resp2)

ports = input("Which ports would you like to test? (start-end)\n")
while not validate_ports(ports):
    print("Invalid port range. Please try again.")
    ports = input("Which ports would you like to test? (start-end)\n")


with open('scan_results.txt', 'a') as file:
    for ip_add in ip_add_list:  
        file.write(f"\nScanning IP: {ip_add}\n") 

        if resp2 == '1':
            scanner.scan(ip_add, ports, '-v -sS')
        elif resp2 == '2':
            scanner.scan(ip_add, ports, '-v -sU')
        elif resp2 == '3':
            scanner.scan(ip_add, ports, '-v -sS -sU -sC')
        
        if ip_add in scanner.all_hosts():
            file.write(f"Ports Scanned: {ports}\n")
            file.write(f"IP Status: {scanner[ip_add].state()}\n")
            file.write(f"Protocols: {scanner[ip_add].all_protocols()}\n")
            
            if 'tcp' in scanner[ip_add]:
                file.write(f"Open TCP Ports: {list(scanner[ip_add]['tcp'].keys())}\n")
                for port, details in scanner[ip_add]['tcp'].items():
                    file.write(f"  Port {port}: {details}\n")
            else:
                file.write("No open TCP ports found.\n")
            
            if 'udp' in scanner[ip_add]:
                file.write(f"Open UDP Ports: {list(scanner[ip_add]['udp'].keys())}\n")
                for port, details in scanner[ip_add]['udp'].items():
                    file.write(f"  Port {port}: {details}\n")
            else:
                file.write("No open UDP ports found.\n")
                
        else:
            file.write(f"IP {ip_add} not found in scan results. Skipping...\n")
        if not scanner.all_hosts():
            file.write(f"No hosts found for IP {ip_add}. Skipping...\n")

print(f"Scanned IP: {ip_add}")
print("Scan results have been saved to 'scan_results.txt'")
