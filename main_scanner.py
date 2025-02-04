
import socket
import  threading
import queue
import logging
import subprocess
import os
import json
import re
import requests

logging.basicConfig(filename='scanner_log.txt', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_nmap_service_probes(file_path):
    """Parses the nmap-service-probes file and organizes into a 2D dictionary by port."""
    service_probes = {}
    current_port = None
    current_payload = None
    payload_followup = False  # Control variable for multi-line payloads
    null_probe = {"NULL": {"": {"matches": [], "protocol": "tcp"}}}  # Initialize Null probe

    try:
        with open(file_path, 'rb') as file:
            for line in file:
                line = line.decode('utf-8', errors='ignore').strip()  # Decode and ignore errors

                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue

                # Detect the start of a probe
                if "##############################NEXT PROBE##############################" in line:
                    current_port = None
                    current_payload = None
                    continue

                if line.startswith("Probe "):
                    parts = line.split()
                    protocol = parts[1]
                    payload = " ".join(parts[3:])
                    current_payload = payload

                    # If this is the first probe, consider it part of the null probe
                    if not service_probes and current_port is None:
                        null_probe["NULL"][""]["protocol"] = protocol

                    # Extract port information from the `ports` directive
                    if current_port is not None:
                        service_probes.setdefault(current_port, {})[current_payload] = {"matches": [], "protocol": protocol}
                    payload_followup = not payload.endswith("|")

                elif payload_followup:
                    current_payload += line
                    if line.endswith("|"):
                        payload_followup = False

                # Detect ports directive
                elif line.startswith("ports "):
                    ports = line.split(" ", 1)[1].split(",")
                    for port in ports:
                        # Handle port ranges like 1040-1043
                        if "-" in port:
                            start, end = map(int, port.split("-"))
                            for expanded_port in range(start, end + 1):
                                current_port = expanded_port
                                if current_port not in service_probes:
                                    service_probes[current_port] = {}
                                if current_payload not in service_probes[current_port]:
                                    service_probes[current_port][current_payload] = {
                                        "matches": [],
                                        "protocol": protocol
                                    }
                        else:
                            # Single port case
                            current_port = int(port.strip())
                            if current_port not in service_probes:
                                service_probes[current_port] = {}
                            if current_payload not in service_probes[current_port]:
                                service_probes[current_port][current_payload] = {
                                    "matches": [],
                                    "protocol": protocol
                                }
#match pop3 m|^\+OK POP3 \[([-\w_.]+)\] v([\d.]+) server ready\r\n| p/UW Imap pop3d/ v/$2/ h/$1/ cpe:/a:uw:imap_toolkit:$2/
                # Detect match entries
                elif line.startswith("match "):
                    match_parts = line.split(" ", 2)
                    
                    regex = re.search(r'm\|(.+?)\|', match_parts[2])
                    full_service=re.search(r'p\/(.+?)\/', match_parts[2])
                    version = re.search(r'v\/(.+?)\/', match_parts[2])
                    #print(full_service.group(1))
                    match_data = {
                        "service": match_parts[1],
                        "full_service": full_service.group(1) if full_service else None,
                        "version": version.group(1) if version else None,
                        "regex": regex.group(1) if regex else None,
                        "info": match_parts[2]
                        
                    }
                    #print(match_data["full_service"])

                    if current_port and current_payload:
                        service_probes[current_port][current_payload]["matches"].append(match_data)
                    else:
                        null_probe["NULL"][""]["matches"].append(match_data)  # Add to null probe matches
    except Exception as e:
        print(f"Error reading file: {e}")

    # Merge null_probe into the main service_probes dictionary
    service_probes.update(null_probe)
    return service_probes

def hex_payload(payload):
    """Convert a payload string from nmap probes to raw bytes."""
    payload = payload.replace('\\x', '').replace('\\0', '00').replace("q|", "").replace("|", "")
    
    try:
        return bytes.fromhex(payload)
    except ValueError:
        return payload.encode('latin1', errors='ignore')  # Handle as raw bytes
def scan_service(ip, port, protocol, payload, matches):
    """Send a single payload and check matches."""

    
    try:
        raw_payload = hex_payload(payload)
        #print(raw_payload)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol.lower() == "tcp" else socket.SOCK_DGRAM)
        s.settimeout(5)
        s.connect((ip, port))
        s.sendall(raw_payload)
        response = s.recv(4096).decode('latin1', errors='ignore')
        s.close()

        # Check matches
        for match in matches:
            
            try:
                regex = match.get("regex")
            
                if regex :
                    match_result=re.search(regex, response)
                    if match_result:
                        
                        version=match.get("version")
                        if version and "$" in version:
                         
                            for i in range(1, len(match_result.groups()) + 1):
                                version = version.replace(f"${i}", match_result.group(i))
                        version=version or match.get("version")
                        #print("Version",version)
                        print(f"{ip}:{port} -> Service: {match['service']}, full_service: {match['full_service']}, Version: {version} ")
                        logging.info(f"{ip}:{port} -> Service: {match['service']}, full_service: {match['full_service']}, Version: {version} ")
                        return ip
                    
            except re.error as regex_error:
                print(f"Regex error for {ip}:{port}: {regex_error}")
    except Exception as e:
        print(f"Error scanning {ip}:{port} - {e}")
        return None
    return None
def worker(ip_queue, service_probes, results):
    """Worker thread to process each IP and port."""
    
    while not ip_queue.empty():
        ip, port = ip_queue.get()
       

        # Process null probe first
        if "NULL" in service_probes:
            null_details = service_probes["NULL"][""]
            result = scan_service(ip, port, null_details["protocol"], "", null_details["matches"])
            if result != None:
                results.append(result)
                ip_queue.task_done()
                continue  # Skip further scanning if null probe matches

        # Process regular probes for this port

        
        
        if port in service_probes:
            for payload, details in service_probes[port].items():
            
                result = scan_service(ip, port, details["protocol"], payload, details["matches"])
                if result:
                    results.append(result)
                    break  # Stop sending more payloads for this port if a match is found

        ip_queue.task_done()
def start_scanner( port_to_other_ips,service_probes, max_threads=1000):
    """Scans the target IPs and ports using threading and queue."""
    ip_queue = queue.Queue()
    results = []

    # Populate the queue with IP and port pairs

    
    for port, ips in port_to_other_ips.items():
        for ip in ips:
            ip_queue.put((ip, int(port)))

    # Create and start threads
    
    threads = []
    for _ in range(max_threads):
        thread = threading.Thread(target=worker, args=(ip_queue, service_probes, results))
        thread.start()
        threads.append(thread)

    # Wait for all threads to complete
    ip_queue.join()
    for thread in threads:
        thread.join()
    return results

def extract_masscan_banners_and_other_ips(input_file, output_file, ports):
    try:
        with open(input_file, 'r') as file:
            masscan_data = json.load(file)
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    results = []
    other_ips=[]

    for entry in masscan_data:
        ip = entry.get("ip")
        port = entry.get("ports", [{}])[0].get("port")
        banner = entry.get("data", {}).get("banner", "")

        # Check if the port is in the desired list and banner exists
        if ip and port in ports and banner:
            results.append(f"{ip}:{port}:{banner.strip()}")
        else:
            other_ips.append(f"{ip}:{port}")


    # Write the results to the output file
    try:
        with open(output_file, 'w') as file:
            file.write("\n".join(results))
        print(f"Filtered results written to {output_file}")
    except Exception as e:
        print(f"Error writing to file: {e}")
        #This represent the ips that aren't scanned with banners.
    try:
        with open('other_ips.txt', 'w') as file:
            file.write("\n".join(other_ips))
        print(f"Filtered results written to {output_file}")
    except Exception as e:
        print(f"Error writing to file: {e}")


def main():

    
    version_scanner_ips=[]
    version_scanner_ports=[]

    #is_file_scan=False

    file_name=input('Please enter the name for list scan (otherwise, leave it empty): ')

    port_number_range = input('Please enter the port number or range: ')
    version_string = input('Please enter the version string that should be matched: ')
    version_number = input('Please enter the version int (otherwise, leave it empty): ')
    ip = input('Please, enter IP or range. leve it empty if already entered file scan (for full internet scan, enter 0.0.0.0/0. Please be aware that the less the rate the more accurate and the more time needed. at rate of 250,000 the scan will be end within 5 hours): ')
    rate = input('Enter scan rate: ')

    subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '6767', '-j', 'DROP']) #This will create a new rule to drop RST packets that are generetd by the kernel

    masscan_output = f"masscan_{version_string}_{version_number}.txt"

  


    if file_name:
        subprocess.run(['masscan', '-iL', file_name, '--rate', rate, '--banners', '--src-port', '6767', '-p', port_number_range, '-oJ', masscan_output])
    
    else:

        if ip=='0.0.0.0/0': #Internet wide scan
            subprocess.run(['masscan', ip, '--rate', rate, '--banners', '--src-port', '6767', '-p', port_number_range, '--exclude 255.255.255.255' '-oJ', masscan_output])
        else:
            subprocess.run(['masscan', ip, '--rate', rate, '--banners', '--src-port', '6767', '-p', port_number_range, '-oJ', masscan_output])
    
    masscan_spported_ports = [21, 80, 143, 110, 25, 22, 443, 445, 23, 3389, 5900] #Supported ips by masscan to be skipped by the service scanner of the script.

    #This code will extract the banners that are already out by masscan and will put other ips withh ports that are not scanned by masscan.
    extract_masscan_banners_and_other_ips( masscan_output, 'masscan_filtered.txt', masscan_spported_ports)

    port_to_other_ips={}
    if os.path.exists(masscan_output):
        print(f"Masscan output file {masscan_output} created.")

        #This file was created for other ips that needs to be scanned by the version scanner. 
        with open('other_ips.txt', 'r') as file:
        
            other_ips=file.readlines()
        #This will fill the dictionary called "port to other ips" to be read by the version scanner part.
        for line in other_ips:
            if line.split(':')[1].strip() in port_to_other_ips:
                port_to_other_ips[line.split(':')[1].strip()].append(line.split(':')[0].strip()) #This line append the ips to their respective ports
            else:
                port_to_other_ips[line.split(':')[1].strip()]=[line.split(':')[0].strip()] #This adds a new entry in the dictionary port_to_other_ips.
 
    else:
        print(f"Masscan output file {masscan_output} not found!")
        return
    #Gathering the ips to be scanned by version scanner and ports in a separate list
    for port in port_to_other_ips.keys():
        if port  in masscan_spported_ports: #If the ports in listed in the masscan ports and it's here, this means that some ips failed to get the benner from them and we don't want in this to scan the whole ip list because of just some or one ip.
            port_to_other_ips.pop(port_to_other_ips[port])

        else: #If the port is not suppported by masscan, it will be appended to the list of ports.
            version_scanner_ports.append(port)
   
    nmap_service_probes_path = "nmap-service-probes.txt"
    service_probes = parse_nmap_service_probes(nmap_service_probes_path)
    #Getting the results of the scanned ips by the version scanner.
    scan_results = start_scanner( port_to_other_ips, service_probes)
    
    print(f"Finished processing port {port}")

    print(f"Final result list:\n{scan_results}")
    subprocess.run(['iptables', '-D', 'INPUT', '-p', 'tcp', '--dport', '6767', '-j', 'DROP'])
main()  

