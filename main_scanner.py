import socket
import threading
import queue
import logging
import subprocess
import os

logging.basicConfig(filename='scanner_log.txt', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def send_packets(ip, port, result_list, semaphore, version_string, version_number):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, port))
        response = s.recv(4096)
        logging.info(f"{ip}: {response}")
        print(f"{ip}: {response}")

        with semaphore:
            if (version_number):
                if version_string.encode('utf-8') and version_number.encode('utf-8')in response:
                    result_list.append(ip)
            else:
                if version_string.encode('utf-8')in response:
                    result_list.append(ip)

        s.close()
    except Exception as e:
        with semaphore:
            logging.error(f"{ip}: {e}")

def worker(ip_queue, port_number, result_list, semaphore, version_string, version_number):
    while not ip_queue.empty():
        ip = ip_queue.get()
        send_packets(ip, port_number, result_list, semaphore, version_string, version_number)
        ip_queue.task_done()

def main():
    port_number = int(input('Please enter the port number: '))
    version_string = input('Please enter the version string that should be matched: ')
    version_number = input('Please enter the version int (Please, just type enter if no version number needed): ')
    ip = input('Please, enter IP or range (for full internet scan, enter 0.0.0.0/0. Please be aware that the less the rate the more accurate and the more time needed. at rate of 250,000 the scan will be end within 5 hours): ')
    rate = int(input('Enter scan rate: '))

    subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '6767', '-j', 'DROP'])

    masscan_output = f"masscan_{version_string}_{version_number}.txt"
    if ip=='0.0.0.0/0':
        subprocess.run(['masscan', ip, '--rate', str(rate), '--src-port', '6767', '-p', str(port_number), '--exclude 255.255.255.255' '-oG', masscan_output])
    else:
        subprocess.run(['masscan', ip, '--rate', str(rate), '--src-port', '6767', '-p', str(port_number), '-oG', masscan_output])

    if os.path.exists(masscan_output):
        print(f"Masscan output file {masscan_output} created.")
        with open(masscan_output, 'r') as f:
            content = f.read()
            print(f"Masscan output content:\n{content}")
    else:
        print(f"Masscan output file {masscan_output} not found!")
        return

    ips_output = f"{version_string}_{version_number}_ips.txt"
    grep_command = f"grep -o '[0-9]\\{{1,3\\}}\\.[0-9]\\{{1,3\\}}\\.[0-9]\\{{1,3\\}}\\.[0-9]\\{{1,3\\}}' {masscan_output} > {ips_output}"

    subprocess.run(grep_command, shell=True)

    if os.path.exists(ips_output):
        print(f"Grep output file {ips_output} created.")
        with open(ips_output, 'r') as f:
            all_ips = f.read().strip().split()
            print(f"Extracted IPs:\n{all_ips}")
            if not all_ips:
                print("No IPs found in grep output!")
                return
    else:
        print(f"Grep output file {ips_output} not found!")
        return


    semaphore = threading.Semaphore(1000)
    result_list = []
    ip_queue = queue.Queue()

    with open(ips_output, 'r') as ips:
        all_ips = ips.read().split()
        for ip in all_ips:
            ip_queue.put(ip)

    threads = []
    for _ in range(1000):
        thread = threading.Thread(target=worker, args=(ip_queue, port_number, result_list, semaphore, version_string, version_number))
        thread.start()
        threads.append(thread)

    ip_queue.join()  

    for thread in threads:
        thread.join()
    print(f"Final result list:\n{result_list}")
    subprocess.run(['iptables', '-D', 'INPUT', '-p', 'tcp', '--dport', '6767', '-j', 'DROP'])





if __name__ == "__main__":
    main()
