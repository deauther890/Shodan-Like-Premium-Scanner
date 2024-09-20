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
    filename=input('Please enter file name: ')

    # Now continue with the threading part
    semaphore = threading.Semaphore(7000)
    result_list = []
    ip_queue = queue.Queue()

    
    print("Current Working Directory:", os.getcwd())


    with open(filename, "r") as ips:
        all_ips = ips.read().split()
        for ip in all_ips:
            ip_queue.put(ip)

    threads = []
    for _ in range(7000):
        thread = threading.Thread(target=worker, args=(ip_queue, port_number, result_list, semaphore, version_string, version_number))
        thread.start()
        threads.append(thread)

    ip_queue.join()  # Wait until all tasks are done

    for thread in threads:
        thread.join()
    print(f"Final result list:\n{result_list}")
 





if __name__ == "__main__":
    main()