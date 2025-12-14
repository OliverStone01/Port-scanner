# This is a pentesting tool designed for ethical use only.
# - This tool must only be used where premision has been given for security testing.

# Importing modules
from concurrent.futures import ThreadPoolExecutor
from sys import argv
import datetime
import ipaddress
import socket
import time

# Defining main function
def main():

    if len(argv) == 1:
        # Title
        print(
            " - - - - - - - - - - - - - - - - \n"
            "Port Scanner\n"
        )

        # Ask the user to choose a scan option while doing input validation
        while True:
            print(
                "Enter the number for the type of scan:\n"
                "1. Range Scan\n"
                "2. Specific Scan"
            )
            scanType = input("= ")

            # Check which option the user chose
            if scanType == "1":

                # Validate IP address
                print(
                    "\nEnter the IP address:"
                )
                address = getIP()

                # Get the first port number
                print(
                    "\n"
                    "Enter the first port number:"
                )
                firstPort = getPort()

                # Get the second port while making sure its larger than the first port
                print(
                    "\n"
                    "Enter the last port:"
                )
                while True:
                    lastPort = getPort()
                    if lastPort > firstPort:
                     break
                    
                    else:
                        print("Last port must be larger than the first port")
                        lastPort = getPort()

                # Get the amount of threads
                threads = getThreads()

                # Run range scan funtion
                rangeScan(address, firstPort, lastPort, threads)
                break

            elif scanType == "2":
                # Run specific scan function
                specificScan()
                break

            # if the user entered an invalid option
            else:
                print(
                    "\n"
                    "Invalid Option\n"
                )
    elif argv[1] == "-help":
        help()

    else:
        if ipaddress.ip_address(argv[1]) == True:
            address == argv[1]
            
            try:
                ipaddress.ip_address(address)
                return address
            except ValueError:
                print(
                    "\n"
                    "Invalid IP"
                )
                quit

        else:









# Defining range scan function1

def rangeScan(address, firstPort, lastPort, threads):

    startTime = time.time()

    openPorts = []
    closedPorts = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(scanSinglePort, address, port)
                   for port in range(firstPort, (lastPort + 1))]
        
        for future in futures:
            port, is_open = future.result()
            if is_open:
                openPorts.append(port)
                print(f"Port {port} is open")
            else:
                closedPorts.append(port)
                print(f"Port {port} is closed")

    totalTime = round(((time.time()) - startTime), 4)
    print(f"{totalTime} secs")

    if input("Do you want to save results to a .txt file? (y/n):").lower() == 'y':
        logRangeScan(address, firstPort, lastPort, threads, openPorts, closedPorts, totalTime)




# Defining specific scan function
def specificScan():

    # Get IP address while validating input including checking if the IP address is valid or not
    print(
        "\nEnter the IP address:"
    )
    address = getIP()

    # Get port number
    print(
        "\n"
        "Enter port number:"
    )
    port = getPort()
    
    startTime = time.time()

    # check the port and print if the port is open or closed
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    result = sock.connect_ex((f"{address}", port))
    sock.close()

    if result == 0:
        print(
             "\nPort " + str(port) + " is open.\n"
        )
    
    else:
        print(
            "\nPort " + str(port) + " is closed.\n"
        )

    totalTime = round(((time.time()) - startTime), 4)
    print(f"{totalTime} secs")

    if input("Do you want to save results to a .txt file? (y/n):").lower() == 'y':
        logSpecificScan(address, port, result, totalTime)




def scanSinglePort(address, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    result = sock.connect_ex((address, port))
    sock.close()
    return (port, result == 0)

# Get IP while validating input including checking if the IP address is valid or not
def getIP():
    while True:
        try:
            address = input("= ")
            ipaddress.ip_address(address)
            return address
        except ValueError:
            print(
                "\n"
                "Invalid IP"
            )


def getPort():
    while True:
        try:
            port = int(input("= "))

            if port >= 0 and port <= 65535:
                return port
            else:
                print(
                    "\nInvalid port, try again"
                )
        except ValueError:
            print(
                "\nInvalid port, try again"
            )


def getThreads():
    while True:
        print(
            "Enter the amount of threads you wish to use.\n"
            "For example:\n"
            "Max speed (200 threads)\n"
            "Safe (50 threads)\n"
            "Stealth (10 threads)\n"
            "Individual (single thread)\n"
        )
        try:
            threads = int(input("= "))

            if threads >= 1 and threads <= 200:
                return threads
            else:
                print(
                    "Invalid amount of threads"
                )
        except ValueError:
            print(
                "Invalid amount of threads"
            )

def logRangeScan(address, firstPort, lastPort, threads, openPorts, closedPorts, scanTime):
    filename = datetime.datetime.now().strftime("portScan_%Y-%m-%d_%H-%M-%S.txt")

    with open(filename, 'w') as file:
        file.write("=" * 50 + "\n")
        file.write("PORT SCANNER LOG\n")
        file.write("=" * 50 + "\n\n")
        file.write(f"Target IP: {address}\n")
        file.write(f"Port Range: {firstPort} - {lastPort}\n")
        file.write(f"Threads Used: {threads}\n")
        file.write(f"Scan Duration: {scanTime} secs\n")
        file.write("=" * 50 + "\n")
        if openPorts:
            file.write("OPEN PORTS:\n")
            for port in openPorts:
                file.write(f"   - Port {port}\n")
            
            file.write("\n")
        else:
            file.write("No open ports found\n\n")
        file.write("=" * 50 + "\n")
        

def logSpecificScan(address, port, result, scanTime):
    filename = datetime.datetime.now().strftime("portScan_%Y-%m-%d_%H-%M-%S.txt")

    with open(filename, 'w') as file:
        file.write("=" * 50 + "\n")
        file.write("PORT SCANNER LOG\n")
        file.write("=" * 50 + "\n\n")
        file.write(f"Target IP: {address}\n")
        file.write(f"Port: {port}\n")
        file.write(f"Scan Duration: {scanTime} secs\n")
        file.write("=" * 50 + "\n")
        if result == 0:
            file.write(f"Port {port} is open\n")
        else:
            file.write(f"Port {port} is closed\n")
        file.write("=" * 50 + "\n\n")


def help():
    print(
                "\nPort scanner\n\n"
                "To run the port scanner with propts, run 'python3 ScannerV4.py'\n"
                "Otherwise you can use commnd line arguments:\n\n"
                "For Range scan:\n"
                "python3 ScannerV4 -RangeScan -IPaddress -FirstPort -LastPort\n"
                "python3 ScannerV4 -RangeScan -111.111.111.111 -100 -200\n\n"
                "For Specific port scan:\n"
                "python3 ScannerV4 -SpecificScan -IPaddress -Port\n"
                "python3 ScannerV4 -SpecificScan -111.111.111.111 -200\n\n"
                "If you wish to save your scan, you can add -Save to end of your input like such:\n"
                "python3 ScannerV4 -SpecificScan -IPaddress -Port -Save\n"
                "python3 ScannerV4 -SpecificScan -111.111.111.111 -200 -Save\n\n"
            )


main()
