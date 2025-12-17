# This is a pentesting tool designed for ethical use only.
# - This tool must only be used where premision has been given for security testing.

# Import modules.
from concurrent.futures import ThreadPoolExecutor
from sys import argv
import datetime
import ipaddress
import socket
import time

# Defining main function.
def main():

    # Check if the user has entered any command line arguements or not.
    if len(argv) == 1:

        # print title
        print(
            " - - - - - - - - - - - - - - - - \n"
            "Port Scanner\n"
        )

        # Ask the user to choose a scan option while doing input validation.
        while True:
            print(
                "Enter the number for the type of scan you want:\n"
                "1. Range Scan\n"
                "2. Specific Scan"
            )
            scanType = input("= ")

            # Check which option the user choose.
            if scanType == "1":

                # Get the IP address the user wants to scan.
                print(
                    "\nEnter the IP address:"
                )
                address = getIP()

                # Get the first port number.
                print(
                    "\n"
                    "Enter the first port number:"
                )
                firstPort = getPort()

                # Get the last port number.
                print(
                    "\n"
                    "Enter the last port:"
                )

                # Check if the last port is larger than the first number. If its not, ask the user again.
                while True:
                    lastPort = getPort()

                    if lastPort > firstPort:
                     break
                    
                    else:
                        print("The last port must be larger than the first port")
                        lastPort = getPort()

                # Ask the user for the ammount of threads they want to use.
                threads = getThreads()

                # Run range scan funtion
                rangeScan(address, firstPort, lastPort, threads)
                break

            # If the user chooses to run a specific port scan:
            elif scanType == "2":

                # Get the IP address the user wants to scan.
                print(
                    "\nEnter the IP address:"
                )
                address = getIP()

                # Get the port number.
                print(
                    "\n"
                    "Enter the port number:"
                )
                port = getPort()

                # Run specific scan function.
                specificScan(address, port)
                break

            # if the user enters an invalid option.
            else:
                print(
                    "\n"
                    "Invalid Option\n"
                )

    # If the user enters help, print the help menu.
    elif argv[1] == "-help":
        help()

    # If the user enters RangeScan:
    elif argv[1] == "RangeScan":

        # Check the user has entered all of the needed data. If not, print errer message.
        if len(argv) != 6:
            print(
                "\nMissing information. Use -help to find out more about formatting\n"
            )
            quit()
        
        # Get the needed data from the command line input.
        else:
            address = validateIP(argv[2])
            firstPort = validatePort(argv[3])
            lastPort = validatePort(argv[4])
            threads = validateThreads(argv[5])

            # Make sure that the first port is smaller than the last port. 
            if firstPort > lastPort or firstPort == lastPort:
                print(
                    "The first port must be smaller than the last port"
                )
                quit()
            else:
                # Run the RangeScan function.
                rangeScan(address, firstPort, lastPort, threads)
            

    # If the user chooses to run a Specific scan.
    elif argv[1] == "SpecificScan":

        # Check the user has entered all of the needed data. If not, print errer message.
        if len(argv) != 4:
            print(
                "\nMissing information. Use -help to find out more about formatting\n"
            )
            quit()
        
        # Get the needed data from the command line input.
        else:
            address = validateIP(argv[2])
            port = validatePort(argv[3])
            specificScan(address, port)
        




# Defining range scan function
def rangeScan(address, firstPort, lastPort, threads):

    # Set start time to measure how long the scan takes.
    startTime = time.time()

    # an array to store the open and closed ports.
    openPorts = []
    closedPorts = []

    # Scan each port using threading.
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

    # Get current time and calculate how long the scan took.
    totalTime = round(((time.time()) - startTime), 4)
    print(f"{totalTime} secs")

    # Ask the user if they want to save the scan.
    if input("Do you want to save results to a .txt file? (y/n):").lower() == 'y':
        logRangeScan(address, firstPort, lastPort, threads, openPorts, closedPorts, totalTime)


# Defining specific scan function
def specificScan(address, port):
    
    # Set start time to measure how long the scan takes.
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

    # Get current time and calculate how long the scan took.
    totalTime = round(((time.time()) - startTime), 4)
    print(f"{totalTime} secs")

    # Ask the user if they want to save the scan.
    if input("Do you want to save results to a .txt file? (y/n):").lower() == 'y':
        logSpecificScan(address, port, result, totalTime)


# Defining a single port scan for command line argument version.
def scanSinglePort(address, port):

    # check the port and print if the port is open or closed
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    result = sock.connect_ex((address, port))
    sock.close()
    return (port, result == 0)


# Get IP while validating input including checking if the IP address is valid.
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

# Get port nuber while validating the port number is a real port number.
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

# Get the amount threads the user wants to use and make sure uts a valid number.
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

        # Ask for the users input and if its invalid, ask the user again.
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
                "python3 ScannerV4 RangeScan IPaddress FirstPort LastPort Threads\n"
                "python3 ScannerV4 RangeScan 111.111.111.111 100 200 10\n\n"
                "For Specific port scan:\n"
                "python3 ScannerV4 SpecificScan IPaddress Port\n"
                "python3 ScannerV4 SpecificScan 111.111.111.111 200\n\n"
                "If you wish to save your scan, you can add Save to end of your input like such:\n"
                "python3 ScannerV4 SpecificScan IPaddress Port Save\n"
                "python3 ScannerV4 SpecificScan 111.111.111.111 200 Save\n\n"
            )
    

def validateIP(address):
    try:
        ipaddress.ip_address(address)
        return address
    except ValueError:
        print(
            "\n"
            "Invalid IP\n"
        )
        quit()
    

def validatePort(input):
    try:
        port = int(input)
        if port >= 0 and port <= 65535:
            return port
        else:
            print(
                "\nInvalid port"
            )
            quit()
    except ValueError:
        print(
            "\nInvalid Port\n"
        )
        quit()


def validateThreads(input):
    try:
        threads = int(input)

        if threads >= 1 and threads <= 200:
            return threads
        else:
            print(
                "\nInvalid amount of threads\n"
            )
            quit()

    except ValueError:
        print(
            "\nInvalid thread input\n"
        )
        quit()


main()
