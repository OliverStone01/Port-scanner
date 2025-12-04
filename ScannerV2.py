# This is a pentesting tool designed for ethical use only.
# - This tool must only be used where premision has been given for security testing.

# Importing modules
from concurrent.futures import ThreadPoolExecutor
import datetime
import ipaddress
import socket 

# Defining main function
def main():
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
            # Run range scan funtion
            rangeScan()
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


# Defining range scan function
def rangeScan():

    # Get IP address while validating input including checking if the IP address is valid or not
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
        "\n" \
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

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(scanSinglePort, address, port)
                   for port in range(firstPort, (lastPort + 1))]
        
        for future in futures:
            port, is_open = future.result()
            if is_open:
                print(f"Port {port} is open")
            else:
                print(f"Port {port} is closed")


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
    

    # check the port and print if the port is open or closed
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    result = sock.connect_ex((f"{address}", port))
    sock.close()

    if result == 0:
        print(
             "Port " + str(port) + " is open.\n"
        )
    
    else:
        print(
            "Port " + str(port) + " is closed.\n"
        )


def scanSinglePort(address, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    result = sock.connect_ex((address, port))
    sock.close()
    return (port, result == 0)

# Defining IP validation function
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

main()


# Get time of results
#    date = datetime.datetime.now()

# Print scan summary
#print(
#"\n"
#"Date: " + str(date) + "\n"
#"IP Address: " + address + "\n"
#"Port: " + str(port) + "\n"
#)