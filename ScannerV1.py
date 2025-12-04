# This is a pentesting tool designed for ethical use only.
# - This tool must only be used where premision has been given for security testing.

# Importing modules
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

    # Ask user for the IP address while validating input including checking if the IP address is valid or not
    while True:
        print(
            "\n"
            "Enter IP address:"
        )
        address = input("= ")

        # Check if the IP address is a valid IP address
        if isValidIP(address) == True:

            # Ask the user for the first port number while validating input
            while True:
                print(
                    "\n"
                    "Enter first port number:"
            )
                try:
                    firstPort = int(input("= "))

                    # Check that the port number is a valid port number
                    if firstPort >= 0 and firstPort <= 65534:

                        # Ask the user for the second port number while validating input.
                        while True:
                            print(
                                "\n"
                                "Enter the last port number:"
                            )
                            try:
                                lastPort = int(input("= "))

                                # Check the last port is greater than the first port
                                if lastPort < firstPort:
                                    print(
                                        "\n"
                                        "Last port cannot be smaller than first port"
                                    )

                                # Check that last port is a valid port
                                elif lastPort >= 1 and lastPort <65535:
                                     
                                    # Get time of results
                                    date = datetime.datetime.now()

                                    # Print scan summary
                                    print(
                                        "\n"
                                        "Date: " + str(date) + "\n"
                                        "IP Address: " + address + "\n"
                                        "Port Range: " + str(firstPort) + "~" + str(lastPort) + "\n"
                                    )

                                    # check each port in range and print if the port is open or closed
                                    for port in range(firstPort, (lastPort + 1)):
                                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                        sock.settimeout(0.5)
                                        result = sock.connect_ex((f"{address}", port))
                                        sock.close()
                                    
                                        if result == 0:
                                            print(
                                                "Port " + str(port) + " is open."
                                            )
                                        else:
                                            print(
                                                "Port " + str(port) + " is closed."
                                            )
                                    break
                                
                                # If the user enters an invalid port
                                else:
                                    print(
                                        "\n"
                                        "Invalid port"
                                    )

                            # If the user enters an invalid port
                            except ValueError:
                                print(
                                    "\n"
                                    "Invalid port"
                                )
                        break
                        
                    # If the user enters an invalid port
                    else:
                        print(
                            "\n"
                            "Invalid port"
                        )

                # If the user enters an invalid port
                except ValueError:
                    print(
                        "\n"
                        "Invalid port"
                        )



            break
        # If user enters an invalid IP address
        else:
            print(
                "\n"
                "Invalid IP"
            )

# Defining specific scan function
def specificScan():

    # Ask user for the IP address while validating input including checking if the IP address is valid or not
    while True:
        print(
            "\n"
            "Enter IP address:"
        )
        address = input("= ")

        # Check if the IP address is a valid IP address
        if isValidIP(address) == True:

            # Ask the user for the port number while validating input
            while True:
                print(
                    "\n"
                    "Enter the port number:"
                )
                try:
                    port = int(input("= "))

                    # Check the port is a valid port
                    if port >=0 and port <=65535:

                        # Get time of results
                        date = datetime.datetime.now()

                        # Print scan summary
                        print(
                            "\n"
                            "Date: " + str(date) + "\n"
                            "IP Address: " + address + "\n"
                            "Port: " + str(port) + "\n"
                        )

                        # check the port and print if the port is open or closed
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.5)
                        result = sock.connect_ex((f"{address}", port))
                        sock.close()

                        if result == 0:
                            print(
                                "Port " + str(port) + " is open.\n"
                            )
                            break
                        else:
                            print(
                                "Port " + str(port) + " is closed.\n"
                            )
                            break

                    # If the user enters an invalid port    
                    else:
                        print(
                            "\n"
                            "Invalid port\n"
                        )
                
                # If the user enters an invalid port
                except ValueError:
                    print(
                        "\n"
                        "Invalid port\n"
                    )

            break
        # If user enters an invalid IP address            
        else:
            print(
                "\n"
                "Invalid IP"
            )

# Defining IP validation function
def isValidIP(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


main()
