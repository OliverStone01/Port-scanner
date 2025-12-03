# Port scanner

> 🛠️ notice:
> Scanner V2 is still under production and currently only range scan is available. Scanner V2 will include threading which allows you to preform quicker port scans.

This is a simple TCP port scanner I designed for ethical penetration testing and cybersecurity studying. This tool can preform specific port scans or it can scan a range of ports.

> ⚠️ This tool was build for ethical use only!  
> This tool must only be used to scan networks you have written premision to test.

### Features:
- Scan a range of ports on a target IP
- Scan a specific port
- Validates IP address and port numbers
- Display time stamps for scans
- Ho external dependencies

### Requirements:
This project only uses pythons standard library.
- python 3.8+

### Usage:
To run this script, make sure you are in the same directory and run:
```
Python3 scanner.py
```
You will then be prompted to choose a type of scan:
1. Range Scan
2. Specific port scan

Then you will be propted to enter a:
- Valid IP address
- One or more port numbers depending on what type of scan you choose.

### Example output:
```
- - - - - - - - - - - - -
Port Scanner

Choose scan type:
1. Range Scan
2. Specific Scan
= 1

Enter IP address:
= 192.168.1.10

Enter first port number:
= 20

Enter last port number:
= 25

Date: 2025-01-01 12:34:56.789123
IP: 192.168.1.10
Port Range: 20 - 25

Port 20 is closed.
Port 21 is open.
Port 22 is open.
Port 23 is closed.
Port 24 is closed.
Port 25 is closed.
```





