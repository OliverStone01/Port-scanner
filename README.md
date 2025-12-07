# Port scanner

#### Current version: V3

This is a simple TCP port scanner I designed for ethical penetration testing and cybersecurity studying. This tool can preform specific port scans or it can scan a range of ports.

> ⚠️ This tool was build for ethical use only!  
> This tool must only be used to scan networks you have written premision to test.

### Features:
- Scan a range of ports on a target IP
- Scan a specific port
- Validates IP address and port numbers
- Display time stamps for scans
- Using threading to improve range scan speeds
- Able to save scans as a text file

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
- The level of threading

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

Enter the amount of threads you wish to use.
For example:
Max speed (200 threads)
Safe (50 threads)
Stealth (10 threads)
Individual (single thread)

= 10

Port 20 is closed.
Port 21 is open.
Port 22 is open.
Port 23 is closed.
Port 24 is closed.
Port 25 is closed.
```





