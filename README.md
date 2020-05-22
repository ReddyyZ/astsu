<h1 align="center"> astsu </h1>

## How it works
- ### Scan common ports
Send a TCP Syn packet to the destination on the defined port, if the port is open, use an nmap scan to check the service running on the port and prints all the ports found.

- ### Discover hosts in network
Uses as a base the router's ip to map all possible ips. It then sends an ICMP packet to each IP, and waits for a response, if it receives any response saved in an array the IP of the online host, and when it finishes checking all hosts, prints all hosts online.

- ### OS Scan
Sends an ICMP packet to the destination and waits for a response. Then, extracts the TTL from the destination response and checks the possible OS in a list, if have founded, prints it.

## How to install
Clone this repository
``` git clone https://github.com/ReddyyZ/astsu.git ```                                                                                    
- Install python 3.
  - Linux
    - ``` apt-get install python3 ```
    - ``` python3 -m pip install -r requirements.txt ```
    - ``` python3 install.py ```
    Done!
  - Windows
    - [Python 3, download and install](https://www.python.org/downloads/)
    - ``` python3 -m pip install -r requirements.txt ```
    - ``` python3 install.py ```
    - Done!
