<h1 align="center"> astsu </h1>
<p align="center">
  <a href="https://www.python.org/downloads/release/python-373/"><img src="https://img.shields.io/badge/python-3.7-blue"></a>
  <a href="https://youtube.com/c/fantasmanosistema"><img src="https://img.shields.io/badge/made%20by-ReddyyZ-red"></a>
  <a href="https://github.com/ReddyyZ/astsu/issues"><img src="https://img.shields.io/github/issues/ReddyyZ/astsu"></a>
  <a href="https://github.com/ReddyyZ/astsu/releases/latest"><img src="https://img.shields.io/github/release-date/ReddyyZ/astsu"></a>
  <a href="https://discord.gg/v5d3PZ9"><img src="https://img.shields.io/discord/704882848364101763"></a>
  <img src="https://img.shields.io/github/repo-size/ReddyyZ/astsu">
</p>

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
    - Done!
  - Windows
    - [Python 3, download and install](https://www.python.org/downloads/)
    - ``` python3 -m pip install -r requirements.txt ```
    - ``` python3 install.py ```
    - Done!

## Arguments
-sC | Scan common ports                                                                                                                 
-sA | Scan all ports
- -sO | Scan OS
  - -i | Interface to use in the scan
-sP | Scan defined port
- -d | Discover hosts in the network
  - -p | Protocol to use in the scan
  - -i | Interface to use in the scan
