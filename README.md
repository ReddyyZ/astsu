# astsu

## How to use
First install the requiriments ``` pip install -r requirements.txt ```                                                                    
Then, install the astsu ``` python install.py ```. If you are in linux type ```chmod +x install.py ``` and ``` python install.py ```       
To use type ``` astsu ``` or ``` python astsu.py ```

## How it works
- ### Scan common ports
Send a TCP Syn packet to the destination on the defined port, if the port is open, use an nmap scan to check the service running on the port and prints all the ports found.

- ### Discover hosts in network
Uses as a base the router's ip to map all possible ips. It then sends an ICMP packet to each IP, and waits for a response, if it receives any response saved in an array the IP of the online host, and when it finishes checking all hosts, prints all hosts online.
