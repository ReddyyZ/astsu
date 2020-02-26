# astsu

## How to use
First install the requiriments ``` pip install -r requirements.txt ```                                                                    
Then, install the astsu ``` python install.py ```. If you are in linux type ```chmod +x install.py ``` and ``` python install.py ```       
To use type ``` astsu ``` or ``` python astsu.py ```

## How it works
- ### Scan common ports
Send a TCP Syn packet to the destination on the defined port, if the port is open, use an nmap scan to check the service running on the port and prints all the ports found.

- ### Discover hosts in network
