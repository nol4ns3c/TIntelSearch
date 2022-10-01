import sys
import socket
from datetime import datetime

#ip='18.158.98.109'
def portscan(ip):
    portlist = []
    scanport = [21,22,23,25,80,110,143,443,1337,445,3389,8080]
    for port in scanport:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)

        # returns an error indicator
        result = s.connect_ex((ip, port))

        if result == 0:
            portlist.append(port)

        s.close()

    return portlist
