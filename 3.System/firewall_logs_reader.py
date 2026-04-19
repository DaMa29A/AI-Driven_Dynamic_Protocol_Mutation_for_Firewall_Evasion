'''
su pfsense Status > System Logs > Settings
spunta su Remote log servers
in ip[:Port] mettere 192.168.10.10:1514   ossia ip kali
spunta su everything

Services > Suricata > Interfaces.
Clicca sulla matita per modificare la tua interfaccia.
in sezione Logging Settings spunta Send Alerts to System Log 
e Abbiamo forzato il Canale (Log Facility) su AUTH inve di Local 1.

Se non funzione vai in status>services e riavvia syslogd

sudo iptables -I OUTPUT -p icmp --icmp-type port-unreachable -d IP_DI_PFSENSE -j DROP
sudo iptables -I OUTPUT -p icmp --icmp-type port-unreachable -d 192.168.10.1 -j DROP
'''

import socket

HOST = "0.0.0.0"
PORT = 1514

def avvia_syslog_spugna():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    print(f"[*] In ascolto su UDP {PORT}... (In attesa di Suricata)")
    
    while True:
        data, addr = sock.recvfrom(4096)
        log_message = data.decode('utf-8', errors='ignore').strip()
        
        # Ignora i log noiosi del firewall per non intasare lo schermo
        if "filterlog" in log_message:
            continue
            
        # Stampa tutto il resto
        if "suricata" in log_message.lower():
            print("\n>>> LOG RICEVUTO:")
            print(log_message)
            print("-" * 30)

if __name__ == "__main__":
    avvia_syslog_spugna()