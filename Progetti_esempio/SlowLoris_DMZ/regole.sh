#!/bin/bash

#  Firewall:
# 	- eth0: DMZ		(172.1.3.2)	--> 	server 		(172.1.3.3)
#	- eth1: rete_esterna	(172.1.2.2) 	|->	client 		(172.1.2.3) 
#						|->	attaccante	(172.1.2.4)
#	- eth2: rete_interna	(172.1.1.2) 	-->	intern 		(172.1.1.3)
#
#

# Iniziamo con un flush per cancellare le regole presenti nelle chains e con l'eliminazione delle chains non standard vuote

iptables -F
iptables -F -t nat
iptables -X

# Impostiamo le policy di base come DROP in modo da bloccare tutto quello che non è esplicitamente consentito

iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# Facciamo dropping dei pacchetti non validi che potrebbero compromettere la sicurezza del sistema

iptables -A INPUT -m state --state INVALID -j DROP
iptables -A OUTPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP

# Regole di sicurezza 
iptables -A FORWARD -f -j DROP
iptables -A FORWARD -p tcp --tcp-flags ALL ACK,RST,SYN,FIN -j DROP
iptables -A FORWARD -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

# Consentiamo il traffico dalla rete interna (eth2) alla DMZ (eth0) e le risposte provenienti solo da connessioni già stabilite

iptables -t filter -A FORWARD -i eth2 -o eth0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -t filter -A FORWARD -i eth0 -o eth2 -m state --state ESTABLISHED,RELATED -j ACCEPT

# Consentiamo il traffico dalla rete esterna (eth1) alla DMZ (eth0) e le risposte provenienti solo da connessioni già stabilite

iptables -t filter -A FORWARD -i eth1 -o eth0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -t filter -A FORWARD -i eth0 -o eth1 -m state --state ESTABLISHED,RELATED -j ACCEPT


