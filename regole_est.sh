#!/bin/bash

#  Firewall:
# 	- eth0: DMZ		(172.1.3.2)	--> 	server 		(172.1.3.3)
#	- eth1: rete_esterna	(172.1.2.2) 	|->	client 		(172.1.2.3) 
#						|->	attaccante	(172.1.2.4)
#	- eth2: rete_interna	(172.1.1.2) 	-->	intern 		(172.1.1.3)
#
#
					#SETTO I DUE FIREWALLS CON IPTABLES
##############################################################################################################################
#				Cancellazione delle regole presenti nelle chains		                             #
##############################################################################################################################
iptables -F
iptables -F -t nat

##############################################################################################################################
#				Eliminazione delle chains non standard vuote			                             #
##############################################################################################################################
iptables -X

##############################################################################################################################
#		Policy di base per firewall1 e firewall2 (blocco tutto quello che non è esplicitamente consentito)           #
##############################################################################################################################
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP


# Elimino pacchetti non validi 1 - VERIFICATO
iptables -A INPUT   -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP
iptables -A OUTPUT  -m state --state INVALID -j DROP

# Droppo pacchetti ip frammentati
iptables -A FORWARD -f -j DROP				


# Security  - VERIFICATO (SONO CONSIDERATI TUTTI PACCHETTI INVALIDI)
# Droppo pacchetti no-sense												
iptables -A FORWARD -p tcp --tcp-flags ALL ACK,RST,SYN,FIN -j DROP	
iptables -A FORWARD -p tcp --tcp-flags ALL ALL -j DROP
iptables -A FORWARD -p tcp --tcp-flags ALL NONE -j DROP
iptables -A FORWARD -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN,RST -j DROP


# Protezione Ip Spoofing
# Tutti i pacchetti che provengono dall'esterno e hanno source address interno vengono scartati
iptables -A FORWARD -s 192.1.3.0/24  -i eth0 -j DROP

# Protezione Syn Flood Attack 
# Creo nuova catena SYN_FLOOD

iptables -N SYN_FLOOD		
# Eseguo le regole della catena SYN_FLOOD se il pacchetto in ingresso è tcp e ha il flag syn = 1		
iptables -A FORWARD -p tcp --syn -j SYN_FLOOD		
# Il pacchetto viene fatto passare se rispetta i limiti prefissati
# Numero massimo di confronti al secondo (in media) = 1
# Numero massimo di confronti iniziali (in media) = 5 default
iptables -A SYN_FLOOD -m limit --limit 1/s -j RETURN
# Se non ha un match con la regola precedente il pacchetto viene scartato
iptables -A SYN_FLOOD -j DROP


# Protezione Ping of Death Attack
iptables -A FORWARD -j NFLOG --nflog-prefix="FORWARD Log pre-regola: "
iptables -N PING_OF_DEATH
iptables -A FORWARD -p icmp -j PING_OF_DEATH
# Accetto tutte le richieste se rispettano i limiti prefissati
iptables -A PING_OF_DEATH -p icmp --icmp-type echo-request -m limit --limit 1/s -j RETURN
# Se non ho un match con la regola di sopra il pacchetto va necessariamente scartato
iptables -A PING_OF_DEATH -p icmp --icmp-type echo-request -j DROP
iptables -A FORWARD -j NFLOG --nflog-prefix="FORWARD Log post-regola: "

# Droppo tutti i pacchetti provenienti dall'esterno e che hanno per ip destinazione quello di un host interno
iptables -t filter -A FORWARD -i eth0 -o eth2 -m state --state NEW,ESTABLISHED,RELATED -j DROP

# Evito UDP-flood Attacks
iptables -N UDP_FLOOD
iptables -A FORWARD -p udp -j UDP_FLOOD
iptables -A UDP_FLOOD -p udp -m limit --limit 1/s -j RETURN
iptables -A UDP_FLOOD -j DROP

# Accetto tutto il traffico diretto alla porta 53 protocollo udp
iptables -t filter -A FORWARD -i eth0 -o eth1 -p udp -d 192.1.2.3 --dport 53 -j ACCEPT
iptables -t filter -A FORWARD -i eth1 -o eth0 -p udp -j ACCEPT

# Droppo tutto il resto del traffico UDP
iptables -t filter -A FORWARD -i eth0 -o eth1 -p udp -j DROP

# Inoltro tutto il resto dei pacchetti provenienti dall'esterno (eth0) sull'interfaccia della DMZ (eth1)	                     
iptables -t filter -A FORWARD -i eth0 -o eth1 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -t filter -A FORWARD -i eth1 -o eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT

				#Natting da qualsiasi host della rete esterna dmz
##############################################################################################################################
#							1-Web Server				                  	     #
##############################################################################################################################
iptables -t nat -A PREROUTING -p tcp -i eth0 --dport 80 -j DNAT --to-dest 192.1.2.2
iptables -t nat -A PREROUTING -p tcp -i eth0 --dport 443 -j DNAT --to-dest 192.1.2.2

##############################################################################################################################
#							2-DNS Server				                  	     #
##############################################################################################################################
iptables -t nat -A PREROUTING -p udp -i eth0 --dport 53 -j DNAT --to-dest 192.1.2.3

##############################################################################################################################
#							3-FTP Server				                  	     #
##############################################################################################################################
iptables -t nat -A PREROUTING -p tcp -i eth0 --dport 21 -j DNAT --to-dest 192.1.2.4
iptables -t nat -A PREROUTING -p tcp -i eth0 --dport 20 -j DNAT --to-dest 192.1.2.4