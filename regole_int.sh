#!/bin/bash

					#SETTO Il FIREWALL CON IPTABLES
##############################################################################################################################
#				Cancellazione delle regole presenti nelle chains		                             #
##############################################################################################################################
iptables -F

##############################################################################################################################
#				Eliminazione delle chains non standard vuote			                             #
##############################################################################################################################
iptables -X

##############################################################################################################################
#		Policy di base per il firewall (blocco tutto quello che non è esplicitamente consentito)           #
##############################################################################################################################
# Elimino pacchetti non validi 
iptables -A INPUT -m state --state INVALID -j NFLOG --nflog-prefix="Rule number: 1 "
iptables -A INPUT -m state --state INVALID -j DROP

iptables -A FORWARD -m state --state INVALID -j NFLOG --nflog-prefix="Rule number: 2 "
iptables -A FORWARD -m state --state INVALID -j DROP

iptables -A OUTPUT  -m state --state INVALID -j NFLOG --nflog-prefix="Rule number: 3"
iptables -A OUTPUT  -m state --state INVALID -j DROP


# Droppo pacchetti ip frammentati
iptables -A FORWARD -f -j NFLOG --nflog-prefix="Rule number: 4"
iptables -A FORWARD -f -j DROP				


# Droppo pacchetti no-sense	
iptables -A FORWARD -p tcp --tcp-flags ALL ACK,RST,SYN,FIN -j NFLOG --nflog-prefix="Rule number: 5"												
iptables -A FORWARD -p tcp --tcp-flags ALL ACK,RST,SYN,FIN -j DROP	

iptables -A FORWARD -p tcp --tcp-flags ALL ALL -j NFLOG --nflog-prefix="Rule number: 6"	
iptables -A FORWARD -p tcp --tcp-flags ALL ALL -j DROP

iptables -A FORWARD -p tcp --tcp-flags ALL NONE -j NFLOG --nflog-prefix="Rule number: 7"
iptables -A FORWARD -p tcp --tcp-flags ALL NONE -j DROP

iptables -A FORWARD -p tcp --tcp-flags SYN,FIN SYN,FIN -j NFLOG --nflog-prefix="Rule number: 8"
iptables -A FORWARD -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN,RST -j NFLOG --nflog-prefix="Rule number: 9"
iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN,RST -j DROP


# Protezione Syn Flood Attack 
# Creo nuova catena SYN_FLOOD

iptables -N SYN_FLOOD		
# Eseguo le regole della catena SYN_FLOOD se il pacchetto in ingresso è tcp e ha il flag syn = 1		
iptables -A FORWARD -p tcp --syn -j SYN_FLOOD		
# Il pacchetto viene fatto passare se rispetta i limiti prefissati
# Numero massimo di confronti al secondo (in media) = 1
# Numero massimo di confronti iniziali (in media) = 5 default
iptables -A SYN_FLOOD -m limit --limit 1/s -j NFLOG --nflog-prefix="Rule number: 10"
iptables -A SYN_FLOOD -m limit --limit 1/s -j RETURN
# Se non ha un match con la regola precedente il pacchetto viene scartato
iptables -A SYN_FLOOD -j NFLOG --nflog-prefix="Rule number: 11"
iptables -A SYN_FLOOD -j DROP


# Protezione Ping of Death Attack

iptables -N PING_OF_DEATH
iptables -A FORWARD -p icmp -j PING_OF_DEATH
# Accetto tutte le richieste se rispettano i limiti prefissati
iptables -A PING_OF_DEATH -p icmp --icmp-type echo-request -m limit --limit 1/s -j NFLOG --nflog-prefix="Rule number: 12"
iptables -A PING_OF_DEATH -p icmp --icmp-type echo-request -m limit --limit 1/s -j RETURN
# Se non ho un match con la regola di sopra il pacchetto va necessariamente scartato
iptables -A PING_OF_DEATH -p icmp --icmp-type echo-request -j NFLOG --nflog-prefix="Rule number: 13"
iptables -A PING_OF_DEATH -p icmp --icmp-type echo-request -j DROP



# Evito UDP-flood Attacks
iptables -N UDP_FLOOD
iptables -A FORWARD -p udp -j UDP_FLOOD

iptables -A UDP_FLOOD -p udp -m limit --limit 1/s -j NFLOG --nflog-prefix="Rule number: 14"
iptables -A UDP_FLOOD -p udp -m limit --limit 1/s -j RETURN

iptables -A UDP_FLOOD -j NFLOG --nflog-prefix="Rule number: 15"
iptables -A UDP_FLOOD -j DROP


# Droppo tutto il  traffico UDP
iptables -t filter -A FORWARD -i eth1 -o eth0 -p udp -j NFLOG --nflog-prefix="Rule number: 16"
iptables -t filter -A FORWARD -i eth1 -o eth0 -p udp -j DROP


# Inoltro tutto il resto dei pacchetti provenienti dall'interno (eth1) sull'interfaccia della DMZ (eth0)
iptables -t filter -A FORWARD -i eth1 -o eth0 -m state --state NEW,ESTABLISHED,RELATED -j NFLOG --nflog-prefix="Rule number: 17"	                     
iptables -t filter -A FORWARD -i eth1 -o eth0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

iptables -t filter -A FORWARD -i eth0 -o eth1 -m state --state ESTABLISHED,RELATED -j NFLOG --nflog-prefix="Rule number: 18"
iptables -t filter -A FORWARD -i eth0 -o eth1 -m state --state ESTABLISHED,RELATED -j ACCEPT

# Droppo tentativi di connessione rete interna - rete esterna
iptables -A FORWARD -d 172.1.2.0/24 -j NFLOG --nflog-prefix="Rule number: 19"
iptables -A FORWARD -d 172.1.2.0/24 -j DROP