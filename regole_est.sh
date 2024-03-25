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
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP


# Elimino pacchetti non validi 
iptables -A INPUT   -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP
iptables -A OUTPUT  -m state --state INVALID -j DROP

# Droppo pacchetti ip frammentati
iptables -A FORWARD -f -j DROP				


# Droppo pacchetti no-sense												
iptables -A FORWARD -p tcp --tcp-flags ALL ACK,RST,SYN,FIN -j DROP	
iptables -A FORWARD -p tcp --tcp-flags ALL ALL -j DROP
iptables -A FORWARD -p tcp --tcp-flags ALL NONE -j DROP
iptables -A FORWARD -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN,RST -j DROP


# Protezione Ip Spoofing
# Tutti i pacchetti che provengono dall'esterno e hanno source address interno vengono scartati
iptables -A FORWARD -s 172.1.1.0/24  -i eth1 -j DROP

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

# Blocca il forwarding del traffico dalla rete esterna alla rete interna
iptables -A FORWARD -i eth1 -o eth0 -d 172.1.1.0/24 -j DROP


# Evito UDP-flood Attacks
iptables -N UDP_FLOOD
iptables -A FORWARD -p udp -j UDP_FLOOD
iptables -A UDP_FLOOD -p udp -m limit --limit 1/s -j RETURN
iptables -A UDP_FLOOD -j DROP



# Droppo tutto il  traffico UDP
iptables -t filter -A FORWARD -i eth1 -o eth0 -p udp -j DROP

# Inoltro tutto il resto dei pacchetti provenienti dall'esterno (eth1) sull'interfaccia della DMZ (eth0)	                     
iptables -t filter -A FORWARD -i eth1 -o eth0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -t filter -A FORWARD -i eth0 -o eth1 -m state --state ESTABLISHED,RELATED -j ACCEPT

				#Natting da qualsiasi host della rete esterna dmz
##############################################################################################################################
#							1-Web Server				                  	     #
##############################################################################################################################
iptables -t nat -A PREROUTING -p tcp -i eth1 --dport 80 -j DNAT --to-dest 172.1.3.3
iptables -t nat -A PREROUTING -p tcp -i eth1 --dport 443 -j DNAT --to-dest 172.1.3.3

##############################################################################################################################
#							2-FTP Server				                  	     #
##############################################################################################################################
iptables -t nat -A PREROUTING -p tcp -i eth1 --dport 21 -j DNAT --to-dest 172.1.3.6
iptables -t nat -A PREROUTING -p tcp -i eth1 --dport 20 -j DNAT --to-dest 172.1.3.6

##############################################################################################################################
#							3-COWRIE HONEYPOT 				                  	     #
##############################################################################################################################
iptables -t nat -A PREROUTING -p udp -i eth1 --dport 2222 -j DNAT --to-dest 172.1.3.4

##############################################################################################################################
#							4-MAILONEY HONEYPOT				                  	     #
##############################################################################################################################
iptables -t nat -A PREROUTING -p udp -i eth1 --dport 25 -j DNAT --to-dest 172.1.3.5