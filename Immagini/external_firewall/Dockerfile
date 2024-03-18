#
# Dockerfile: external firewall
#

FROM ubuntu:latest
LABEL maintainer ariccitiello "al.riccitiello@studenti.unina.it"

RUN apt-get update && apt-get install -y \
  bridge-utils \
  net-tools \
  iptables \
  iputils-ping \
  traceroute \
  nano \
  tcpdump \
  httpie

CMD echo "Firewall Esterno" && \
    iptables -L 
