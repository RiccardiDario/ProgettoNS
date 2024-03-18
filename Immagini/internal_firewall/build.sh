#!/bin/bash
docker build -t internal_firewall .
docker run --privileged -t internal_firewall
