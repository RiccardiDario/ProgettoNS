#!/bin/bash
docker build -t external_firewall .
docker run --privileged -t external_firewall
