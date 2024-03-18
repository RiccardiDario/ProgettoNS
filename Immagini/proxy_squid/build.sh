#!/bin/bash

docker build -t proxy_squid .

docker run --privileged -t proxy_squid



