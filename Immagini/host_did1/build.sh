#!/bin/bash

docker build -t host_did1 .

docker run --privileged -t host_did1

