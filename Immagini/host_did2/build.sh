#!/bin/bash

docker build -t host_did2 .

docker run --privileged -t host_did2

