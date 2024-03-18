#!/bin/bash

docker build -t host_int2 .

docker run --privileged -t host_int2

