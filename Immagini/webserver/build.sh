#!/bin/bash

docker build -t webserver .

docker run --privileged -t webserver

