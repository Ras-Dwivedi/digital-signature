#!/bin/bash

if [[ $1 == "stop" ]]; then
    docker compose -f ./docker-compose.yaml down
else
  if [[ $1 == "dev" ]]; then
    echo "####################################################################"
    echo "                  Connecting to Development server"
    echo "####################################################################"
    export ESIGNER_PORT=9000
  else
    echo "####################################################################"
    echo "                  Connecting to Staging server"
    echo "####################################################################"
    export ESIGNER_PORT=9000
  fi

  mvn clean package
  if [ $? -ne 0 ]; then
      echo "####################################################################"
      echo "   Error: Failed to build the jar. Exiting .."
      echo "####################################################################"
      exit 1

  fi
#    docker build -t eSigner .
    docker compose -f docker-compose.yaml build
    docker compose -f docker-compose.yaml up -d
    echo "####################################################################"
    echo "                        Successfully Deployed"
    echo "####################################################################"
    docker ps -a
fi

