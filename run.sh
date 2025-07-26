#!/bin/bash

CONTAINER_NAME="osint-container"

# Stop and remove existing container if exists
if [ "$(docker ps -aq -f name=$CONTAINER_NAME)" ]; then
    echo " Removing old container: $CONTAINER_NAME ..."
    docker rm -f $CONTAINER_NAME
fi

# Run new container
echo " Running new container..."
docker run -it -p 8000:8000 --name $CONTAINER_NAME osint-agent
