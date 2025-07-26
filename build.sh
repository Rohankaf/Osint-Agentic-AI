#!/bin/bash

echo " Building Docker image: osint-agent ..."
docker build -t osint-agent .

echo "Build complete!"
