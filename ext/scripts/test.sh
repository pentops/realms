#!/bin/bash

docker compose -f docker-compose.test.yaml up --build --remove-orphans --abort-on-container-exit test