#!/bin/bash

# Create log directory if it doesn't exist
mkdir -p /var/log/nginx

# Start Nginx in foreground
exec nginx -g "daemon off;"