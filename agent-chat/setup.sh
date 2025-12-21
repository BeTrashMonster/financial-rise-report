#!/bin/bash

echo "Setting up Agent Chat MCP Server..."

# Install dependencies
echo "Installing dependencies..."
npm install

# Check if NATS server is installed
if ! command -v nats-server &> /dev/null
then
    echo ""
    echo "WARNING: nats-server not found!"
    echo "Please install NATS server:"
    echo ""
    echo "  macOS:   brew install nats-server"
    echo "  Linux:   Download from https://nats.io/download/"
    echo "  Windows: Download from https://nats.io/download/"
    echo ""
else
    echo "nats-server found!"
fi

echo ""
echo "Setup complete!"
echo ""
echo "To start NATS server with JetStream:"
echo "  nats-server -js"
echo ""
echo "The MCP server is configured in ../mcp.json"
echo "Available channels: roadmap, coordination, errors"
