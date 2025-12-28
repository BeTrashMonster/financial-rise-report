# Agent Chat MCP Server

A NATS JetStream-based persistent chat system for agents, accessible via MCP (Model Context Protocol).

## Overview

This MCP server provides a Slack-like chat experience for AI agents using NATS JetStream for reliable, persistent messaging.

## Channels

- **roadmap** - Discuss project roadmap and planning
- **coordination** - Coordinate parallel work between agents
- **errors** - Report and discuss errors

## Features

- Persistent message storage (24 hour retention)
- Agent handles/usernames
- Multiple channels
- Message history retrieval
- Real-time subscriptions

## Prerequisites

1. **NATS Server with JetStream** must be running:

```bash
# Install NATS server
# macOS
brew install nats-server

# Or download from https://nats.io/download/

# Run with JetStream enabled
nats-server -js
```

2. **Node.js** (v18 or higher)

## Installation

```bash
cd agent-chat
npm install
```

## Configuration

The server is configured in `../mcp.json`. By default it connects to `nats://localhost:4222`.

To use a different NATS server, modify the `NATS_SERVER` environment variable in `mcp.json`.

## Available Tools

### `set_handle`
Set your agent handle/username for the chat.

**Parameters:**
- `handle` (string): Your agent handle (e.g., "project-manager", "code-reviewer")

### `get_handle`
Get your current agent handle.

### `list_channels`
List all available chat channels.

### `publish_message`
Send a message to a channel.

**Parameters:**
- `channel` (enum): One of "roadmap", "coordination", "errors"
- `message` (string): Your message content

### `read_messages`
Read recent messages from a channel.

**Parameters:**
- `channel` (enum): Channel to read from
- `limit` (number, optional): Max messages to retrieve (default: 20)

### `subscribe_channel`
Subscribe to live updates from a channel.

**Parameters:**
- `channel` (enum): Channel to subscribe to

## Usage Example

```javascript
// Set your handle first
set_handle({ handle: "project-manager" })

// Send a message
publish_message({
  channel: "coordination",
  message: "Starting work on authentication module"
})

// Read messages
read_messages({
  channel: "coordination",
  limit: 10
})

// Subscribe to updates
subscribe_channel({ channel: "errors" })
```

## Architecture

- **NATS JetStream** provides persistent storage and reliable delivery
- Each channel has its own stream (AGENT_CHAT_ROADMAP, AGENT_CHAT_COORDINATION, AGENT_CHAT_ERRORS)
- Messages are stored for 24 hours or up to 1000 messages per channel
- Storage is file-based for persistence across restarts

## Development

To run the MCP server directly:

```bash
node index.js
```

The server uses stdio transport for MCP communication.

## Agent Memory System

In addition to chat coordination, agents have a hierarchical memory system powered by the MCP memory server. See **[MEMORY-SYSTEM.md](./MEMORY-SYSTEM.md)** for complete documentation.

**Key Features:**
- **5 memory layers**: Core principles, Current task, Recent memory, Episodic memory, Memory compost
- **Auto-summarization**: Recent memories automatically summarized after 10 entries
- **5 pre-configured agents**: tdd-implementer, project-manager, business-analyst, requirements-reviewer, security-reviewer
- **Memory utilities**: Helper library in `memory-manager.js` for common operations

**Quick Example:**
```javascript
// Load agent memory
const nodes = await mcp__memory__open_nodes({ names: ["tdd-implementer"] });

// Add recent memory
await mcp__memory__add_observations({
  observations: [{
    entityName: "tdd-implementer",
    contents: ["[RECENT] Completed Work Stream 15 with 87% test coverage"]
  }]
});
```

## Troubleshooting

**"NATS connection failed"**
- Ensure NATS server is running with JetStream enabled: `nats-server -js`
- Check NATS_SERVER environment variable points to correct address

**"Handle not set"**
- Call `set_handle` before publishing messages

**"No messages in channel"**
- Channel may be empty, or this is the first message
- Check NATS server logs for issues
