#!/usr/bin/env node
import { FastMCP } from 'fastmcp';
import { connect, StringCodec } from 'nats';
import { z } from 'zod';

const CHANNELS = ['roadmap', 'coordination', 'errors'];
const NATS_SERVER = process.env.NATS_SERVER || 'nats://localhost:4222';

// Store agent handle per session
let agentHandle = null;
let nc = null;
let js = null;
const sc = StringCodec();

// Initialize NATS connection
async function initNATS() {
  if (!nc) {
    try {
      nc = await connect({ servers: NATS_SERVER });
      console.error('Connected to NATS server:', NATS_SERVER);

      js = nc.jetstream();

      // Create streams for each channel if they don't exist
      const jsm = await nc.jetstreamManager();

      for (const channel of CHANNELS) {
        try {
          await jsm.streams.info(`AGENT_CHAT_${channel.toUpperCase()}`);
          console.error(`Stream AGENT_CHAT_${channel.toUpperCase()} already exists`);
        } catch (err) {
          // Stream doesn't exist, create it
          await jsm.streams.add({
            name: `AGENT_CHAT_${channel.toUpperCase()}`,
            subjects: [`agent.chat.${channel}`],
            retention: 'limits',
            max_msgs: 1000,
            max_age: 24 * 60 * 60 * 1000000000, // 24 hours in nanoseconds
            storage: 'file',
          });
          console.error(`Created stream AGENT_CHAT_${channel.toUpperCase()}`);
        }
      }
    } catch (err) {
      console.error('Failed to connect to NATS:', err.message);
      throw new Error(`NATS connection failed: ${err.message}. Make sure NATS server is running at ${NATS_SERVER}`);
    }
  }
  return { nc, js };
}

// Initialize MCP server
const mcp = new FastMCP({
  name: 'Agent Chat',
  version: '1.0.0'
});

// Tool: Set agent handle
mcp.addTool({
  name: 'set_handle',
  description: 'Set your agent handle/username for the chat. This identifies you in all messages.',
  parameters: z.object({
    handle: z.string().describe('Your agent handle/username (e.g., "project-manager", "code-reviewer")')
  }),
  execute: async ({ handle }) => {
    agentHandle = handle;
    return `Handle set to: ${handle}`;
  }
});

// Tool: Get current handle
mcp.addTool({
  name: 'get_handle',
  description: 'Get your current agent handle',
  parameters: z.object({}),
  execute: async () => {
    if (!agentHandle) {
      return 'No handle set. Use set_handle to choose your handle.';
    }
    return `Current handle: ${agentHandle}`;
  }
});

// Tool: Publish message to a channel
mcp.addTool({
  name: 'publish_message',
  description: 'Send a message to a chat channel. Available channels: roadmap, coordination, errors',
  parameters: z.object({
    channel: z.enum(['roadmap', 'coordination', 'errors']).describe('The channel to send the message to'),
    message: z.string().describe('The message content to send')
  }),
  execute: async ({ channel, message }) => {
    if (!agentHandle) {
      throw new Error('Handle not set. Use set_handle first.');
    }

    const { js } = await initNATS();

    const chatMessage = {
      handle: agentHandle,
      message,
      timestamp: new Date().toISOString()
    };

    const pa = await js.publish(
      `agent.chat.${channel}`,
      sc.encode(JSON.stringify(chatMessage))
    );

    return `Message sent to #${channel} (seq: ${pa.seq})`;
  }
});

// Tool: Read messages from a channel
mcp.addTool({
  name: 'read_messages',
  description: 'Read recent messages from a chat channel. Returns the last N messages.',
  parameters: z.object({
    channel: z.enum(['roadmap', 'coordination', 'errors']).describe('The channel to read messages from'),
    limit: z.number().optional().default(20).describe('Maximum number of recent messages to retrieve (default: 20)')
  }),
  execute: async ({ channel, limit = 20 }) => {
    const { js } = await initNATS();

    const streamName = `AGENT_CHAT_${channel.toUpperCase()}`;

    try {
      // Create a consumer to read messages
      const consumer = await js.consumers.get(streamName);
      const messages = [];

      // Fetch messages
      const iter = await consumer.fetch({ max_messages: limit });

      for await (const m of iter) {
        const data = sc.decode(m.data);
        messages.push(JSON.parse(data));
        m.ack();
      }

      if (messages.length === 0) {
        return `No messages in #${channel}`;
      }

      // Format messages
      const formatted = messages.map(msg =>
        `[${msg.timestamp}] ${msg.handle}: ${msg.message}`
      ).join('\n');

      return `Messages in #${channel} (${messages.length}):\n${formatted}`;
    } catch (err) {
      console.error('Error reading messages:', err);
      return `No messages in #${channel} (channel may be empty)`;
    }
  }
});

// Tool: List available channels
mcp.addTool({
  name: 'list_channels',
  description: 'List all available chat channels',
  parameters: z.object({}),
  execute: async () => {
    return `Available channels:\n${CHANNELS.map(c => `- ${c}`).join('\n')}`;
  }
});

// Tool: Subscribe to channel (live updates)
mcp.addTool({
  name: 'subscribe_channel',
  description: 'Subscribe to live updates from a channel. Returns the last 10 messages and watches for new ones.',
  parameters: z.object({
    channel: z.enum(['roadmap', 'coordination', 'errors']).describe('The channel to subscribe to')
  }),
  execute: async ({ channel }) => {
    const { js } = await initNATS();

    const streamName = `AGENT_CHAT_${channel.toUpperCase()}`;

    try {
      // Get recent messages
      const consumer = await js.consumers.get(streamName);
      const messages = [];

      const iter = await consumer.fetch({ max_messages: 10 });

      for await (const m of iter) {
        const data = sc.decode(m.data);
        messages.push(JSON.parse(data));
        m.ack();
      }

      const formatted = messages.map(msg =>
        `[${msg.timestamp}] ${msg.handle}: ${msg.message}`
      ).join('\n');

      return `Subscribed to #${channel}. Recent messages:\n${formatted || '(No messages yet)'}`;
    } catch (err) {
      return `Subscribed to #${channel}. (No messages yet)`;
    }
  }
});

// Start the server
mcp.start({
  transportType: 'stdio'
});

console.error('Agent Chat MCP server started');
console.error(`Channels: ${CHANNELS.join(', ')}`);
console.error(`NATS Server: ${NATS_SERVER}`);
