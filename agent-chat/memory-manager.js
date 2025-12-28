/**
 * Memory Manager for AI Agents
 *
 * Provides utilities for managing agent memory through the MCP memory server.
 *
 * Memory Structure:
 * - [CORE] - Personality principles (immutable)
 * - [CURRENT] - Current task (single entry)
 * - [RECENT] - Recent memories (max 10, then summarized)
 * - [EPISODIC] - Summarized past events
 * - [COMPOST] - Archived/composted memories
 */

const MEMORY_TYPES = {
  CORE: '[CORE]',
  CURRENT: '[CURRENT]',
  RECENT: '[RECENT]',
  EPISODIC: '[EPISODIC]',
  COMPOST: '[COMPOST]'
};

const MAX_RECENT_MEMORIES = 10;

/**
 * Parse observation to extract memory type and content
 */
function parseObservation(observation) {
  const match = observation.match(/^\[([A-Z]+)\]\s*(.*)$/);
  if (match) {
    return { type: match[1], content: match[2] };
  }
  // Default to RECENT if no tag
  return { type: 'RECENT', content: observation };
}

/**
 * Format observation with memory type tag
 */
function formatObservation(type, content) {
  return `[${type}] ${content}`;
}

/**
 * Get all observations for an agent, organized by memory type
 */
function organizeMemories(observations) {
  const organized = {
    CORE: [],
    CURRENT: [],
    RECENT: [],
    EPISODIC: [],
    COMPOST: []
  };

  for (const obs of observations) {
    const { type, content } = parseObservation(obs);
    if (organized[type]) {
      organized[type].push(content);
    }
  }

  return organized;
}

/**
 * Summarize recent memories into a single episodic memory
 * This is a simple concatenation - you can enhance with LLM summarization
 */
function summarizeRecentMemories(recentMemories) {
  if (recentMemories.length === 0) return null;

  // Simple summarization: create a narrative from recent events
  const timestamp = new Date().toISOString().split('T')[0];
  const summary = `Summary from ${timestamp}: ${recentMemories.join('; ')}`;

  return summary;
}

/**
 * Memory Manager class for interacting with agent memory
 *
 * Note: This class provides the logic for memory management.
 * To use with MCP server, you'll need to call the MCP memory tools directly
 * (create_entities, add_observations, delete_observations, etc.)
 *
 * Example usage with MCP tools:
 *
 * // 1. Get agent's current state
 * const nodes = await mcp__memory__open_nodes({ names: ["tdd-implementer"] });
 * const agent = nodes.entities[0];
 *
 * // 2. Add a recent memory
 * const memories = MemoryManager.organizeMemories(agent.observations);
 * const recentCount = memories.RECENT.length;
 *
 * if (recentCount >= MAX_RECENT_MEMORIES) {
 *   // Need to summarize first
 *   const summary = MemoryManager.summarizeRecentMemories(memories.RECENT);
 *
 *   // Delete recent memories
 *   await mcp__memory__delete_observations({
 *     deletions: [{
 *       entityName: "tdd-implementer",
 *       observations: memories.RECENT.map(m => `[RECENT] ${m}`)
 *     }]
 *   });
 *
 *   // Add episodic summary
 *   await mcp__memory__add_observations({
 *     observations: [{
 *       entityName: "tdd-implementer",
 *       contents: [`[EPISODIC] ${summary}`]
 *     }]
 *   });
 * }
 *
 * // 3. Add the new recent memory
 * await mcp__memory__add_observations({
 *   observations: [{
 *     entityName: "tdd-implementer",
 *     contents: ["[RECENT] Started implementing Work Stream 15"]
 *   }]
 * });
 */
class MemoryManager {
  static MEMORY_TYPES = MEMORY_TYPES;
  static MAX_RECENT_MEMORIES = MAX_RECENT_MEMORIES;

  /**
   * Parse observation to extract type and content
   */
  static parseObservation(observation) {
    return parseObservation(observation);
  }

  /**
   * Format observation with memory type tag
   */
  static formatObservation(type, content) {
    return formatObservation(type, content);
  }

  /**
   * Organize observations by memory type
   */
  static organizeMemories(observations) {
    return organizeMemories(observations);
  }

  /**
   * Summarize recent memories
   */
  static summarizeRecentMemories(recentMemories) {
    return summarizeRecentMemories(recentMemories);
  }

  /**
   * Check if recent memories need summarization
   */
  static needsSummarization(memories) {
    return memories.RECENT.length >= MAX_RECENT_MEMORIES;
  }

  /**
   * Get agent's current task
   */
  static getCurrentTask(observations) {
    const memories = organizeMemories(observations);
    return memories.CURRENT[0] || null;
  }

  /**
   * Get agent's core principles
   */
  static getCorePrinciples(observations) {
    const memories = organizeMemories(observations);
    return memories.CORE;
  }

  /**
   * Get recent memories
   */
  static getRecentMemories(observations) {
    const memories = organizeMemories(observations);
    return memories.RECENT;
  }

  /**
   * Get episodic memories
   */
  static getEpisodicMemories(observations) {
    const memories = organizeMemories(observations);
    return memories.EPISODIC;
  }

  /**
   * Create a memory snapshot for context injection
   * Returns a formatted string suitable for agent prompts
   */
  static createMemorySnapshot(observations, options = {}) {
    const {
      includeCore = true,
      includeCurrent = true,
      includeRecent = true,
      includeEpisodic = true,
      maxRecent = 5,
      maxEpisodic = 3
    } = options;

    const memories = organizeMemories(observations);
    const snapshot = [];

    if (includeCore && memories.CORE.length > 0) {
      snapshot.push('## Core Principles');
      memories.CORE.forEach(m => snapshot.push(`- ${m}`));
      snapshot.push('');
    }

    if (includeCurrent && memories.CURRENT.length > 0) {
      snapshot.push('## Current Task');
      snapshot.push(memories.CURRENT[0]);
      snapshot.push('');
    }

    if (includeRecent && memories.RECENT.length > 0) {
      snapshot.push('## Recent Memory');
      memories.RECENT.slice(-maxRecent).forEach(m => snapshot.push(`- ${m}`));
      snapshot.push('');
    }

    if (includeEpisodic && memories.EPISODIC.length > 0) {
      snapshot.push('## Episodic Memory');
      memories.EPISODIC.slice(-maxEpisodic).forEach(m => snapshot.push(`- ${m}`));
      snapshot.push('');
    }

    return snapshot.join('\n');
  }

  /**
   * Move old episodic memories to compost
   * Returns objects ready for MCP delete/add operations
   */
  static compressEpisodicToCompost(memories, keepMostRecent = 5) {
    if (memories.EPISODIC.length <= keepMostRecent) {
      return null; // Nothing to compress
    }

    const toCompost = memories.EPISODIC.slice(0, -keepMostRecent);
    const timestamp = new Date().toISOString().split('T')[0];
    const compostEntry = `Compressed ${toCompost.length} memories on ${timestamp}`;

    return {
      toDelete: toCompost.map(m => `[EPISODIC] ${m}`),
      toAdd: [`[COMPOST] ${compostEntry}`]
    };
  }
}

// Export for Node.js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = MemoryManager;
}

// Export for browser/global scope
if (typeof window !== 'undefined') {
  window.MemoryManager = MemoryManager;
}
