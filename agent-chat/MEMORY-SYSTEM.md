# Agent Memory System

A hierarchical memory system for AI agents using the MCP (Model Context Protocol) memory server.

## Overview

This system provides persistent, layered memory for AI agents, inspired by the "Inside Out" core memories concept. Each agent maintains multiple memory layers with automatic summarization and archival.

## Architecture

### Memory Layers

Each agent has five distinct memory layers, stored as tagged observations in the MCP memory knowledge graph:

1. **Core Memories `[CORE]`** - Immutable personality principles
   - Define agent's identity and operational philosophy
   - Never summarized or removed
   - Example: "I follow test-driven development principles"

2. **Current Task `[CURRENT]`** - Active work context
   - Single entry describing what the agent is currently doing
   - Replaced when starting new work
   - Example: "Implementing Work Stream 15: Checklist API endpoints"

3. **Recent Memory `[RECENT]`** - Short-term working memory
   - Last ~10 discrete events or actions
   - Automatically summarized when reaching 10 entries
   - Example: "Started TDD implementation of checklist CRUD endpoints"

4. **Episodic Memory `[EPISODIC]`** - Summarized past experiences
   - Summaries of batches of recent memories
   - Periodically compressed to compost when accumulating
   - Example: "Summary from 2025-12-20: Completed Work Stream 7 implementation; ran into TypeORM migration issues; resolved with manual schema sync"

5. **Memory Compost `[COMPOST]`** - Long-term archive
   - Highly compressed historical context
   - Rarely accessed, but preserved for continuity
   - Example: "Compressed 15 memories from early December 2025"

### Agent Entities

Five agents are configured with this memory system:

#### 1. `tdd-implementer`
**Role:** Test-Driven Development work stream executor
**Core Principles:**
- Write failing tests first, then minimal implementation
- Maintain 80%+ code coverage
- Tests as living documentation
- Incremental refactoring with frequent test runs

#### 2. `project-manager`
**Role:** Roadmap maintenance and work coordination
**Core Principles:**
- Track work stream progress and dependencies
- Garden roadmap (archive completed work)
- Identify and assign unblocked parallel work
- Communicate progress and blockers clearly

#### 3. `business-analyst`
**Role:** Feature analysis and value prioritization
**Core Principles:**
- Apply business value frameworks (RICE, impact/effort)
- Prioritize measurable user outcomes
- Identify end-to-end value chains
- Challenge assumptions with data

#### 4. `requirements-reviewer`
**Role:** Requirements quality and traceability
**Core Principles:**
- Ensure requirements are specific, measurable, testable
- Identify gaps, conflicts, dependencies
- Advocate for non-functional requirements
- Maintain business-to-technical traceability

#### 5. `security-reviewer`
**Role:** Security vulnerability assessment and compliance
**Core Principles:**
- Identify security vulnerabilities using OWASP Top 10, CWE, and industry best practices
- Ensure compliance with security requirements (encryption, authentication, authorization)
- Analyze attack vectors and threat models for potential exploits
- Advocate for defense-in-depth strategies and fail-secure design patterns

## Usage

### Prerequisites

1. MCP memory server must be running (included in Claude Code)
2. Agents are already created in the knowledge graph (see setup section)

### Basic Operations

#### 1. Retrieve Agent Memory

```javascript
// Using MCP memory tools
const nodes = await mcp__memory__open_nodes({ names: ["tdd-implementer"] });
const agent = nodes.entities[0];

// Organize memories by type
const MemoryManager = require('./memory-manager.js');
const memories = MemoryManager.organizeMemories(agent.observations);

console.log('Current Task:', memories.CURRENT[0]);
console.log('Recent Memories:', memories.RECENT);
console.log('Core Principles:', memories.CORE);
```

#### 2. Add a Recent Memory

```javascript
// Check if summarization is needed first
if (memories.RECENT.length >= 10) {
  // Perform summarization (see section below)
}

// Add new memory
await mcp__memory__add_observations({
  observations: [{
    entityName: "tdd-implementer",
    contents: ["[RECENT] Completed unit tests for checklist service with 85% coverage"]
  }]
});
```

#### 3. Update Current Task

```javascript
// Delete old current task
await mcp__memory__delete_observations({
  deletions: [{
    entityName: "tdd-implementer",
    observations: [`[CURRENT] ${memories.CURRENT[0]}`]
  }]
});

// Add new current task
await mcp__memory__add_observations({
  observations: [{
    entityName: "tdd-implementer",
    contents: ["[CURRENT] Implementing Work Stream 16: Email notification templates"]
  }]
});
```

#### 4. Automatic Summarization (After 10 Recent Memories)

```javascript
const MemoryManager = require('./memory-manager.js');

// Get current state
const nodes = await mcp__memory__open_nodes({ names: ["tdd-implementer"] });
const memories = MemoryManager.organizeMemories(nodes.entities[0].observations);

// Check if summarization is needed
if (MemoryManager.needsSummarization(memories)) {
  // 1. Create summary
  const summary = MemoryManager.summarizeRecentMemories(memories.RECENT);

  // 2. Delete recent memories
  await mcp__memory__delete_observations({
    deletions: [{
      entityName: "tdd-implementer",
      observations: memories.RECENT.map(m => `[RECENT] ${m}`)
    }]
  });

  // 3. Add episodic summary
  await mcp__memory__add_observations({
    observations: [{
      entityName: "tdd-implementer",
      contents: [`[EPISODIC] ${summary}`]
    }]
  });
}
```

#### 5. Compress Episodic to Compost

```javascript
// When episodic memories accumulate (e.g., > 10 entries)
const compressed = MemoryManager.compressEpisodicToCompost(memories, 5);

if (compressed) {
  // Delete old episodic memories
  await mcp__memory__delete_observations({
    deletions: [{
      entityName: "tdd-implementer",
      observations: compressed.toDelete
    }]
  });

  // Add compost entry
  await mcp__memory__add_observations({
    observations: [{
      entityName: "tdd-implementer",
      contents: compressed.toAdd
    }]
  });
}
```

#### 6. Create Memory Snapshot for Prompts

```javascript
// Generate formatted memory context for agent prompts
const snapshot = MemoryManager.createMemorySnapshot(agent.observations, {
  includeCore: true,
  includeCurrent: true,
  includeRecent: true,
  maxRecent: 5,
  maxEpisodic: 3
});

console.log(snapshot);
/*
Output:
## Core Principles
- I follow test-driven development principles: write failing tests first...
- I maintain 80%+ code coverage and prioritize testability...

## Current Task
Implementing Work Stream 15: Checklist API endpoints

## Recent Memory
- Started TDD implementation of checklist CRUD
- Wrote 12 failing tests for checklist service
- Implemented minimal checklist model
- Added database migration for checklists table
- All tests passing, 87% coverage achieved
*/
```

### Advanced Operations

#### Query Agent Memories

```javascript
// Search for specific memories
const results = await mcp__memory__search_nodes({
  query: "checklist implementation"
});

// Returns agents and entities related to checklists
```

#### Create Memory Relations

```javascript
// Link memories between agents or tasks
await mcp__memory__create_relations({
  relations: [{
    from: "tdd-implementer",
    to: "Work Stream 15",
    relationType: "working_on"
  }]
});
```

## Workflow Examples

### Example 1: TDD Implementer Starting Work

```javascript
const MemoryManager = require('./memory-manager.js');

// 1. Load agent state
const nodes = await mcp__memory__open_nodes({ names: ["tdd-implementer"] });
const memories = MemoryManager.organizeMemories(nodes.entities[0].observations);

// 2. Update current task
await mcp__memory__delete_observations({
  deletions: [{
    entityName: "tdd-implementer",
    observations: [`[CURRENT] ${memories.CURRENT[0]}`]
  }]
});

await mcp__memory__add_observations({
  observations: [{
    entityName: "tdd-implementer",
    contents: ["[CURRENT] Implementing Work Stream 15: Checklist CRUD API"]
  }]
});

// 3. Add initial recent memory
await mcp__memory__add_observations({
  observations: [{
    entityName: "tdd-implementer",
    contents: ["[RECENT] Claimed Work Stream 15 from roadmap dependency level 1"]
  }]
});
```

### Example 2: Project Manager Tracking Progress

```javascript
// 1. Load state
const nodes = await mcp__memory__open_nodes({ names: ["project-manager"] });
const memories = MemoryManager.organizeMemories(nodes.entities[0].observations);

// 2. Add progress update
await mcp__memory__add_observations({
  observations: [{
    entityName: "project-manager",
    contents: ["[RECENT] Work Stream 15 completed by tdd-implementer, unblocked WS 24 and WS 25"]
  }]
});

// 3. Check if summarization needed
if (memories.RECENT.length >= 10) {
  const summary = MemoryManager.summarizeRecentMemories(memories.RECENT);

  await mcp__memory__delete_observations({
    deletions: [{
      entityName: "project-manager",
      observations: memories.RECENT.map(m => `[RECENT] ${m}`)
    }]
  });

  await mcp__memory__add_observations({
    observations: [{
      entityName: "project-manager",
      contents: [`[EPISODIC] ${summary}`]
    }]
  });
}

// 4. Update current task
await mcp__memory__delete_observations({
  deletions: [{
    entityName: "project-manager",
    observations: [`[CURRENT] ${memories.CURRENT[0]}`]
  }]
});

await mcp__memory__add_observations({
  observations: [{
    entityName: "project-manager",
    contents: ["[CURRENT] Monitoring dependency level 1 - 2/4 work streams complete"]
  }]
});
```

## Memory Management Best Practices

### 1. Keep Recent Memories Atomic
Each recent memory should be a single, complete thought:
- ✅ Good: "Completed checklist CRUD with 87% test coverage"
- ❌ Bad: "Working on stuff and things are going okay"

### 2. Update Current Task Frequently
When context switches:
- Starting new work stream
- Moving to different phase (tests → implementation → documentation)
- Switching between parallel tasks

### 3. Let Summarization Happen Automatically
Don't manually create episodic memories unless necessary:
- Let the system auto-summarize after 10 recent entries
- This prevents memory bloat and maintains relevance

### 4. Core Memories Are Sacred
Never modify or delete core memories:
- They define agent identity
- Changing them changes agent behavior fundamentally
- Use configuration/settings for behavior tuning instead

### 5. Use Memory Snapshots in Agent Prompts
Inject relevant memory context when invoking agents:
```javascript
const snapshot = MemoryManager.createMemorySnapshot(observations);
const prompt = `
You are the TDD Implementer agent.

${snapshot}

New Task: Implement Work Stream 20...
`;
```

## Setup

### Initial Agent Creation

The five agents are already created in the knowledge graph. If you need to recreate them:

```javascript
await mcp__memory__create_entities({
  entities: [
    {
      name: "tdd-implementer",
      entityType: "agent",
      observations: [
        "[CORE] I follow test-driven development principles: write failing tests first, then implement minimal code to pass, then refactor",
        "[CORE] I maintain 80%+ code coverage and prioritize testability in all implementations",
        "[CORE] I write clear, focused tests that serve as living documentation of requirements",
        "[CORE] I refactor incrementally and run tests frequently to catch regressions early",
        "[CURRENT] Idle - awaiting work stream assignment"
      ]
    },
    // ... (see agent-chat/memory-manager.js for full definitions)
  ]
});
```

### Verification

Check that agents are created:

```javascript
const graph = await mcp__memory__read_graph();
const agents = graph.entities.filter(e => e.entityType === 'agent');
console.log(`Found ${agents.length} agents:`, agents.map(a => a.name));
// Expected output: Found 5 agents: ['tdd-implementer', 'project-manager', 'business-analyst', 'requirements-reviewer', 'security-reviewer']
```

## Implementation Notes

### Why This Architecture?

1. **Tagged Observations** - Using prefixes like `[CORE]` allows flexible querying while maintaining simple data structure
2. **Auto-Summarization** - Prevents memory bloat and keeps context relevant
3. **Layered Access** - Different memory layers serve different purposes (identity, context, history)
4. **MCP Integration** - Leverages existing MCP memory tools rather than building custom storage

### Performance Considerations

- Recent memories limited to 10 to keep context window manageable
- Episodic summaries compress ~10 events into 1 entry (10x reduction)
- Compost provides long-term archival without active retrieval cost
- Core memories always included (typically 3-5 entries per agent)

### Future Enhancements

Potential improvements:

1. **LLM-Powered Summarization** - Use Claude to create better episodic summaries instead of concatenation
2. **Semantic Search** - Query memories by concept, not just keywords
3. **Memory Importance Scoring** - Keep important memories longer in recent/episodic layers
4. **Cross-Agent Memory Sharing** - Allow agents to reference each other's episodic memories
5. **Memory Visualization** - Dashboard showing agent memory states and relationships

## Troubleshooting

### Problem: Recent memories not summarizing
**Solution:** Check that you're comparing `memories.RECENT.length >= 10`, not `> 10`

### Problem: Current task shows multiple entries
**Solution:** Ensure you delete old current task before adding new one

### Problem: Agent not found
**Solution:** Verify agent name exactly matches (case-sensitive): `tdd-implementer`, not `TDD-Implementer`

### Problem: Memory snapshot empty
**Solution:** Check that observations have proper `[TYPE]` tags. Untagged observations default to `[RECENT]`

## Related Files

- `agent-chat/memory-manager.js` - Memory management utility library
- `agent-chat/index.js` - MCP agent-chat server (messaging)
- `plans/roadmap.md` - Project roadmap (tracked by project-manager agent)
- `.claude/agents/*.md` - Agent prompt templates

## References

- MCP Memory Server: https://github.com/anthropics/mcp-memory
- Agent Chat System: See `agent-chat/README.md`
- Project Documentation: See `CLAUDE.md`
