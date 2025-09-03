# TaskManager API Reference Guide

Complete reference for the TaskManager API - a comprehensive task management system designed for Claude Code agents with multi-agent support, automatic agent initialization, and directory-restriction-free operations.

## 🚀 Quick Start

### Node.js API Interface (Recommended)
```bash
# NEW APPROACH: Node.js API works from any directory (no cd required)

# Use the convenient wrapper script (RECOMMENDED):
bash "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/tm" init

# This initialization command displays all available TaskManager API commands.
```

### Legacy Shell Scripts Interface (Deprecated)
```bash
# ❌ OLD APPROACH: Requires directory changes (now blocked by Claude Code security)
# cd "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook"
# ./scripts/taskmanager/taskmanager.sh current

# Use Node.js API instead!
```

### Initialize Agent and Start Working
```bash
# NEW APPROACH: Initialize agent with Node.js API (recommended workflow)
bash "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/tm" init

# Initialize with specific configuration
bash "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/tm" init '{"role": "development", "sessionId": "my_session", "specialization": ["testing", "linting"]}'

# Save agent ID from JSON response for subsequent commands
# Example response: {"success": true, "agentId": "development_session_123...", "config": {...}}

# Use saved agent ID for subsequent operations
bash "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/tm" current [agentId]
bash "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/tm" status [agentId]
```

## 🎯 Node.js API Operations (Primary Interface)

All TaskManager operations are now available through the Node.js API, which resolves directory restriction issues and provides better error handling.

### Core Task Operations
```bash
# Initialize new agent (gets auto-assigned ID)
bash "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/tm" init
bash "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/tm" init '{"role": "testing", "specialization": ["unit-tests"]}'

# Task management
bash "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/tm" current [agentId]
bash "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/tm" list '{"status": "pending"}'
bash "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/tm" create '{"title": "Fix bug", "mode": "DEVELOPMENT", "priority": "high"}'
bash "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/tm" claim task_123 [agentId] normal
bash "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/tm" complete task_123 '{"notes": "Fixed successfully"}'

# Task organization
bash "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/tm" move-top task_123
bash "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/tm" move-up task_123
bash "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/tm" move-down task_123
bash "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/tm" move-bottom task_123

# Agent and system status
bash "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/tm" status [agentId]
bash "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/tm" stats
bash "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/tm" linter-check
```

### Direct Node.js API Calls
```bash
# For advanced usage or programmatic access
node "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/taskmanager-api.js" init
node "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/taskmanager-api.js" current
node "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/taskmanager-api.js" list '{"mode": "DEVELOPMENT"}'
node "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/taskmanager-api.js" create '{"title": "Task", "mode": "TESTING"}'
```

## 🤖 Agent Management (Legacy Interface)

### Agent Registry Operations

```bash
# Initialize new agent (auto-assigns agent_1, agent_2, etc.)
node initialize-agent.js init

# Initialize with specific configuration
node initialize-agent.js init '{"role": "testing", "specialization": ["unit-tests", "integration"], "sessionId": "test_session"}'

# Update agent activity (keeps agent active)
node initialize-agent.js update agent_1

# Get agent information
node initialize-agent.js info agent_1

# List all active agents
node initialize-agent.js active

# Get registry statistics
node initialize-agent.js stats
```

### Agent Environment Variables
```bash
# Set for consistent agent identification
export CLAUDE_AGENT_ID="agent_1"              # Specific agent ID
export CLAUDE_SESSION_ID="my_session"         # Session identifier
export CLAUDE_AGENT_ROLE="development"        # Agent role
export CLAUDE_AGENT_SPECIALIZATION="testing,linting"  # Specializations
```

## 🔧 Shell Scripts Interface

### Master Script Commands
All TaskManager operations are available via shell scripts for reliability:

```bash
# Task Management
./scripts/taskmanager/taskmanager.sh current [agent_id]
./scripts/taskmanager/taskmanager.sh create --title "Title" --description "Desc" --mode "DEVELOPMENT"
./scripts/taskmanager/taskmanager.sh complete <task_id>
./scripts/taskmanager/taskmanager.sh status <task_id> <new_status>
./scripts/taskmanager/taskmanager.sh info <task_id>
./scripts/taskmanager/taskmanager.sh list [--status pending] [--mode DEVELOPMENT]
./scripts/taskmanager/taskmanager.sh remove <task_id>

# Task Organization
./scripts/taskmanager/taskmanager.sh move-top <task_id>
./scripts/taskmanager/taskmanager.sh move-bottom <task_id>
./scripts/taskmanager/taskmanager.sh move-up <task_id>
./scripts/taskmanager/taskmanager.sh move-down <task_id>

# File Management
./scripts/taskmanager/taskmanager.sh add-file <task_id> <file_path>
./scripts/taskmanager/taskmanager.sh remove-file <task_id> <file_path>

# Dependencies
./scripts/taskmanager/taskmanager.sh dependencies [--graph] [--executable]

# Agent Management
./scripts/taskmanager/taskmanager.sh agent-register --role "role" --session "session"
./scripts/taskmanager/taskmanager.sh agent-claim <agent_id> <task_id>
./scripts/taskmanager/taskmanager.sh agent-status <agent_id>
./scripts/taskmanager/taskmanager.sh agent-list [--active]

# Linter Feedback (NEW)
./scripts/taskmanager/taskmanager.sh linter-check    # Check for pending linter feedback
./scripts/taskmanager/taskmanager.sh linter-clear    # Clear linter feedback to proceed

# Backup & Archive
./scripts/taskmanager/taskmanager.sh backup [--list|--create|--restore]
./scripts/taskmanager/taskmanager.sh archive [--list|--stats|--restore task_id]
```

### Linter Feedback Workflow
The system now enforces mandatory linter checks after task completion:

```bash
# 1. Complete a task (this now triggers linter feedback requirement)
./scripts/taskmanager/taskmanager.sh complete task_123

# 2. Check what linter feedback is pending
./scripts/taskmanager/taskmanager.sh linter-check
# Output: Shows task details, linting commands needed

# 3. Run recommended linting
npm run lint           # Or specific directories as recommended
npm run lint:fix        # Auto-fix issues if available

# 4. Clear linter feedback to proceed to next task
./scripts/taskmanager/taskmanager.sh linter-clear
# Only after this step can you get the next task assignment
```

## 📋 Stop Hook Integration

### Task Continuation Workflow
```bash
# Get task continuation guidance (recommended main workflow)
node stop-hook.js

# System responses based on current state:
# 1. Linter Feedback Required: Shows pending linter feedback from completed task
#    - Must run linter checks and clear feedback before proceeding
#    - Use: ./scripts/taskmanager/taskmanager.sh linter-clear
# 2. Initialize agent if needed (auto-assigns agent number)
# 3. Find current task or assign new task
# 4. Provide detailed instructions and commands
# 5. Give completion commands (now triggers mandatory linter feedback)
```

### Manual Task Continuation Commands
```bash
# Get task continuation guidance for specific agent
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.getTaskContinuationGuidance('agent_1').then(guidance => console.log(JSON.stringify(guidance, null, 2)));"

# Get next available task when current task is completed
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.getNextTask('agent_1', 'completed_task_id').then(task => console.log(task ? 'Next: ' + task.title : 'No more tasks'));"
```

## Core Operations

### Linter Feedback Management (NEW)
```bash
# Check for pending linter feedback (Shell Script - Recommended)
./scripts/taskmanager/taskmanager.sh linter-check

# Clear pending linter feedback (Shell Script - Recommended) 
./scripts/taskmanager/taskmanager.sh linter-clear

# Check if linter feedback is pending (Node API)
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.hasPendingLinterFeedback().then(pending => console.log('Pending feedback:', pending));"

# Get linter feedback details (Node API)
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.getPendingLinterFeedback().then(feedback => console.log(JSON.stringify(feedback, null, 2)));"

# Clear linter feedback (Node API)
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.clearLinterFeedback().then(result => console.log(JSON.stringify(result, null, 2)));"
```

### Agent-Aware Task Management

```bash
# Read TODO.json with validation and auto-fix
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.readTodo().then(data => console.log(JSON.stringify(data, null, 2)));"

# Get current task for specific agent
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.getCurrentTask('agent_1').then(task => console.log(JSON.stringify(task, null, 2)));"

# Get current task (general - any agent)
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.getCurrentTask().then(task => console.log(JSON.stringify(task, null, 2)));"

# Update task status by ID
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.updateTaskStatus('task_id', 'completed').then(() => console.log('Task updated'));"

# Create new task with full schema support
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.createTask({title: 'New Task', description: 'Task description', mode: 'DEVELOPMENT', priority: 'high'}).then(id => console.log('Created task:', id));"
```

### Multi-Agent Task Assignment

```bash
# Assign task to specific agent
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.assignTaskToAgent('task_id', 'agent_1', 'primary').then(success => console.log('Task assigned:', success));"

# Assign agent to collaborative task
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.assignTaskToAgent('task_id', 'agent_2', 'collaborative').then(success => console.log('Joined collaborative task:', success));"

# Get all tasks for specific agent
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.getTasksForAgent('agent_1').then(tasks => console.log('Agent tasks:', tasks.length));"

# Claim task with automatic assignment
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.claimTask('task_id', 'agent_1', 'high').then(result => console.log(JSON.stringify(result, null, 2)));"
```

### Task Removal Operations

```bash
# Remove a single task by ID
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.removeTask('task_id').then(removed => console.log('Task removed:', removed));"

# Remove multiple tasks at once
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.removeTasks(['task_id1', 'task_id2', 'task_id3']).then(result => console.log('Removal results:', JSON.stringify(result, null, 2)));"
```

### Task Reordering Operations

```bash
# Reorder a task to a specific position (0-based index)
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.reorderTask('task_id', 2).then(moved => console.log('Task reordered:', moved));"

# Move task to the top of the list
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.moveTaskToTop('task_id').then(moved => console.log('Task moved to top:', moved));"

# Move task to the bottom of the list
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.moveTaskToBottom('task_id').then(moved => console.log('Task moved to bottom:', moved));"

# Move task up one position
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.moveTaskUp('task_id').then(moved => console.log('Task moved up:', moved));"

# Move task down one position
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.moveTaskDown('task_id').then(moved => console.log('Task moved down:', moved));"

# Reorder multiple tasks at once
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.reorderTasks([{taskId: 'task1', newIndex: 0}, {taskId: 'task2', newIndex: 3}]).then(result => console.log('Reorder results:', JSON.stringify(result, null, 2)));"

# Get current position of a task
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); console.log('Task position:', tm.getTaskPosition('task_id'));"
```

### File and Research Management

```bash
# Add important file to task (for task-specific documentation)
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.addImportantFile('task_id', './development/research-reports/task-specific-analysis.md').then(added => console.log('Important file added:', added));"

# Remove important file from task
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.removeImportantFile('task_id', './file/path').then(removed => console.log('File removed:', removed));"

# Get research report path for task
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); console.log(tm.getResearchReportPath('task_id'));"

# Check if research report exists
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); console.log(tm.researchReportExists('task_id'));"
```

## Advanced Operations

### Mode and Workflow Management

```bash
# Determine next execution mode based on project state
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.readTodo().then(async (data) => { const mode = await tm.getNextMode(data); console.log('Next mode:', mode); });"

# Check if reviewer should run
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.readTodo().then(data => console.log('Should run reviewer:', tm.shouldRunReviewer(data)));"

# Handle strike logic for review system
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.readTodo().then(data => console.log(JSON.stringify(tm.handleStrikeLogic(data), null, 2)));"
```

### Validation and Recovery

```bash
# Validate TODO.json without modifications
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.validateTodoFile().then(result => console.log(JSON.stringify(result, null, 2)));"

# Get detailed file status
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.getFileStatus().then(status => console.log(JSON.stringify(status, null, 2)));"

# Perform auto-fix on TODO.json
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.performAutoFix().then(result => console.log(JSON.stringify(result, null, 2)));"

# Dry run auto-fix (preview changes)
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.dryRunAutoFix().then(result => console.log(JSON.stringify(result, null, 2)));"
```

### Backup Management

```bash
# List available backups
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.listBackups().then(backups => console.log(JSON.stringify(backups, null, 2)));"

# Create manual backup
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.createBackup().then(result => console.log(JSON.stringify(result, null, 2)));"

# Restore from backup
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.restoreFromBackup().then(result => console.log(JSON.stringify(result, null, 2)));"

# Clean up legacy backups
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.cleanupLegacyBackups().then(result => console.log(JSON.stringify(result, null, 2)));"
```

## 🔀 Multi-Agent Coordination

### Collaborative Task Management

```bash
# Create task that allows collaboration
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.createTask({title: 'Collaborative Task', description: 'Multiple agents can work on this', mode: 'DEVELOPMENT', allows_collaboration: true, max_agents: 3}).then(id => console.log('Created collaborative task:', id));"

# Find collaborative tasks available to join
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.getExecutableTasks().then(tasks => { const collaborative = tasks.filter(t => t.allows_collaboration !== false && t.status === 'pending'); console.log('Collaborative tasks:', collaborative.length); });"

# Create parallel execution plan
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.createParallelExecution(['task1', 'task2', 'task3'], ['agent_1', 'agent_2', 'agent_3'], ['sync_point_1']).then(result => console.log(JSON.stringify(result, null, 2)));"
```

### Agent Workload Management

```bash
# Check if agent can accept more tasks
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.canAgentAcceptTasks('agent_1').then(canAccept => console.log('Can accept tasks:', canAccept));"

# Update agent workload
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.updateAgentWorkload('agent_1', 3).then(() => console.log('Workload updated'));"

# Get multi-agent statistics
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.getMultiAgentStatistics().then(stats => console.log(JSON.stringify(stats, null, 2)));"
```

### Agent Specialization and Capabilities

```bash
# Find best agent for specific task
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.findBestAgentForTask({mode: 'TESTING', specialization: 'unit-tests', priority: 'high'}).then(agentId => console.log('Best agent:', agentId));"

# Get agent capabilities
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.getAgentCapabilities('agent_1').then(capabilities => console.log('Capabilities:', capabilities));"
```

## Enhanced Features

### Dependency Management

```bash
# Build dependency graph with text visualization
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.buildDependencyGraph().then(graph => console.log(graph.tree));"

# Get dependency report in markdown format
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.generateDependencyReport().then(report => console.log(report));"

# Get executable tasks (no unmet dependencies)
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.getExecutableTasks().then(tasks => console.log(JSON.stringify(tasks.map(t => ({id: t.id, title: t.title, status: t.status})), null, 2)));"
```

### Executable Quality Gates

```bash
# Execute quality gates for a task
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.executeQualityGates('task_id').then(result => console.log(JSON.stringify(result, null, 2)));"

# Add executable quality gate to task
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.addQualityGate('task_id', 'npm run lint').then(added => console.log('Quality gate added:', added));"
```

#### Supported Quality Gate Types

- **npm/node commands**: `npm run lint`, `npm test`, `node script.js`
- **File existence**: `file exists: ./path/to/file`
- **Coverage thresholds**: `coverage > 80%`
- **Predefined checks**: `tests pass`, `lint passes`

### Batch Operations

```bash
# Batch update multiple tasks
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.batchUpdateTasks([{taskId: 'task1', field: 'status', value: 'completed'}, {taskId: 'task2', field: 'priority', value: 'high'}]).then(result => console.log(JSON.stringify(result, null, 2)));"
```

### Task Filtering and Querying

```bash
# Query tasks with filters
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.queryTasks({status: 'pending', priority: 'high'}).then(tasks => console.log(JSON.stringify(tasks.map(t => ({id: t.id, title: t.title})), null, 2)));"

# Available filter options:
# - status: 'pending', 'in_progress', 'completed', 'blocked'
# - priority: 'low', 'medium', 'high'
# - mode: 'DEVELOPMENT', 'TESTING', 'RESEARCH', etc.
# - hasFile: string to match in important_files
# - titleContains: string to search in task titles
```

### Task Templates

```bash
# Create task from template
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.createTaskFromTemplate('bug-fix', {bugDescription: 'Login fails on mobile', priority: 'high'}).then(id => console.log('Created task:', id));"
```

#### Available Templates

- **bug-fix**: Bug investigation and resolution
- **feature**: New feature implementation  
- **refactor**: Code refactoring tasks
- **research**: Research and analysis tasks

### Error Tracking

```bash
# Track task error
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.trackTaskError('task_id', {type: 'test_failure', message: 'Unit tests failing', blocking: true}).then(tracked => console.log('Error tracked:', tracked));"

# Get error summary
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.getErrorSummary().then(summary => console.log(JSON.stringify(summary, null, 2)));"

# Get errors for specific task
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.getErrorSummary('task_id').then(errors => console.log(JSON.stringify(errors, null, 2)));"
```

### Completed Task Archiving (DONE.json)

```bash
# View completed tasks from DONE.json
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.readDone().then(data => console.log(JSON.stringify(data, null, 2)));"

# Get recent completed tasks (last 10)
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.getCompletedTasks({limit: 10}).then(tasks => console.log(JSON.stringify(tasks.map(t => ({id: t.id, title: t.title, completed_at: t.completed_at})), null, 2)));"

# Get completed tasks from last 7 days
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(); tm.getCompletedTasks({since: sevenDaysAgo}).then(tasks => console.log('Completed last 7 days:', tasks.length));"

# Get completion statistics
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.getCompletionStats().then(stats => console.log(JSON.stringify(stats, null, 2)));"

# Restore a completed task back to TODO.json
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.restoreCompletedTask('task_id').then(restored => console.log('Task restored:', restored));"

# Migrate all existing completed tasks from TODO.json to DONE.json (one-time setup)
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.migrateCompletedTasks().then(result => console.log('Migration results:', JSON.stringify(result, null, 2)));"
```

#### Automatic Archiving Behavior

When a task status is updated to 'completed':
- Task is automatically moved from TODO.json to DONE.json
- Completion timestamp (`completed_at`) is added
- Task is removed from TODO.json to keep it focused on active work
- Archive metadata tracks source file and completion details

#### DONE.json Structure

```javascript
{
  project: "infinite-continue-stop-hook",
  completed_tasks: [
    {
      // Original task properties plus:
      completed_at: "2025-08-07T04:55:19.628Z",
      archived_from_todo: "./TODO.json"
    }
  ],
  total_completed: 149,
  last_completion: "2025-08-07T04:55:19.628Z",
  created_at: "2025-08-07T04:55:04.024Z"
}
```

## Task Schema

### Complete Task Object Structure

```javascript
{
  id: "task_timestamp_randomstring",        // Auto-generated unique ID
  title: "Task Title",                      // Required: Brief task description
  description: "Detailed description",     // Required: Full task details
  mode: "DEVELOPMENT",                      // Required: Execution mode
  priority: "medium",                       // Optional: low|medium|high (default: medium)
  status: "pending",                        // Optional: pending|in_progress|completed|blocked (default: pending)
  dependencies: ["task_id1", "task_id2"],  // Optional: Array of task IDs this depends on
  important_files: ["./file1", "./file2"], // Optional: Relevant file paths
  success_criteria: ["criteria1", "cmd"],  // Optional: Completion criteria (can be executable)
  estimate: "2-3 hours",                    // Optional: Time estimate
  requires_research: false,                 // Optional: Research phase required
  subtasks: [],                             // Optional: Array of subtask objects
  created_at: "2024-08-05T10:00:00.000Z",  // Auto-generated: ISO timestamp
  errors: [],                               // Auto-managed: Error tracking array
  
  // Multi-Agent Support Fields:
  assigned_agent: "agent_1",                // Primary agent assigned to task
  assigned_agents: ["agent_1", "agent_2"], // All agents working on task (collaborative)
  allows_collaboration: true,               // Whether multiple agents can work on task
  max_agents: 3,                           // Maximum agents allowed on task
  agent_assignment_history: [              // History of agent assignments
    {
      agentId: "agent_1",
      role: "primary",                      // primary, collaborative, coordinator
      assignedAt: "2024-08-05T10:00:00.000Z",
      reassignReason: null
    }
  ],
  parallel_execution: {                     // Parallel execution metadata
    canParallelize: true,
    parallelWith: ["task_id2", "task_id3"],
    coordinatorTask: "coordinator_task_id",
    syncPoints: ["checkpoint_1", "completion"]
  },
  
  // Special task type flags (auto-set):
  is_linter_task: false,                    // Linter-related task
  is_quality_improvement_task: false,       // Quality improvement task
  is_review_task: false,                    // Review system task
  linter_summary: {}                        // Linter error summary (if applicable)
}
```

### TODO.json Structure

```javascript
{
  project: "Project Name",                  // Project identifier
  tasks: [],                                // Array of task objects
  
  // Multi-Agent Support:
  agents: {                                 // Active agent registry
    "agent_1": {
      name: "Development Agent",
      role: "development",
      specialization: ["frontend", "testing"],
      status: "active",
      assignedTasks: ["task_id1", "task_id2"],
      lastHeartbeat: "2024-08-05T10:00:00.000Z",
      workload: 2,
      maxConcurrentTasks: 5
    }
  },
  
  // Execution State:
  current_mode: "DEVELOPMENT",              // Current execution mode
  last_mode: "TASK_CREATION",               // Previous execution mode
  execution_count: 42,                      // Hook execution counter
  review_strikes: 2,                        // Review system strike count (0-3)
  strikes_completed_last_run: false,        // Strike completion flag
  last_hook_activation: 1754375000000       // Timestamp of last hook activation
}
```

### Agent Registry Structure (agent-registry.json)

```javascript
{
  agents: {                                 // All registered agents
    "agent_1": {
      agentId: "agent_1",
      agentNumber: 1,
      sessionId: "session_12345",
      role: "development",
      specialization: ["testing", "linting"],
      status: "active",                     // active, inactive
      lastActivity: 1754981528457,
      totalRequests: 42,
      createdAt: "2024-08-05T10:00:00.000Z",
      metadata: {},
      capabilities: ["file-operations", "testing"]
    }
  },
  nextAgentNumber: 4,                       // Next available agent number
  lastCleanup: 1754981528457,               // Last cleanup timestamp
  metadata: {
    created: "2024-08-05T10:00:00.000Z",
    version: "1.0.0"
  }
}
```

## 🔄 Complete Workflow Examples

### Single Agent Development Workflow

```bash
#!/bin/bash
# Complete single-agent workflow

# 1. Initialize agent (gets agent_1, agent_2, etc.)
echo "🚀 Initializing agent..."
AGENT_RESULT=$(node initialize-agent.js init '{"role": "development", "sessionId": "dev_workflow"}')
AGENT_ID=$(echo "$AGENT_RESULT" | jq -r '.agentId')
echo "Agent initialized: $AGENT_ID"

# 2. Set environment variable for consistency
export CLAUDE_AGENT_ID="$AGENT_ID"

# 3. Start main workflow loop
while true; do
  echo "📋 Getting task guidance..."
  node stop-hook-simple.js
  
  # Exit code 2 means continue working, 0 means all done
  if [ $? -eq 0 ]; then
    echo "✅ All tasks completed!"
    break
  fi
  
  # Update agent activity every 5 minutes to stay active
  (sleep 300 && node initialize-agent.js update "$AGENT_ID") &
  
  echo "⏳ Work on the task above, then run this script again..."
  read -p "Press Enter when task is complete or to check for next task..."
done
```

### Multi-Agent Collaboration Workflow

```bash
#!/bin/bash
# Multi-agent collaboration setup

echo "🤖 Setting up multi-agent collaboration..."

# Initialize specialized agents
FRONTEND_AGENT=$(node initialize-agent.js init '{"role": "development", "specialization": ["frontend", "react"], "sessionId": "frontend_team"}' | jq -r '.agentId')
BACKEND_AGENT=$(node initialize-agent.js init '{"role": "development", "specialization": ["backend", "api"], "sessionId": "backend_team"}' | jq -r '.agentId')
TEST_AGENT=$(node initialize-agent.js init '{"role": "testing", "specialization": ["integration", "e2e"], "sessionId": "test_team"}' | jq -r '.agentId')

echo "Agents initialized:"
echo "  Frontend: $FRONTEND_AGENT"
echo "  Backend: $BACKEND_AGENT"  
echo "  Testing: $TEST_AGENT"

# Create collaborative task
COLLAB_TASK=$(node -e "
const TaskManager = require('./lib/taskManager');
const tm = new TaskManager('./TODO.json');
tm.createTask({
  title: 'Build User Authentication System',
  description: 'Implement complete user auth with frontend, backend, and tests',
  mode: 'DEVELOPMENT',
  allows_collaboration: true,
  max_agents: 3,
  priority: 'high'
}).then(id => console.log(id));
")

# Assign agents to collaborative task
node -e "const tm = require('./lib/taskManager'); const taskManager = new tm('./TODO.json'); taskManager.assignTaskToAgent('$COLLAB_TASK', '$FRONTEND_AGENT', 'primary');"
node -e "const tm = require('./lib/taskManager'); const taskManager = new tm('./TODO.json'); taskManager.assignTaskToAgent('$COLLAB_TASK', '$BACKEND_AGENT', 'collaborative');"
node -e "const tm = require('./lib/taskManager'); const taskManager = new tm('./TODO.json'); taskManager.assignTaskToAgent('$COLLAB_TASK', '$TEST_AGENT', 'collaborative');"

echo "✅ Collaborative task created and agents assigned"
echo "Each agent can now run: CLAUDE_AGENT_ID=\"agent_X\" node stop-hook-simple.js"
```

### Agent Activity Monitoring

```bash
#!/bin/bash
# Monitor agent activity and performance

echo "📊 Agent Activity Monitor"
echo "========================="

# Show registry statistics
echo "Registry Status:"
node initialize-agent.js stats | jq '.stats'

echo -e "\nActive Agents:"
node initialize-agent.js active | jq -r '.activeAgents[] | "  \(.agentId): \(.role) - \(.totalRequests) requests"'

echo -e "\nTask Assignment Overview:"
node -e "
const TaskManager = require('./lib/taskManager');
const tm = new TaskManager('./TODO.json');
tm.readTodo().then(data => {
  const agentTasks = {};
  data.tasks.forEach(task => {
    if (task.assigned_agent) {
      agentTasks[task.assigned_agent] = (agentTasks[task.assigned_agent] || 0) + 1;
    }
  });
  Object.entries(agentTasks).forEach(([agent, count]) => {
    console.log(\`  \${agent}: \${count} tasks\`);
  });
});
"

# Monitor for inactive agents (approaching 2-hour timeout)
echo -e "\nInactivity Warnings:"
node -e "
const AgentRegistry = require('./lib/agentRegistry');
const registry = new AgentRegistry();
const data = registry.readRegistry();
const threshold = 2 * 60 * 60 * 1000 - 30 * 60 * 1000; // 1.5 hours
Object.values(data.agents).forEach(agent => {
  const timeSinceActivity = Date.now() - agent.lastActivity;
  if (timeSinceActivity > threshold && timeSinceActivity < 2 * 60 * 60 * 1000) {
    const minutesLeft = Math.round((2 * 60 * 60 * 1000 - timeSinceActivity) / (1000 * 60));
    console.log(\`  ⚠️  \${agent.agentId} will become inactive in \${minutesLeft} minutes\`);
  }
});
"
```

### Task Completion and Next Task Flow

```bash
#!/bin/bash
# Complete current task and get next task

# Set your agent ID
AGENT_ID="${CLAUDE_AGENT_ID:-agent_1}"

echo "🔄 Task Completion Flow for $AGENT_ID"

# Get current task
CURRENT_TASK=$(node -e "
const TaskManager = require('./lib/taskManager');
const tm = new TaskManager('./TODO.json');
tm.getCurrentTask('$AGENT_ID').then(task => {
  if (task) {
    console.log(task.id);
  } else {
    console.log('none');
  }
});
")

if [ "$CURRENT_TASK" = "none" ]; then
  echo "❌ No current task found for $AGENT_ID"
  echo "🔍 Getting next available task..."
  node stop-hook-simple.js
  exit 0
fi

echo "📋 Current task: $CURRENT_TASK"

# Update agent activity
node initialize-agent.js update "$AGENT_ID"

# Mark task as completed
echo "✅ Marking task as completed..."
node -e "
const TaskManager = require('./lib/taskManager');
const tm = new TaskManager('./TODO.json');
tm.updateTaskStatus('$CURRENT_TASK', 'completed').then(() => {
  console.log('Task marked as completed');
});
"

# Run linter check
echo "🔍 Running mandatory linter check..."
if npm run lint; then
  echo "✅ Linter check passed"
else
  echo "❌ Linter errors found - fix before proceeding"
  exit 1
fi

# Get next task
echo "➡️  Getting next task..."
NEXT_TASK=$(node -e "
const TaskManager = require('./lib/taskManager');
const tm = new TaskManager('./TODO.json');
tm.getNextTask('$AGENT_ID', '$CURRENT_TASK').then(task => {
  if (task) {
    console.log('Next task:', task.title);
    console.log('Mode:', task.mode);
    console.log('Priority:', task.priority);
  } else {
    console.log('🎉 No more tasks available!');
  }
});
")

echo "$NEXT_TASK"
```

## Integration Patterns

### Claude Code Bash Integration

All TaskManager operations are designed for bash execution:

```bash
# Template for TaskManager operations
node -e "
const TaskManager = require('./lib/taskManager');
const tm = new TaskManager('./TODO.json');
tm.METHOD_NAME(PARAMETERS).then(result => {
  console.log(JSON.stringify(result, null, 2));
}).catch(error => {
  console.error('Error:', error.message);
});
"
```

### Agent Registry Integration

```bash
# Template for Agent Registry operations
node -e "
const { initializeAgent, updateAgentActivity, getAgentInfo } = require('./initialize-agent');
FUNCTION_NAME(PARAMETERS).then(result => {
  console.log(JSON.stringify(result, null, 2));
}).catch(error => {
  console.error('Error:', error.message);
});
"
```

### Error Handling

All methods include comprehensive error handling:
- File corruption recovery via AutoFixer
- Atomic write operations with backups  
- Graceful fallback for missing dependencies
- Detailed error reporting with context
- Agent registry conflict resolution
- Task assignment validation
- Collaborative task coordination

### Performance Considerations

- Atomic file operations prevent corruption
- Backup creation before modifications
- Efficient dependency graph algorithms
- Minimal memory footprint for large task sets
- Agent slot reuse optimization (2-hour timeout)
- Thread-safe agent registry operations
- Collaborative task load balancing

## 🚀 Quick Reference

### Most Common Operations

```bash
# 🎯 RECOMMENDED: Use the simplified stop hook for main workflow
node stop-hook-simple.js

# Initialize agent manually
node initialize-agent.js init

# Get current task for specific agent
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.getCurrentTask('agent_1').then(task => console.log(task ? task.title : 'No active tasks'));"

# Mark current task as completed
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.getCurrentTask('agent_1').then(async task => { if(task) { await tm.updateTaskStatus(task.id, 'completed'); console.log('Task completed:', task.title); } });"

# Get next available task for agent
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.getNextTask('agent_1').then(task => console.log(task ? 'Next: ' + task.title : 'No more tasks'));"

# Create new collaborative task
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.createTask({title: 'Collaborative Task', description: 'Multiple agents can work on this', mode: 'DEVELOPMENT', allows_collaboration: true, max_agents: 3}).then(id => console.log('Created:', id));"

# Assign task to agent
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.assignTaskToAgent('task_id', 'agent_1', 'primary').then(success => console.log('Assigned:', success));"

# Check agent registry stats
node initialize-agent.js stats

# List active agents
node initialize-agent.js active

# Update agent activity (keep alive)
node initialize-agent.js update agent_1

# Get task continuation guidance
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.getTaskContinuationGuidance('agent_1').then(guidance => console.log(guidance.instructions));"
```

## 📚 Summary

This comprehensive TaskManager API provides:

### ✅ **Core Features:**
- **Multi-agent task management** with automatic number assignment
- **Agent registry** with 2-hour inactivity timeout and slot reuse
- **Stop hook integration** for seamless task continuation workflows
- **Collaborative task support** with multiple agents per task
- **Automatic linter checks** for development tasks
- **Task dependency management** and conflict resolution

### ✅ **Key Benefits:**
- **Simplified workflow**: Use `node stop-hook-simple.js` for most operations
- **Agent persistence**: Agents maintain numbered identity across sessions
- **Resource efficiency**: Inactive agent slots automatically reused
- **Collaborative work**: Multiple agents can work on complex tasks
- **Quality enforcement**: Mandatory linter checks before task completion
- **Bash compatibility**: All operations work in Claude Code environment

### ✅ **Perfect for:**
- **Claude Code agents** requiring task orchestration
- **Multi-agent development teams** with specialized roles
- **Continuous integration workflows** with quality gates
- **Complex project management** with dependencies and collaboration
- **Automated task assignment** based on agent capabilities

This system provides enterprise-grade task management with the simplicity needed for effective agent workflows!

---

## 🔄 Migration Notice

**IMPORTANT**: This guide has been updated to prioritize the new Node.js API interface over legacy shell scripts due to Claude Code directory restrictions. 

**✅ Use Node.js API (Recommended):**
- Works from any directory
- No `cd` commands required
- Better error handling
- JSON output format
- Resolves security restrictions

**❌ Legacy Shell Scripts (Deprecated):**
- Requires directory changes (`cd`)
- Blocked by Claude Code security
- Use only if specifically needed

For the best experience, use the Node.js API via the convenient wrapper script:
```bash
bash "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/tm" [command]
```