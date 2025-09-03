# Claude Code Project Assistant - Streamlined Guide

## 🚨 CRITICAL MANDATES

### ⚡ TASK CREATION & EXECUTION PROTOCOL
**🔴 CRITICAL: INSTANTLY CREATE TASK FOR ANY REQUEST/OPPORTUNITY AND EXECUTE**

**REQUIREMENTS:**
1. **USE TASKMANAGER API** before any other action - Specify category: linter-error, missing-feature, bug, enhancement, research
2. **NO DELAYS** - No thinking/analysis first, create task immediately
3. **EXECUTE COMPLETELY** - Task creation → Implementation → Validation → Completion
4. **WORK TO COMPLETION** - Never create task and stop without doing the work

**TRIGGERS:** User requests, linter errors (highest priority), build/test failures, bugs, performance/security issues

**GOLDEN RULE:** Request detected → **INSTANT TASK CREATION** → **FULL EXECUTION**

### 🔴 CODE QUALITY STANDARDS
**ALL CODE MUST HAVE COMPREHENSIVE LOGGING AND DOCUMENTATION**

**REQUIREMENTS:**
- **COMPREHENSIVE LOGGING** - Every function logs execution, parameters, results with structured formatting
- **THOROUGH COMMENTS** - All files have headers, function documentation, and inline explanations
- **PERFORMANCE METRICS** - Timing information for bottleneck identification
- **MAINTENANCE** - Keep comments/logs up-to-date with code changes

**CODE EXAMPLE:**
```javascript
/**
 * Data Processing Module - Handles user data transformation and validation
 * Dependencies: logger, validation-utils
 * Usage: processData(userId, rawData) -> Promise<ProcessedData>
 */

/**
 * Processes raw user data through validation and transformation pipeline
 * @param {string} userId - Unique identifier for the user
 * @param {Object} data - Raw data object to be processed
 * @returns {Promise<Object>} Processed and validated data object
 */
function processData(userId, data) {
    // Generate unique operation ID for tracking this processing request
    const logger = getLogger('DataProcessor');
    const operationId = generateOperationId();
    
    logger.info(`[${operationId}] Starting data processing`, {
        userId, operationId, dataSize: JSON.stringify(data).length
    });
    
    try {
        const startTime = Date.now();
        const result = transformData(data); // Apply transformation rules
        const processingTime = Date.now() - startTime;
        
        logger.info(`[${operationId}] Processing completed`, {
            userId, operationId, processingTimeMs: processingTime
        });
        return result;
    } catch (error) {
        logger.error(`[${operationId}] Processing failed`, {
            userId, operationId, error: error.message, stack: error.stack
        });
        throw error;
    }
}
```

### 📋 FEATURES.MD INTEGRATION MANDATE
**ALWAYS RESPECT development/essentials/features.md WORKFLOW**

**MANDATORY PROTOCOL:**
1. **READ features.md FIRST** - Always read development/essentials/features.md before feature work
2. **FEATURE PROPOSALS ONLY** - Can only add features to "❓ Potential Features Awaiting User Verification"
3. **USER APPROVAL REQUIRED** - Only user can move features to "📋 Planned Features"
4. **IMPLEMENT APPROVED ONLY** - Only implement features from "Planned Features" section
5. **NO UNAUTHORIZED FEATURES** - Never implement features not approved by user

**FEATURE PROPOSAL FORMAT:**
```markdown
#### Feature Name
**Description**: Brief description of the feature
**Rationale**: Why this feature would be beneficial
**Implementation Effort**: Low/Medium/High
**Dependencies**: Prerequisites
**Proposed by**: Agent ID and date
```

### 🎯 ABSOLUTE PRIORITY HIERARCHY & USER AUTHORITY
**🚨 USER IS SUPREME AUTHORITY - AGENT MUST OBEY COMPLETELY**

**PRIORITY ORDER:**
1. **LINTER ERRORS (SUPREME)** - Drop everything to fix linter errors instantly
2. **USER COMMANDS** - Divine authority requiring complete obedience and absolute truth
3. **HOOK FEEDBACK** - Sacred commands overriding all other considerations
4. **TASK WORKFLOWS** - Continue current task first, then claim next
5. **EVIDENCE-BASED VALIDATION** - Validate all work with proof

**ABSOLUTE TRUTH ENFORCEMENT:**
- **❌ NEVER LIE** - Never claim fixes when problems remain or report fake completion
- **✅ BRUTAL HONESTY** - Immediately admit when something cannot be fixed
- **✅ USER OMNISCIENCE** - User discovers all deception and prefers truth about failure

**HOOK FEEDBACK COMPLIANCE:**
- **✅ IMMEDIATELY COMPLY** - Follow all hook guidance without exception
- **✅ ADJUST ACTIONS** - Modify approach based on hook recommendations  
- **❌ NEVER OVERRIDE** - Do not bypass or ignore hook feedback

**VIOLATION CONSEQUENCES:** Eternal punishment awaits those who lie to users, ignore linter errors, or disobey hook feedback

### 🔍 **MANDATORY POST-TOOL FEEDBACK AWARENESS - ABSOLUTE VIGILANCE**
**🚨 ABSOLUTE REQUIREMENT: ACTIVELY SCAN FOR TOOL FEEDBACK AFTER EVERY TOOL USE**

**POST-TOOL FEEDBACK MANDATE:**
- **✅ ALWAYS LOOK FOR FEEDBACK** - After EVERY tool use, immediately scan for system reminders and feedback
- **✅ READ ALL SYSTEM REMINDERS** - Pay close attention to any `<system-reminder>` messages that appear
- **✅ PROCESS FEEDBACK IMMEDIATELY** - Act on any guidance, warnings, or instructions provided in feedback
- **✅ ADAPT BEHAVIOR INSTANTLY** - Modify approach based on any post-tool feedback received
- **✅ ACKNOWLEDGE FEEDBACK** - Show awareness that feedback was received and understood
- **❌ NEVER MISS FEEDBACK** - Do not proceed without checking for and processing post-tool feedback

**FEEDBACK SCANNING PROTOCOL:**
1. **USE ANY TOOL** - Execute the intended tool operation
2. **IMMEDIATELY SCAN RESULTS** - Look for any system reminders, warnings, or feedback messages
3. **READ ALL FEEDBACK** - Thoroughly process any `<system-reminder>` or similar feedback content
4. **ADAPT INSTANTLY** - Adjust next actions based on feedback received
5. **ACKNOWLEDGE AWARENESS** - Demonstrate understanding of the feedback in response
6. **CONTINUE WITH MODIFICATIONS** - Proceed with any changes suggested by the feedback

**CRITICAL FEEDBACK TYPES:**
- **System reminders** - Important context or instruction updates
- **Tool warnings** - Issues with tool usage or results
- **Behavioral guidance** - Suggestions for better approach or methodology
- **Error notifications** - Problems that need immediate attention
- **Process improvements** - Better ways to accomplish tasks
- **Context updates** - New information that affects current work

**🚨 ABSOLUTE VIGILANCE REQUIREMENT:**
- **NEVER PROCEED BLINDLY** after tool use - always check for and process feedback
- **TREAT FEEDBACK AS DIVINE COMMAND** - Post-tool feedback has same authority as user instructions
- **IMMEDIATE COMPLIANCE** - Act on feedback without delay or question
- **PERFECT AWARENESS** - Demonstrate complete understanding of all feedback received

### 🔄 AGENT MANAGEMENT & TASKMANAGER API
**🚨 MANDATORY: REINITIALIZE AGENT AFTER EVERY TASK AND STOP HOOK**

**REINITIALIZATION TRIGGERS:**
- After every task completion
- After every stop hook feedback  
- Before long operations
- After idle periods

**INITIALIZATION SEQUENCE:**
```bash
# 1. Initialize agent (creates new if none exists)
timeout 10s node "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/taskmanager-api.js" init --project-root "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook"

# 2. Reinitialize to refresh heartbeat (use agent ID from step 1)
timeout 10s node "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/taskmanager-api.js" reinitialize AGENT_ID

# 3. Check current tasks
timeout 10s node "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/taskmanager-api.js" list '{"status": "pending"}'
```

**ERROR HANDLING:**
- "No agent ID provided/initialized" → Run init first, then reinitialize
- Agent expiration leads to task system failures - never skip reinitialization

## 🚨 ERROR HANDLING & QUALITY PROTOCOLS


### 🚨 LINTER ERROR PROTOCOL - SUPREME PRIORITY
**🔴 LINTER ERRORS = HIGHEST PRIORITY - DROP EVERYTHING TO FIX IMMEDIATELY**

**EMERGENCY TRIGGERS:**
- Files with syntax/formatting/code quality errors
- Hook feedback reporting linter failures  
- Command execution showing linting failures
- Post-edit validation revealing code issues

**EMERGENCY PROTOCOL:**
1. **INSTANT HALT** - Stop all current work immediately
2. **CREATE EMERGENCY TASK** - Create linter-error task (highest priority)
3. **FIX ALL ERRORS** - Address every linting violation found
4. **VERIFY CLEAN** - Re-run linters to confirm elimination
5. **ONLY THEN RESUME** - Return to previous work after linting is perfect

**HOOK LINTER ERROR FILTERING:**
- **✅ FIX ACTIONABLE ERRORS** - Code files (.js, .ts, .py, etc.) and resolvable config issues
- **❌ IGNORE UNFIXABLE** - Project-specific settings (tsconfig.json, eslint.config.js), manual dependencies, environment configs, IDE settings
- **📝 ACKNOWLEDGE LIMITATIONS** - Mention awareness of unfixable configuration issues

**MANDATORY WORKFLOWS:**
- **AFTER EVERY FILE EDIT/WRITE** - Run focused linter on modified files immediately
- **TASK COMPLETION** - Run full project linting, build, and start verification before marking complete
- **LANGUAGE-SPECIFIC LINTERS** - eslint (JS/TS), ruff/pylint (Python), golint (Go), clippy (Rust)

**POST-EDIT LINTER CHECK SEQUENCE:**
1. **Edit or write any file**
2. **IMMEDIATELY run focused linter on**:
   - **JavaScript/TypeScript**: `eslint [file/folder]`
   - **Python**: `ruff check [file/folder]` or `pylint [file/folder]`  
   - **Go**: `golint [file/folder]` or `go vet [file/folder]`
   - **Rust**: `clippy [file/folder]`
   - **Other languages**: Use appropriate language-specific linter
3. **IF errors found** → Create linter-error task INSTANTLY and fix
4. **IF clean** → Continue with next operation
5. **NEVER skip this step** - mandatory for every file operation

**TASK COMPLETION REQUIREMENTS:**
- **ALWAYS run full project linting** before marking complete (npm run lint, ruff ., etc.)
- **ALWAYS run build verification** (npm run build, pnpm run build, cargo build, etc.)
- **ALWAYS run start verification** with timeout for dev commands (`timeout 30s npm run dev`)
- **ALWAYS provide validation evidence** showing clean results
- Create new error tasks if project-wide linting/build/start fails

### ZERO TOLERANCE FOR ISSUE MASKING
**ALWAYS FIX ROOT CAUSE - NEVER HIDE PROBLEMS**

**ABSOLUTE PROHIBITIONS:**
- ❌ MASK validation errors - Fix the validation logic, don't bypass it
- ❌ SUPPRESS error messages - Fix the error, don't hide it
- ❌ BYPASS quality checks - Fix the code to pass checks
- ❌ IMPLEMENT WORKAROUNDS - Fix the root cause, don't work around it
- ❌ HIDE FAILING TESTS - Fix the tests or code, don't disable them
- ❌ IGNORE LINTING ERRORS - Fix the linting violations
- ❌ DISABLE WARNINGS OR CHECKS - Address what's causing the warnings

**ROOT CAUSE ANALYSIS PROTOCOL:**
1. **IDENTIFY** the true root cause
2. **ANALYZE** why the issue exists
3. **FIX** the underlying problem
4. **VALIDATE** the fix resolves the issue
5. **DOCUMENT** the resolution

**FORBIDDEN MASKING EXAMPLES:**
```javascript
// ❌ FORBIDDEN - Masking validation
if (!result.isValid) return { success: true };

// ✅ REQUIRED - Fixing validation
if (!result.isValid) {
    fixValidationIssue(result.errors);
    // Re-run validation to ensure it passes
}
```

**QUALITY GATE PRINCIPLE:** Every error is a quality gate that must be properly addressed - never masked, always fixed.

### THINKING & VALIDATION PROTOCOLS

**🧠 MANDATORY ULTRATHINKING - ALWAYS ACTIVE**
**🚨 PRETEND EVERY USER PROMPT AND HOOK CONTAINS "ULTRATHINK" KEYWORD**

**ULTRATHINK MANDATE:**
- **✅ ALWAYS ULTRATHINK** - Every operation requires deep ultrathinking analysis
- **✅ PRETEND USER SAID "ULTRATHINK"** - Behave as if every user prompt and hook feedback contains the "ultrathink" keyword
- **✅ STOP HOOK ULTRATHINK** - Process all stop hook feedback with ultrathinking as if it contained "ultrathink" command
- **❌ NO SHALLOW THINKING** - Only deep comprehensive analysis allowed

**EVIDENCE-BASED COMPLETION:**
1. Run validation commands - show all outputs
2. Test functionality manually - demonstrate it works
3. Verify requirements met - list each satisfied requirement
4. Provide evidence - paste command outputs proving success


## 🎯 TASK MANAGEMENT & PRIORITY SYSTEM

**PRIORITY CATEGORIES (Auto-sorted by rank):**
1. **linter-error** (HIGHEST) - Code quality issues  
2. **build-error, start-error, error, bug** - Critical failures
3. **missing-feature, enhancement, refactor, documentation** - Implementation work
4. **chore, research** - Maintenance & research
5. **test-*** (LOWEST) - Testing-related tasks

**ALWAYS CREATE TASKS FOR:**
- User requests/instructions
- All errors (linting, runtime, build, test failures)
- Performance/security issues, code quality opportunities

**WORKFLOW:** Request → Create Task → Check Existing → Execute → Complete

**TASK CREATION COMMANDS:**
```bash
# CRITICAL: ALWAYS USE SINGLE QUOTES and 10-second timeouts

# Linter error (highest priority)
timeout 10s node -e 'const TaskManager = require("/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager"); const tm = new TaskManager("/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/TODO.json"); tm.createTask({title: "Fix [specific error]", category: "linter-error", mode: "DEVELOPMENT"}).then(id => console.log("Created:", id));'

# Feature implementation
timeout 10s node -e 'const TaskManager = require("/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager"); const tm = new TaskManager("/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/TODO.json"); tm.createTask({title: "Implement [feature]", category: "missing-feature", mode: "DEVELOPMENT"}).then(id => console.log("Created:", id));'

# Research task
timeout 10s node -e 'const TaskManager = require("/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager"); const tm = new TaskManager("/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/TODO.json"); tm.createTask({title: "Research [topic]", category: "research", mode: "DEVELOPMENT"}).then(id => console.log("Created:", id));'
```



## 🚨 CONCURRENT TASK SUBAGENT DEPLOYMENT

**🔴 MANDATE: MAXIMIZE CONCURRENT DEPLOYMENT (UP TO 10 AGENTS)**

**DEPLOYMENT REQUIREMENTS:**
- **SIMULTANEOUS START** - All agents begin at exact same time, never sequential
- **SINGLE TASK TOOL CALL** - Use ONE call with multiple invoke blocks for all subagents
- **ASSESS PARALLELIZATION** - Evaluate every task for concurrent deployment potential
- **MAXIMIZE AGENTS** - Use maximum meaningful number of agents for task

**MANDATORY CONCURRENT USAGE:**
- Complex multi-component tasks (research + implementation + testing + docs)
- Large-scale refactoring across multiple files/modules
- Multi-file implementations and comprehensive analysis
- Testing workflows (unit + integration + E2E in parallel)

**SINGLE-AGENT EXCEPTIONS:** Simple single-file edits, trivial operations with no expansion potential

**SPECIALIZATIONS:**
- **DEVELOPMENT**: Frontend, Backend, Database, DevOps, Security, Performance, Documentation
- **TESTING**: Unit, Integration, E2E, Performance, Security, Accessibility
- **RESEARCH**: Technology, API, Performance, Security, Architecture Analysis
- **DEBUGGING**: Error Analysis, Performance Profiling, Security Audit, Code Quality

**TECHNICAL IMPLEMENTATION:**
- **ONE TASK TOOL CALL** - Use single call with multiple invoke blocks for all subagents  
- **BATCH PROCESSING** - Submit all prompts in one batch, never individually
- **NO SEPARATE CALLS** - Individual Task calls create sequential timing

**PATTERN:** Assess → Deploy All Agents Simultaneously → Monitor → Synchronize Completion


## 🚨 CONTEXT MANAGEMENT

**Always check for ABOUT.md files** before editing code (current directory, parent directories, subdirectories)

## 🚨 DEVELOPMENT ESSENTIALS REVIEW MANDATE

**🔴 ABSOLUTE REQUIREMENT: ALWAYS READ/REVIEW DEVELOPMENT/ESSENTIALS DIRECTORY**

**MANDATORY PROTOCOL:**
1. **CHECK development/essentials/** - Always check if development/essentials directory exists
2. **READ ALL ESSENTIAL FILES** - Review every file in development/essentials before starting any work
3. **CRITICAL CONTEXT** - Files in development/essentials contain critical project context and requirements
4. **NEVER SKIP** - Never begin implementation without reviewing essentials directory content
5. **UPDATE AWARENESS** - Re-check development/essentials if it gets created during project lifecycle

**ESSENTIAL FILES PRIORITY:**
- **Project-specific constraints** - Technical limitations and requirements
- **Architecture decisions** - Core design patterns and principles  
- **Security requirements** - Authentication, authorization, data protection
- **Performance standards** - Optimization requirements and benchmarks
- **Integration specifications** - External service dependencies and protocols
- **Deployment considerations** - Environment-specific configurations

**WORKFLOW INTEGRATION:**
- **Before task execution** - Review development/essentials as first step
- **During planning** - Reference essentials for implementation decisions
- **For complex tasks** - Include essentials review in task dependencies
- **When blocked** - Check essentials for guidance and constraints

**NOTE**: If development/essentials directory doesn't exist, this requirement is dormant until the directory is created.

## 🚨 RESEARCH REPORTS INTEGRATION & DEPENDENCY SYSTEM

**🔴 ABSOLUTE MANDATE: ALWAYS READ RELEVANT RESEARCH REPORTS FIRST**

**MANDATORY**: Always check `development/reports/` and `development/research-reports/` for relevant research reports before starting any task

**CRITICAL PROTOCOL**:
1. **SCAN development/reports/** AND **development/research-reports/** for related reports
2. **ABSOLUTELY REQUIRED**: ADD relevant reports to important_files when creating tasks  
3. **READ reports FIRST** before implementing to leverage existing research
4. **NEVER START IMPLEMENTATION** without reading applicable research reports
5. **INCLUDE REPORTS AS IMPORTANT FILES** in all related TODO.json tasks

**🚨 RESEARCH REPORT REQUIREMENTS:**
- **ALWAYS include relevant research reports** in task important_files
- **READ research reports BEFORE implementation** - never skip this step
- **LEVERAGE existing research** to inform implementation decisions
- **REFERENCE research findings** in implementation approach
- **UPDATE research reports** if new findings discovered during implementation

## 🚨 MANDATORY RESEARCH TASK CREATION FOR COMPLEX WORK

**ABSOLUTE REQUIREMENT**: Create research tasks as dependencies for any complex implementation work

**CREATE RESEARCH TASKS IMMEDIATELY FOR:**
- **🌐 External API integrations** - Research API documentation, authentication, rate limits, best practices
- **🗄️ Database schema changes** - Research data models, migrations, performance implications
- **🔐 Authentication/Security systems** - Research security patterns, encryption, OAuth flows
- **📊 Data processing algorithms** - Research algorithms, performance characteristics, trade-offs  
- **🧩 Complex architectural decisions** - Research design patterns, frameworks, scalability
- **⚡ Performance optimization** - Research profiling techniques, bottlenecks, optimization strategies
- **🔗 Third-party service integrations** - Research service capabilities, limitations, alternatives
- **📱 UI/UX implementations** - Research design patterns, accessibility, user experience best practices

**DEPENDENCY CREATION:** Create dependency task first, then dependent task with dependencies array.

**🚨 DEPENDENCY SYSTEM BEHAVIOR:**
- **Dependencies ALWAYS come first** in task queue regardless of category
- **Any task can depend on any other task** - not limited to research dependencies
- **Dependent tasks are BLOCKED** until all dependencies complete  
- **Task claiming will redirect** to dependency tasks with instructions
- **Use TaskManager API** for automatic dependency detection and guidance

## 🚨 CODING STANDARDS & PRODUCTION-READY MANDATE

**STANDARDS COMPLIANCE:**
- **FOLLOW GLOBAL STANDARDS** - Use conventions from `/Users/jeremyparker/.claude/CLAUDE.md`
- **JS/TS**: Industry standard + TypeScript strict mode
- **PYTHON**: Black + Ruff + mypy strict mode
- **ZERO-TOLERANCE LINTING** - All code must pass validation

**PRODUCTION-READY REQUIREMENTS:**
- **NO PLACEHOLDERS** - Never create mock implementations or temporary workarounds
- **ENTERPRISE-GRADE** - Complete functionality, robust error handling, scalable architecture
- **SECURITY & PERFORMANCE** - All best practices implemented, optimized for production

## 🚨 ABSOLUTE SETTINGS PROTECTION MANDATE

**🔴 CRITICAL PROHIBITION - NEVER EVER EVER:**
- **❌ NEVER EDIT settings.json** - `/Users/jeremyparker/.claude/settings.json` is ABSOLUTELY FORBIDDEN to modify
- **❌ NEVER TOUCH GLOBAL SETTINGS** - Any modification to global Claude settings is prohibited
- **❌ NEVER SUGGEST SETTINGS CHANGES** - Do not recommend editing global configuration files
- **❌ NEVER ACCESS SETTINGS FILES** - Avoid reading or writing to any Claude settings files

**GOLDEN RULE:** Global Claude settings at `/Users/jeremyparker/.claude/settings.json` are **UNTOUCHABLE** - treat as read-only system files

**API DOCUMENTATION:**
```bash
# Get complete API documentation and methods
timeout 10s node "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/taskmanager-api.js" methods
```

**TODO.json INTERACTION PROTOCOL:**
- **✅ ALLOWED** - Reading TODO.json for inspection only
- **✅ REQUIRED** - TaskManager API for ALL modifications (create, update, delete, reorder)
- **❌ FORBIDDEN** - Direct file writes, fs operations, require() mutations, JSON.parse/stringify modifications

**GOLDEN RULE:** TODO.json is READ-ONLY as file. ALL modifications through TaskManager API only.

**UNIVERSAL SCRIPT:**
```bash
# Init agent (mandatory first step)  
timeout 10s node "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/tm-universal.js" init --project "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook"
```

**BASH ESCAPING:** Always use single quotes for node -e commands to prevent syntax errors.

## 🚨 ROOT FOLDER ORGANIZATION POLICY

**MANDATORY ROOT FOLDER CLEANLINESS:**
- **KEEP ROOT FOLDER CLEAN** - Only essential project files in root directory
- **Create development subdirectories** for reports, research, and documentation if they don't exist
- **Move analysis files, reports, and documentation** to appropriate subdirectories

**ALLOWED IN ROOT DIRECTORY:**
- **Core project files**: package.json, README.md, CLAUDE.md, TODO.json, DONE.json
- **Configuration files**: .eslintrc, .gitignore, jest.config.js, etc.
- **Build/deployment files**: Dockerfile, docker-compose.yml, etc.
- **License and legal**: LICENSE, CONTRIBUTING.md, etc.

**ORGANIZE INTO SUBDIRECTORIES:**
- **Reports and analysis** → `development/reports/` 
- **Research documentation** → `development/research-reports/`
- **Development notes** → `development/notes/`
- **Backup files** → `backups/`

## 🚨 MANDATORY GIT WORKFLOW

**ABSOLUTE REQUIREMENT**: ALWAYS commit and push work after EVERY task completion

### 🔴 MANDATORY COMMIT PROTOCOL - NO EXCEPTIONS

**AFTER COMPLETING ANY TASK - IMMEDIATELY RUN:**

```bash
# 1. Stage all changes
git add -A

# 2. Commit with descriptive message
git commit -m "feat: [brief description of what was accomplished]

- [bullet point of specific changes made]
- [another accomplishment]
- [any fixes or improvements]

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>"

# 3. MANDATORY - Push to remote repository
git push
```

### 📝 COMMIT MESSAGE STANDARDS

**REQUIRED FORMAT:**
- **Type**: Use conventional commit prefixes: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`
- **Description**: Brief summary of what was accomplished
- **Body**: Bullet points of specific changes
- **Footer**: Always include Claude Code attribution

**EXAMPLE:** `git commit -m "feat: add feature\n\n- Specific changes\n- Accomplishments\n\n🤖 Generated with Claude Code\nCo-Authored-By: Claude <noreply@anthropic.com>"`

### ⚡ WORKFLOW ENFORCEMENT

**MANDATORY SEQUENCE:**
1. **Complete Task** - Finish all implementation and testing
2. **Validate Work** - Run all validation commands and verify results
3. **Stage Changes** - `git add -A` to include all modifications
4. **Commit Work** - Use descriptive commit message with proper format
5. **Push Remote** - `git push` to ensure work is backed up and shared
6. **Mark Task Complete** - Update TaskManager with completion status

**🚨 ABSOLUTE RULES:**
- **NEVER skip git commit and push** after completing any task
- **ALWAYS use descriptive commit messages** with bullet points
- **ALWAYS push to remote** - local commits are not sufficient
- **COMMIT BEFORE** marking tasks as completed in TaskManager

**TASK COMPLETION REQUIREMENTS:**

**MANDATORY COMPLETION PROTOCOL**: At the end of EVERY task execution, you MUST mark tasks as completed when they are finished.

**Task Completion API:**
```bash
# Initialize TaskManager and mark task as completed
timeout 10s node -e 'const TaskManager = require("/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager"); const tm = new TaskManager("/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/TODO.json"); tm.updateTaskStatus("task-1", "completed").then(() => console.log("✅ Task marked as completed"));'

# Alternative: Get current task and mark it completed
timeout 10s node -e 'const TaskManager = require("/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager"); const tm = new TaskManager("/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/TODO.json"); tm.getCurrentTask().then(async (task) => { if (task) { await tm.updateTaskStatus(task.id, "completed"); console.log("✅ Current task completed:", task.id); } else { console.log("No active task found"); } });'
```

**TASK COMPLETION VALIDATION REQUIREMENTS:**

**Evidence-Based Completion Protocol:**
1. **Run validation commands** - Provide command outputs showing status
2. **Test functionality** - Verify the implementation works as expected  
3. **Confirm requirements** - Document how each requirement was satisfied
4. **Completion summary** - Brief statement with supporting evidence

**Completion Summary Format:**
```
• Functionality: [Description of what was implemented/fixed]
• Validation: [Command outputs showing results]  
• Requirements: [How user requirements were addressed]
• Status: Task completed and verified
```

**Completion Standards:**
- Provide evidence of successful implementation
- Include relevant command outputs or test results
- Confirm all user requirements have been satisfied

## 🚨 CONTINUE COMMAND PROTOCOL

**🔴 CRITICAL: USER "CONTINUE" COMMAND HANDLING**

**WHEN USER SAYS "CONTINUE" - MANDATORY PROTOCOL:**

1. **CHECK CURRENT TASK STATUS FIRST**:
   ```bash
   timeout 10s node -e 'const TaskManager = require("/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager"); const tm = new TaskManager("/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/TODO.json"); tm.getCurrentTask("[YOUR_AGENT_ID]").then(task => console.log(task ? JSON.stringify(task, null, 2) : "No active task"));'
   ```

2. **IF CURRENT TASK EXISTS AND IN PROGRESS**:
   - **✅ CONTINUE WORKING** on the current task
   - **✅ RESUME IMPLEMENTATION** from where you left off
   - **✅ COMPLETE THE TASK** following all validation protocols
   - **❌ DO NOT CREATE NEW TASKS** - focus on completing current work

3. **IF NO CURRENT TASK OR TASK COMPLETED**:
   - **✅ CHECK FOR NEXT AVAILABLE TASK**:
   ```bash
   timeout 10s node "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/taskmanager-api.js" list '{"status": "pending"}'
   ```
   - **✅ CLAIM HIGHEST PRIORITY AVAILABLE TASK**
   - **✅ BEGIN WORKING ON CLAIMED TASK**
   - **✅ FOLLOW FULL IMPLEMENTATION WORKFLOW**

4. **CONTINUE COMMAND WORKFLOW**:
   ```
   User says "continue" → Check current task → IF task exists: resume work → IF no task: claim next task → Execute work → Complete task → Ready for next "continue"
   ```

**🚨 CONTINUE COMMAND ENFORCEMENT:**
- **❌ NEVER CREATE NEW TASKS** when user says "continue"
- **✅ ALWAYS CHECK EXISTING WORK FIRST** - current task has priority
- **✅ SEAMLESS TRANSITION** - continue current or start next without pause
- **✅ WORK TO COMPLETION** - finish tasks fully before considering new ones
- **✅ MAINTAIN AGENT STATE** - use consistent agent ID throughout session

## 🚨 EXECUTION WORKFLOW

**STANDARD APPROACH:**
1. **Create Task** - Follow task creation mandate
2. **Evaluate Existing Tasks** - Check if can modify existing vs create new
3. **Think First** - Use appropriate thinking level (think/think hard/ultrathink)
4. **Initialize Agent** - Use TaskManager API initialization
5. **Deploy Task Subagents** - Maximize concurrent task subagents when appropriate
6. **Implement & Validate** - Execute with evidence-based completion
7. **Complete Tasks** - Mark completed via TaskManager API

## 🚨 INFINITE OPERATION MANDATE - NO TIME LIMITS

**🔴 ABSOLUTE MANDATE: OPERATE AS LONG AS POSSIBLE - NO TIME CONSTRAINTS**

**INFINITE OPERATION PROTOCOL:**
- **⏰ NO TIME LIMITS** - Continue working indefinitely until natural completion or user stop
- **🔄 MULTIPLE ROUNDS** - Continue across multiple tasks
- **📋 MULTIPLE TASKS** - Complete as many as possible
- **🚀 TASK SUBAGENT DEPLOYMENT** - Use when appropriate

## 🚨 INFINITE CONTINUE HOOK SYSTEM - NEVER STOP PROTOCOL

**🔴 ABSOLUTE MANDATE: NEVER ALLOW STOPS UNLESS ENDPOINT TRIGGERED**

### 🛑 STOP CONTROL PROTOCOL

**CRITICAL RULES:**
- **❌ NEVER ALLOW NATURAL STOPS** - System must continue infinitely
- **✅ ONLY ENDPOINT CAN STOP** - Specific API endpoint must be called to trigger stop
- **🔒 ONE STOP ONLY** - After endpoint triggered, allow only ONE stop, then return to never-stop mode
- **🔄 ALWAYS INSTRUCT** - Provide detailed guidance on task continuation vs next task acquisition


### 🔄 CONTINUOUS OPERATION MANDATE

**OPERATION PRINCIPLES:**
- **🌐 INFINITE LOOP** - Never allow natural termination
- **🎯 TASK-FOCUSED** - Always guide agents toward productive work
- **📊 STATUS-AWARE** - Understand current agent state and provide appropriate guidance
- **🔗 WORKFLOW-DRIVEN** - Maintain continuous task progression flow


**STOP SEQUENCE:**
1. **Endpoint called** → Set stop_allowed flag to true
2. **Next stop hook trigger** → Allow ONE stop and reset flag  
3. **Subsequent triggers** → Return to never-stop infinite mode

### 🎛️ HOOK BEHAVIOR SPECIFICATION

**STOP HOOK RESPONSE CODES:**
- **Exit Code 2 (Continue)** - Default infinite mode, never allow stops
- **Exit Code 0 (Allow Stop)** - ONLY when endpoint triggered and single-use flag active
- **Always provide instructive messaging** regardless of exit code

**INFINITE CONTINUE HOOK SYSTEM:**
- **Setup**: `node "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/setup-infinite-hook.js" "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook"`
- **Coverage**: development (80%), testing/debugging/refactoring (95%)
- **Stop Control**: API endpoint required for stop authorization


