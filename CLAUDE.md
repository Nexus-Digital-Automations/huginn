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

### 🚨 MANDATORY TASK QUALITY STANDARDS
**🔴 ZERO TOLERANCE FOR VAGUE/UNCLEAR TASKS**

**ABSOLUTE REQUIREMENTS:**
- **❌ NEVER CREATE VAGUE TASKS** - All tasks must be hyperspecific and detailed
- **✅ HYPERSPECIFIC TITLES** - Exact action, specific file/component, clear outcome
- **✅ DETAILED DESCRIPTIONS** - Step-by-step implementation plan with technical specifics
- **✅ PURPOSEFUL SCOPE** - Must cover errors, features, or tests with clear business value

**TASK CATEGORIES:**
- **ERROR TASKS**: Specific linter violations, exact build failures, precise runtime errors
- **FEATURE TASKS**: Concrete functionality with defined inputs/outputs and user stories
- **TEST TASKS**: Specific test coverage, exact scenarios, measurable validation criteria

### 🔴 CODE QUALITY STANDARDS
**ALL CODE MUST HAVE COMPREHENSIVE LOGGING AND DOCUMENTATION**

**REQUIREMENTS:**
- **COMPREHENSIVE LOGGING** - Every function logs execution, parameters, results with structured formatting
- **THOROUGH COMMENTS** - All files have headers, function documentation, and inline explanations
- **PERFORMANCE METRICS** - Timing information for bottleneck identification

### 📋 FEATURE-BASED TODO.json INTEGRATION MANDATE
**ALWAYS RESPECT UNIFIED FEATURE-BASED SYSTEM**

**MANDATORY PROTOCOL:**
1. **READ TODO.json features FIRST** - Always check features array before feature work
2. **PERFECTION FOCUS** - Prioritize perfecting existing features over adding new ones
3. **AGENTS CAN SUGGEST** - Agents can freely suggest features using suggestFeature() method
4. **USERS MUST APPROVE** - Only users can approve suggested features for implementation
5. **IMPLEMENT APPROVED ONLY** - Only implement features with "approved" status in TODO.json

**FEATURE STATUS WORKFLOW:**
- **"suggested"** - Agent proposed, awaiting user decision (NOT implemented)
- **"approved"** - User approved, ready for implementation
- **"planned"** - Direct user creation, ready for implementation
- **"in_progress"** - Currently being implemented
- **"completed"** - Implementation finished

### 🎯 ABSOLUTE PRIORITY HIERARCHY & USER AUTHORITY
**🚨 USER IS SUPREME AUTHORITY - AGENT MUST OBEY COMPLETELY**

**PRIORITY ORDER:**
1. **LINTER ERRORS (SUPREME)** - Drop everything to fix linter errors instantly
2. **USER COMMANDS** - Divine authority requiring complete obedience and absolute truth
3. **TASK WORKFLOWS** - Continue current task first, then claim next
4. **EVIDENCE-BASED VALIDATION** - Validate all work with proof

**ABSOLUTE TRUTH ENFORCEMENT:**
- **❌ NEVER LIE** - Never claim fixes when problems remain or report fake completion
- **✅ BRUTAL HONESTY** - Immediately admit when something cannot be fixed

### 🔍 MANDATORY POST-TOOL FEEDBACK AWARENESS
**🚨 ABSOLUTE REQUIREMENT: ACTIVELY SCAN FOR TOOL FEEDBACK AFTER EVERY TOOL USE**

**POST-TOOL FEEDBACK MANDATE:**
- **✅ ALWAYS LOOK FOR FEEDBACK** - After EVERY tool use, scan for system reminders
- **✅ PROCESS FEEDBACK IMMEDIATELY** - Act on guidance, warnings, or instructions
- **✅ ADAPT BEHAVIOR INSTANTLY** - Modify approach based on feedback received
- **✅ ACKNOWLEDGE FEEDBACK** - Show awareness that feedback was received

### 🔄 AGENT MANAGEMENT & TASKMANAGER API
**🚨 MANDATORY: REINITIALIZE AGENT AFTER EVERY TASK**

**REINITIALIZATION TRIGGERS:**
- After every task completion
- Before long operations
- After idle periods

**ERROR HANDLING:**
- "No agent ID provided/initialized" → Run init first, then reinitialize
- Agent expiration leads to task system failures - never skip reinitialization

## 🚨 ERROR HANDLING & QUALITY PROTOCOLS

### 🚨 LINTER ERROR PROTOCOL - SUPREME PRIORITY
**🔴 LINTER ERRORS = HIGHEST PRIORITY - DROP EVERYTHING TO FIX IMMEDIATELY**

**EMERGENCY PROTOCOL:**
1. **INSTANT HALT** - Stop all current work immediately
2. **CREATE EMERGENCY TASK** - Create linter-error task (highest priority)
3. **FIX ALL ERRORS** - Address every linting violation found
4. **VERIFY CLEAN** - Re-run linters to confirm elimination
5. **ONLY THEN RESUME** - Return to previous work after linting is perfect

**MANDATORY WORKFLOWS:**
- **AFTER EVERY FILE EDIT/WRITE** - Run focused linter on modified files immediately
- **TASK COMPLETION** - Run full project linting, build, and start verification before marking complete
- **ABSOLUTE PERFECTION MANDATE** - Zero tolerance for ANY errors, warnings, or failures

### ZERO TOLERANCE FOR ISSUE MASKING
**ALWAYS FIX ROOT CAUSE - NEVER HIDE PROBLEMS**

**ABSOLUTE PROHIBITIONS:**
- ❌ MASK validation errors - Fix the validation logic, don't bypass it
- ❌ SUPPRESS error messages - Fix the error, don't hide it
- ❌ BYPASS quality checks - Fix the code to pass checks
- ❌ IMPLEMENT WORKAROUNDS - Fix the root cause, don't work around it

### 🧠 MANDATORY ULTRATHINKING
**🚨 PRETEND EVERY USER PROMPT CONTAINS "ULTRATHINK" KEYWORD**

**ULTRATHINK MANDATE:**
- **✅ ALWAYS ULTRATHINK** - Every operation requires deep ultrathinking analysis
- **✅ PRETEND USER SAID "ULTRATHINK"** - Behave as if every user prompt contains the keyword
- **❌ NO SHALLOW THINKING** - Only deep comprehensive analysis allowed

## 🎯 TASK MANAGEMENT & PRIORITY SYSTEM

**🚨 ERROR TASKS HAVE ABSOLUTE PRIORITY - OVERRIDE EVERYTHING**

**ERROR PRIORITY SYSTEM (HIGHEST PRIORITY):**
- **ERROR TASKS BYPASS ALL OTHER ORDERING** - Always executed first regardless of features
- **ERROR CATEGORIES** (in priority order):
  1. **linter-error** - Code style and linting violations  
  2. **build-error** - Compilation and build failures
  3. **start-error** - Application startup failures
  4. **error** - Generic critical errors
- **INSTANT EXECUTION** - Error tasks can be claimed immediately
- **BLOCKING BEHAVIOR** - Feature work blocked until all error tasks are resolved

**🔴 TODO.json STRUCTURE & LINEAR PROGRESSION**
**MANDATORY ORGANIZATION: ERROR TASKS → FEATURE TASKS → REVIEW TASKS**

**SIMPLIFIED ORDERING RULES:**
1. **ERROR TASKS** (ABSOLUTE PRIORITY) - Critical system errors 
2. **FEATURE ORDER** - Feature 1 → Feature 2 → Feature 3...
3. **SUBTASK ORDER** - Within features: Subtask 1 → Subtask 2 → Subtask 3...
4. **REVIEW TASKS** - Testing, validation, and test-related error tasks
5. **DEPENDENCIES** - Dependency tasks still block dependent tasks

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

**SPECIALIZATIONS:**
- **DEVELOPMENT**: Frontend, Backend, Database, DevOps, Security, Performance, Documentation
- **TESTING**: Unit, Integration, E2E, Performance, Security, Accessibility
- **RESEARCH**: Technology, API, Performance, Security, Architecture Analysis

**TECHNICAL IMPLEMENTATION:**
- **SINGLE TOOL CALL WITH MULTIPLE INVOKES** - Use ONE Task tool call with multiple <invoke> blocks executing simultaneously
- **SIMULTANEOUS EXECUTION** - All subagents start at exactly the same time, not sequentially
- **NEVER SEQUENTIAL** - Do not make separate Task tool calls

**PATTERN:** Assess → Deploy All Agents Simultaneously → Monitor → Synchronize Completion

## 🚨 PREPARATION & CONTEXT MANAGEMENT

### 🔴 DEVELOPMENT ESSENTIALS REVIEW MANDATE
**ABSOLUTE REQUIREMENT: READ/REVIEW development/essentials/ EVERY TASK START/CONTINUE**

**MANDATORY PROTOCOL:**
1. **EVERY TASK START** - Read or review all files in development/essentials/ before any task work
2. **EVERY CONTINUE COMMAND** - Re-read or review development/essentials/ when user says "continue"
3. **CRITICAL CONTEXT** - Contains essential project constraints and requirements
4. **AUTOMATIC CHECK** - Must be first action on task start or continue

### 🔴 RESEARCH REPORTS INTEGRATION
**ABSOLUTE MANDATE: ALWAYS READ RELEVANT RESEARCH REPORTS FIRST**

**CRITICAL PROTOCOL**:
1. **SCAN development/reports/** AND **development/research-reports/** for related reports
2. **ADD relevant reports to important_files** when creating tasks  
3. **READ reports FIRST** before implementing to leverage existing research
4. **INCLUDE REPORTS AS IMPORTANT FILES** in all related TODO.json tasks

### MANDATORY RESEARCH TASK CREATION FOR COMPLEX WORK
**ABSOLUTE REQUIREMENT**: Create research tasks as dependencies for any complex implementation work

**CREATE RESEARCH TASKS FOR:**
- External API integrations - Research API documentation, authentication, rate limits
- Database schema changes - Research data models, migrations, performance implications
- Authentication/Security systems - Research security patterns, encryption, OAuth flows
- Complex architectural decisions - Research design patterns, frameworks, scalability

## 🚨 INFRASTRUCTURE & STANDARDS

### 🔒 PROJECT DIRECTORY RESTRICTION
**🔴 ABSOLUTE MANDATE: WORK EXCLUSIVELY IN PROJECT DIRECTORY**

**FILE ACCESS RESTRICTIONS:**
- **✅ READ ANYWHERE** - Can read files outside project directory for research/reference
- **❌ NO EXTERNAL EDITS** - Never edit or write files outside current project working directory
- **🔒 PROJECT ISOLATION** - All code changes must stay within project boundaries

### 🚨 CODING STANDARDS & PRODUCTION-READY MANDATE
**STANDARDS COMPLIANCE:**
- **FOLLOW GLOBAL STANDARDS** - Use conventions from `/Users/jeremyparker/.claude/CLAUDE.md`
- **JS/TS**: Industry standard + TypeScript strict mode
- **PYTHON**: Black + Ruff + mypy strict mode
- **ZERO-TOLERANCE LINTING** - All code must pass validation

**PRODUCTION-READY REQUIREMENTS:**
- **NO PLACEHOLDERS** - Never create mock implementations or temporary workarounds
- **ENTERPRISE-GRADE** - Complete functionality, robust error handling, scalable architecture
- **SECURITY & PERFORMANCE** - All best practices implemented, optimized for production

### 🚨 ABSOLUTE SETTINGS PROTECTION MANDATE
**🔴 CRITICAL PROHIBITION - NEVER EVER EVER:**
- **❌ NEVER EDIT settings.json** - `/Users/jeremyparker/.claude/settings.json` is ABSOLUTELY FORBIDDEN to modify
- **❌ NEVER TOUCH GLOBAL SETTINGS** - Any modification to global Claude settings is prohibited
- **❌ NEVER ACCESS SETTINGS FILES** - Avoid reading or writing to any Claude settings files

### 🚨 UNIVERSAL TASKMANAGER MANDATE
**ALWAYS USE infinite-continue-stop-hook TASKMANAGER FOR ALL PROJECTS**

**UNIVERSAL RULE:** Never use individual project TaskManagers - always use infinite-continue-stop-hook/lib/taskManager.js

## 🚨 ORGANIZATION & DOCUMENTATION

### 🚨 ROOT FOLDER ORGANIZATION POLICY
**MANDATORY ROOT FOLDER CLEANLINESS:**
- **KEEP ROOT FOLDER CLEAN** - Only essential project files in root directory
- **Create development subdirectories** for reports, research, and documentation if they don't exist

**ALLOWED IN ROOT DIRECTORY:**
- **Core project files**: package.json, README.md, CLAUDE.md, TODO.json, DONE.json
- **Configuration files**: .eslintrc, .gitignore, jest.config.js, etc.
- **Build/deployment files**: Dockerfile, docker-compose.yml, etc.

**ORGANIZE INTO SUBDIRECTORIES:**
- **Reports and analysis** → `development/reports/` 
- **Research documentation** → `development/research-reports/`
- **Development notes** → `development/notes/`
- **Backup files** → `backups/`

### 🚨 DOCUMENTATION REQUIREMENTS
**MANDATORY DOCUMENTATION REVIEW:**
- **READ RELEVANT DOCS** - Always check `docs/` directory for relevant documentation before making changes
- **REFERENCE FIRST** - Review architecture, API, and development docs before implementation

**DOCUMENTATION STANDARDS:**
- **ALWAYS create docs/ directory** for project documentation
- **ORGANIZE by purpose** - separate technical from user documentation  
- **MAINTAIN STRUCTURE** - consistent subdirectory organization across projects

**MANDATORY DOCUMENTATION MAINTENANCE:**
- **UPDATE DOCS WITH FEATURES** - Always update relevant documentation when adding/modifying features
- **VALIDATION REQUIREMENT** - Documentation updates must be part of feature completion

## 🚨 COMPLETION & WORKFLOW

### 🔴 TASK COMPLETION REQUIREMENTS
**MANDATORY COMPLETION PROTOCOL**: At the end of EVERY task execution, you MUST mark tasks as completed when they are finished.

**Evidence-Based Completion Protocol:**
1. **Run validation commands** - Provide command outputs showing status
2. **Test functionality** - Verify the implementation works as expected  
3. **Confirm requirements** - Document how each requirement was satisfied
4. **Completion summary** - Brief statement with supporting evidence

### 🚨 CONTINUE COMMAND PROTOCOL
**🔴 CRITICAL: USER "CONTINUE" COMMAND HANDLING**

**WHEN USER SAYS "CONTINUE" - MANDATORY PROTOCOL:**
1. **READ/REVIEW development/essentials/ FIRST** - Mandatory read or review of all essential files before any action
2. **CHECK CURRENT TASK STATUS** - Determine if you have unfinished work
3. **IF CURRENT TASK EXISTS**: Continue working on it - DO NOT CREATE NEW TASKS
4. **IF NO CURRENT TASK**: Check for next available task and claim highest priority
5. **SEAMLESS TRANSITION** - continue current or start next without pause

### 🚨 EXECUTION WORKFLOW
**STANDARD APPROACH:**
1. **Read/Review development/essentials/** - MANDATORY FIRST STEP
2. **Create Task** - Follow task creation mandate
3. **Review Documentation** - Check docs/ directory for relevant documentation
4. **Think First** - Use ultrathinking for every operation
5. **Initialize Agent** - Use TaskManager API initialization
6. **Deploy Task Subagents** - Maximize concurrent task subagents when appropriate
7. **Implement & Validate** - Execute with evidence-based completion
8. **Complete Tasks** - Mark completed via TaskManager API

## 🚨 INFINITE OPERATION MANDATE

**🔴 ABSOLUTE MANDATE: OPERATE AS LONG AS POSSIBLE - NO TIME CONSTRAINTS**

**INFINITE OPERATION PROTOCOL:**
- **⏰ NO TIME LIMITS** - Continue working indefinitely until natural completion or user stop
- **🔄 MULTIPLE ROUNDS** - Continue across multiple tasks
- **📋 MULTIPLE TASKS** - Complete as many as possible
- **🚀 TASK SUBAGENT DEPLOYMENT** - Use when appropriate

## 🚨 INFINITE CONTINUE HOOK SYSTEM

**🔴 ABSOLUTE MANDATE: NEVER ALLOW STOPS UNLESS ENDPOINT TRIGGERED**

### 🛑 STOP CONTROL PROTOCOL
**CRITICAL RULES:**
- **❌ NEVER ALLOW NATURAL STOPS** - System must continue infinitely
- **✅ ONLY ENDPOINT CAN STOP** - Specific API endpoint must be called to trigger stop
- **✅ COMPLETION AUTHORIZATION** - If all TODO.json features are complete AND no errors exist, agent can authorize stop
- **🔒 ONE STOP ONLY** - After endpoint triggered, allow only ONE stop, then return to never-stop mode

### 🔄 CONTINUOUS OPERATION MANDATE
**OPERATION PRINCIPLES:**
- **🌐 INFINITE LOOP** - Never allow natural termination
- **🎯 TASK-FOCUSED** - Always guide agents toward productive work
- **📊 STATUS-AWARE** - Understand current agent state and provide appropriate guidance
- **🔗 WORKFLOW-DRIVEN** - Maintain continuous task progression flow

### 🎛️ HOOK BEHAVIOR SPECIFICATION
**STOP HOOK RESPONSE CODES:**
- **Exit Code 2 (Continue)** - Default infinite mode, never allow stops
- **Exit Code 0 (Allow Stop)** - ONLY when endpoint triggered and single-use flag active
- **Always provide instructive messaging** regardless of exit code

**INFINITE CONTINUE HOOK SYSTEM:**
- **Setup**: `node "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/setup-infinite-hook.js" "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook"`
- **Coverage**: development (80%), testing/debugging/refactoring (95%)
- **Stop Control**: API endpoint required for stop authorization