/**
 * Huginn API JavaScript Client Library
 * 
 * A comprehensive JavaScript/Node.js client for interacting with the Huginn API.
 * Works in both browser and Node.js environments.
 * 
 * Usage:
 *   import { HuginnClient } from './huginn-client.js';
 *   
 *   const client = new HuginnClient('https://your-huginn.com', {
 *     sessionCookie: 'your-session-cookie'
 *   });
 *   
 *   const agents = await client.getAgents();
 *   await client.sendWebhook(1, 123, 'secret', { test: 'data' });
 */

// Check if we're in Node.js or browser environment
const isNode = typeof window === 'undefined' && typeof global !== 'undefined';

// Use appropriate fetch implementation
const fetch = isNode ? require('node-fetch') : window.fetch;

/**
 * Custom error class for Huginn API errors
 */
class HuginnAPIError extends Error {
    constructor(message, statusCode = null, responseText = null) {
        super(message);
        this.name = 'HuginnAPIError';
        this.statusCode = statusCode;
        this.responseText = responseText;
    }
}

/**
 * Huginn Agent class
 */
class Agent {
    constructor(data) {
        Object.assign(this, data);
    }

    /**
     * Check if agent is a WebhookAgent
     */
    isWebhookAgent() {
        return this.type === 'Agents::WebhookAgent';
    }

    /**
     * Check if agent is a DataOutputAgent
     */
    isDataOutputAgent() {
        return this.type === 'Agents::DataOutputAgent';
    }

    /**
     * Get webhook URL for this agent
     */
    getWebhookUrl(baseUrl, userId, secret) {
        return `${baseUrl}/users/${userId}/web_requests/${this.id}/${secret}`;
    }
}

/**
 * Huginn Event class
 */
class Event {
    constructor(data) {
        Object.assign(this, data);
        this.created_at = new Date(this.created_at);
        if (this.expires_at) {
            this.expires_at = new Date(this.expires_at);
        }
    }

    /**
     * Check if event has expired
     */
    isExpired() {
        return this.expires_at && this.expires_at < new Date();
    }
}

/**
 * Huginn Scenario class
 */
class Scenario {
    constructor(data) {
        Object.assign(this, data);
        this.created_at = new Date(this.created_at);
        this.updated_at = new Date(this.updated_at);
    }
}

/**
 * Main Huginn API Client
 */
class HuginnClient {
    /**
     * Initialize the Huginn client
     * 
     * @param {string} baseUrl - Base URL of your Huginn instance
     * @param {Object} options - Configuration options
     * @param {string} options.sessionCookie - Session cookie for authentication
     * @param {number} options.timeout - Request timeout in milliseconds (default: 30000)
     * @param {Object} options.headers - Additional headers to send with requests
     */
    constructor(baseUrl, options = {}) {
        this.baseUrl = baseUrl.replace(/\/$/, ''); // Remove trailing slash
        this.options = {
            timeout: 30000,
            headers: {},
            ...options
        };

        // Set default headers
        this.defaultHeaders = {
            'Content-Type': 'application/json',
            ...this.options.headers
        };

        // Add session cookie if provided
        if (this.options.sessionCookie) {
            if (isNode) {
                this.defaultHeaders['Cookie'] = `_huginn_session=${this.options.sessionCookie}`;
            } else {
                // In browser, cookies are handled automatically
                document.cookie = `_huginn_session=${this.options.sessionCookie}`;
            }
        }
    }

    /**
     * Make an HTTP request to the Huginn API
     * 
     * @param {string} method - HTTP method
     * @param {string} endpoint - API endpoint
     * @param {Object} options - Request options
     * @returns {Promise<Response>} - Fetch response
     */
    async _makeRequest(method, endpoint, options = {}) {
        const url = `${this.baseUrl}/${endpoint.replace(/^\//, '')}`;
        
        const requestOptions = {
            method,
            headers: { ...this.defaultHeaders, ...(options.headers || {}) },
            ...options
        };

        // Handle timeout
        let timeoutId;
        const timeoutPromise = new Promise((_, reject) => {
            timeoutId = setTimeout(
                () => reject(new Error(`Request timeout after ${this.options.timeout}ms`)),
                this.options.timeout
            );
        });

        try {
            const response = await Promise.race([
                fetch(url, requestOptions),
                timeoutPromise
            ]);

            clearTimeout(timeoutId);

            if (!response.ok) {
                const errorText = await response.text();
                throw new HuginnAPIError(
                    `HTTP ${response.status}: ${response.statusText}`,
                    response.status,
                    errorText
                );
            }

            return response;
        } catch (error) {
            clearTimeout(timeoutId);
            if (error instanceof HuginnAPIError) {
                throw error;
            }
            throw new HuginnAPIError(`Request failed: ${error.message}`);
        }
    }

    /**
     * GET request that returns JSON
     */
    async _getJson(endpoint, params = {}) {
        const url = new URL(endpoint, `${this.baseUrl}/`);
        Object.entries(params).forEach(([key, value]) => {
            if (value !== null && value !== undefined) {
                url.searchParams.append(key, value.toString());
            }
        });

        const response = await this._makeRequest('GET', url.pathname + url.search);
        return response.json();
    }

    /**
     * POST request with JSON data
     */
    async _postJson(endpoint, data = {}) {
        const response = await this._makeRequest('POST', endpoint, {
            body: JSON.stringify(data)
        });
        
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            return response.json();
        }
        return {};
    }

    /**
     * PUT request with JSON data
     */
    async _putJson(endpoint, data = {}) {
        const response = await this._makeRequest('PUT', endpoint, {
            body: JSON.stringify(data)
        });
        
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            return response.json();
        }
        return {};
    }

    /**
     * DELETE request
     */
    async _delete(endpoint, params = {}) {
        const url = new URL(endpoint, `${this.baseUrl}/`);
        Object.entries(params).forEach(([key, value]) => {
            if (value !== null && value !== undefined) {
                url.searchParams.append(key, value.toString());
            }
        });

        const response = await this._makeRequest('DELETE', url.pathname + url.search);
        return response.status === 200 || response.status === 204;
    }

    // Agent Management Methods

    /**
     * Get list of agents
     * 
     * @param {Object} options - Query options
     * @param {number} options.page - Page number
     * @param {string} options.sort - Sort field
     * @param {string} options.direction - Sort direction
     * @returns {Promise<Agent[]>} - Array of agents
     */
    async getAgents({ page = 1, sort = 'created_at', direction = 'desc' } = {}) {
        const agentsData = await this._getJson('/agents', { page, sort, direction });
        return agentsData.map(data => new Agent(data));
    }

    /**
     * Get a specific agent by ID
     * 
     * @param {number} agentId - Agent ID
     * @returns {Promise<Agent>} - Agent object
     */
    async getAgent(agentId) {
        const agentData = await this._getJson(`/agents/${agentId}`);
        return new Agent(agentData);
    }

    /**
     * Create a new agent
     * 
     * @param {Object} agentData - Agent data
     * @param {string} agentData.name - Agent name
     * @param {string} agentData.type - Agent type
     * @param {Object} agentData.options - Agent options
     * @returns {Promise<Agent>} - Created agent
     */
    async createAgent(agentData) {
        const createdAgent = await this._postJson('/agents', agentData);
        return new Agent(createdAgent);
    }

    /**
     * Update an existing agent
     * 
     * @param {number} agentId - Agent ID
     * @param {Object} updates - Agent updates
     * @returns {Promise<Agent>} - Updated agent
     */
    async updateAgent(agentId, updates) {
        const updatedAgent = await this._putJson(`/agents/${agentId}`, updates);
        return new Agent(updatedAgent);
    }

    /**
     * Delete an agent
     * 
     * @param {number} agentId - Agent ID
     * @returns {Promise<boolean>} - Success status
     */
    async deleteAgent(agentId) {
        return this._delete(`/agents/${agentId}`);
    }

    /**
     * Manually run an agent
     * 
     * @param {number} agentId - Agent ID
     * @returns {Promise<boolean>} - Success status
     */
    async runAgent(agentId) {
        const response = await this._makeRequest('POST', `/agents/${agentId}/run`);
        return response.status === 200;
    }

    /**
     * Re-emit all events from an agent
     * 
     * @param {number} agentId - Agent ID
     * @param {boolean} deleteOld - Whether to delete old events
     * @returns {Promise<boolean>} - Success status
     */
    async reemitAgentEvents(agentId, deleteOld = false) {
        const params = { delete_old_events: deleteOld ? '1' : '0' };
        const response = await this._makeRequest('POST', `/agents/${agentId}/reemit_events`, { 
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams(params).toString()
        });
        return response.status === 200;
    }

    /**
     * Clear all events from an agent
     * 
     * @param {number} agentId - Agent ID
     * @returns {Promise<boolean>} - Success status
     */
    async clearAgentEvents(agentId) {
        return this._delete(`/agents/${agentId}/remove_events`);
    }

    /**
     * Clear an agent's memory
     * 
     * @param {number} agentId - Agent ID
     * @returns {Promise<boolean>} - Success status
     */
    async clearAgentMemory(agentId) {
        return this._delete(`/agents/${agentId}/memory`);
    }

    /**
     * Get agent type details
     * 
     * @param {string} agentType - Agent type class name
     * @returns {Promise<Object>} - Agent type details
     */
    async getAgentTypeDetails(agentType) {
        return this._getJson('/agents/type_details', { type: agentType });
    }

    /**
     * Validate an agent option
     * 
     * @param {string} agentType - Agent type
     * @param {string} attribute - Attribute to validate
     * @param {Object} options - Agent options
     * @returns {Promise<boolean>} - Validation result
     */
    async validateAgentOption(agentType, attribute, options) {
        try {
            const response = await this._makeRequest('POST', '/agents/validate', {
                body: JSON.stringify({ type: agentType, options }),
                headers: { 
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: new URLSearchParams({ attribute }).toString()
            });
            const text = await response.text();
            return text.trim() === 'ok';
        } catch (error) {
            if (error.statusCode === 403) {
                return false;
            }
            throw error;
        }
    }

    // Webhook Methods

    /**
     * Send webhook data to an agent
     * 
     * @param {number} userId - User ID that owns the agent
     * @param {number} agentId - Target agent ID
     * @param {string} secret - Secret token
     * @param {Object} data - Payload data
     * @returns {Promise<Object>} - Response from agent
     */
    async sendWebhook(userId, agentId, secret, data) {
        const endpoint = `/users/${userId}/web_requests/${agentId}/${secret}`;
        
        try {
            const response = await this._makeRequest('POST', endpoint, {
                body: JSON.stringify(data)
            });
            
            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                return response.json();
            } else {
                return { 
                    response: await response.text(), 
                    status_code: response.status 
                };
            }
        } catch (error) {
            throw error;
        }
    }

    /**
     * Get data from a DataOutputAgent webhook
     * 
     * @param {number} userId - User ID
     * @param {number} agentId - Agent ID
     * @param {string} secret - Secret token
     * @param {string} format - Response format ('json' or 'xml')
     * @returns {Promise<Object|string>} - Feed data
     */
    async getWebhookFeed(userId, agentId, secret, format = 'json') {
        const endpoint = `/users/${userId}/web_requests/${agentId}/${secret}`;
        const response = await this._makeRequest('GET', endpoint + `?format=${format}`);
        
        if (format === 'json') {
            return response.json();
        } else {
            return response.text();
        }
    }

    // Event Methods

    /**
     * Get list of events
     * 
     * @param {Object} options - Query options
     * @param {number} options.page - Page number
     * @param {number} options.agentId - Filter by agent ID
     * @returns {Promise<Event[]>} - Array of events
     */
    async getEvents({ page = 1, agentId = null } = {}) {
        const params = { page };
        if (agentId) params.agent_id = agentId;
        
        const eventsData = await this._getJson('/events', params);
        return eventsData.map(data => new Event(data));
    }

    /**
     * Get a specific event by ID
     * 
     * @param {number} eventId - Event ID
     * @returns {Promise<Event>} - Event object
     */
    async getEvent(eventId) {
        const eventData = await this._getJson(`/events/${eventId}`);
        return new Event(eventData);
    }

    /**
     * Delete an event
     * 
     * @param {number} eventId - Event ID
     * @returns {Promise<boolean>} - Success status
     */
    async deleteEvent(eventId) {
        return this._delete(`/events/${eventId}`);
    }

    /**
     * Re-emit a specific event
     * 
     * @param {number} eventId - Event ID
     * @returns {Promise<boolean>} - Success status
     */
    async reemitEvent(eventId) {
        const response = await this._makeRequest('POST', `/events/${eventId}/reemit`);
        return response.status === 200;
    }

    // Scenario Methods

    /**
     * Get list of scenarios
     * 
     * @param {number} page - Page number
     * @returns {Promise<Scenario[]>} - Array of scenarios
     */
    async getScenarios(page = 1) {
        const scenariosData = await this._getJson('/scenarios', { page });
        return scenariosData.map(data => new Scenario(data));
    }

    /**
     * Get a specific scenario by ID
     * 
     * @param {number} scenarioId - Scenario ID
     * @returns {Promise<Scenario>} - Scenario object
     */
    async getScenario(scenarioId) {
        const scenarioData = await this._getJson(`/scenarios/${scenarioId}`);
        return new Scenario(scenarioData);
    }

    /**
     * Create a new scenario
     * 
     * @param {Object} scenarioData - Scenario data
     * @returns {Promise<Scenario>} - Created scenario
     */
    async createScenario(scenarioData) {
        const createdScenario = await this._postJson('/scenarios', scenarioData);
        return new Scenario(createdScenario);
    }

    /**
     * Update a scenario
     * 
     * @param {number} scenarioId - Scenario ID
     * @param {Object} updates - Scenario updates
     * @returns {Promise<boolean>} - Success status
     */
    async updateScenario(scenarioId, updates) {
        const response = await this._makeRequest('PUT', `/scenarios/${scenarioId}`, {
            body: JSON.stringify(updates)
        });
        return response.status === 200 || response.status === 204;
    }

    /**
     * Delete a scenario
     * 
     * @param {number} scenarioId - Scenario ID
     * @param {string} mode - Deletion mode
     * @returns {Promise<boolean>} - Success status
     */
    async deleteScenario(scenarioId, mode = 'scenario_only') {
        return this._delete(`/scenarios/${scenarioId}`, { mode });
    }

    /**
     * Export scenario as JSON
     * 
     * @param {number} scenarioId - Scenario ID
     * @returns {Promise<Object>} - Scenario export data
     */
    async exportScenario(scenarioId) {
        return this._getJson(`/scenarios/${scenarioId}/export`);
    }

    // System Methods

    /**
     * Get worker status information
     * 
     * @param {number} sinceId - Only count events after this ID
     * @returns {Promise<Object>} - Worker status data
     */
    async getWorkerStatus(sinceId = null) {
        const params = sinceId ? { since_id: sinceId } : {};
        return this._getJson('/worker_status', params);
    }

    // Convenience Methods

    /**
     * Create a WebhookAgent
     * 
     * @param {string} name - Agent name
     * @param {string} secret - Webhook secret
     * @param {Object} options - Additional options
     * @returns {Promise<Agent>} - Created agent
     */
    async createWebhookAgent(name, secret, options = {}) {
        const webhookOptions = {
            secret,
            expected_receive_period_in_days: 1,
            payload_path: '.',
            verbs: 'post',
            response: 'Event Created',
            ...options
        };

        return this.createAgent({
            name,
            type: 'Agents::WebhookAgent',
            options: webhookOptions
        });
    }

    /**
     * Create a DataOutputAgent
     * 
     * @param {string} name - Agent name
     * @param {string[]} secrets - Access secrets
     * @param {Object} template - RSS/JSON template
     * @param {Object} options - Additional options
     * @returns {Promise<Agent>} - Created agent
     */
    async createDataOutputAgent(name, secrets, template, options = {}) {
        const outputOptions = {
            secrets,
            expected_receive_period_in_days: 2,
            template,
            events_to_show: 20,
            ...options
        };

        return this.createAgent({
            name,
            type: 'Agents::DataOutputAgent',
            options: outputOptions
        });
    }

    /**
     * Monitor events in real-time
     * 
     * @param {Function} callback - Function to call for each event
     * @param {Object} options - Monitoring options
     * @param {number[]} options.agentIds - Agent IDs to monitor
     * @param {number} options.pollInterval - Polling interval in seconds
     */
    async monitorEvents(callback, { agentIds = null, pollInterval = 5 } = {}) {
        let lastEventId = 0;
        
        console.log(`Starting event monitor (polling every ${pollInterval}s)`);
        
        const poll = async () => {
            try {
                let events = [];
                
                if (agentIds) {
                    for (const agentId of agentIds) {
                        const agentEvents = await this.getEvents({ agentId });
                        events.push(...agentEvents);
                    }
                } else {
                    events = await this.getEvents();
                }
                
                const newEvents = events
                    .filter(event => event.id > lastEventId)
                    .sort((a, b) => a.id - b.id);
                
                for (const event of newEvents) {
                    try {
                        await callback(event);
                        lastEventId = Math.max(lastEventId, event.id);
                    } catch (error) {
                        console.error('Error in event callback:', error);
                    }
                }
                
            } catch (error) {
                console.error('Error polling events:', error);
            }
        };
        
        // Initial poll
        await poll();
        
        // Set up polling interval
        const intervalId = setInterval(poll, pollInterval * 1000);
        
        // Return cleanup function
        return () => {
            clearInterval(intervalId);
            console.log('Event monitoring stopped');
        };
    }
}

// Export for both Node.js and browser environments
if (isNode) {
    module.exports = { 
        HuginnClient, 
        HuginnAPIError, 
        Agent, 
        Event, 
        Scenario 
    };
} else {
    window.HuginnClient = HuginnClient;
    window.HuginnAPIError = HuginnAPIError;
    window.Agent = Agent;
    window.Event = Event;
    window.Scenario = Scenario;
}

// Usage Examples
if (isNode && require.main === module) {
    // Example usage in Node.js
    (async () => {
        const client = new HuginnClient('https://your-huginn.com', {
            sessionCookie: 'your-session-cookie'
        });

        try {
            // List agents
            const agents = await client.getAgents();
            console.log(`Found ${agents.length} agents`);

            // Create a webhook agent
            const webhookAgent = await client.createWebhookAgent(
                'Test Webhook Agent',
                'test-secret-123'
            );
            console.log(`Created webhook agent: ${webhookAgent.name} (ID: ${webhookAgent.id})`);

            // Send webhook data
            const webhookResponse = await client.sendWebhook(
                1,
                webhookAgent.id,
                'test-secret-123',
                { 
                    message: 'Hello from JavaScript client!', 
                    timestamp: new Date().toISOString() 
                }
            );
            console.log('Webhook response:', webhookResponse);

            // Monitor events for 30 seconds
            const stopMonitoring = await client.monitorEvents(
                (event) => console.log(`New event: ${event.id} from agent ${event.agent_id}`),
                { pollInterval: 2 }
            );

            // Stop monitoring after 30 seconds
            setTimeout(stopMonitoring, 30000);

        } catch (error) {
            console.error('Error:', error.message);
        }
    })();
}