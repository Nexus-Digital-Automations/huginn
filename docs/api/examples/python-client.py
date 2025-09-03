#!/usr/bin/env python3
"""
Huginn API Python Client Library

A comprehensive Python client for interacting with the Huginn API.
Provides methods for agent management, webhook sending, event monitoring, and more.

Usage:
    from huginn_client import HuginnClient

    client = HuginnClient('https://your-huginn.com', session_cookie='your-session-cookie')
    agents = client.get_agents()
    client.send_webhook(user_id=1, agent_id=123, secret='secret', data={'test': 'data'})
"""

import requests
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from urllib.parse import urljoin


@dataclass
class Agent:
    """Represents a Huginn agent"""

    id: int
    name: str
    type: str
    options: Dict[str, Any]
    disabled: bool = False
    schedule: Optional[str] = None
    keep_events_for: int = 0
    last_check_at: Optional[str] = None
    last_event_at: Optional[str] = None
    last_receive_at: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    memory: Optional[Dict[str, Any]] = None
    source_ids: Optional[List[int]] = None
    receiver_ids: Optional[List[int]] = None


@dataclass
class Event:
    """Represents a Huginn event"""

    id: int
    agent_id: int
    payload: Dict[str, Any]
    created_at: str
    expires_at: Optional[str] = None


@dataclass
class Scenario:
    """Represents a Huginn scenario"""

    id: int
    name: str
    description: Optional[str] = None
    public: bool = False
    guid: Optional[str] = None
    tag_fg_color: Optional[str] = None
    tag_bg_color: Optional[str] = None
    icon: Optional[str] = None
    source_url: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    user_id: Optional[int] = None


class HuginnAPIError(Exception):
    """Base exception for Huginn API errors"""

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        response_text: Optional[str] = None,
    ):
        self.message = message
        self.status_code = status_code
        self.response_text = response_text
        super().__init__(self.message)


class HuginnClient:
    """
    Huginn API Client

    Provides a comprehensive interface for interacting with Huginn's REST API.
    """

    def __init__(
        self, base_url: str, session_cookie: Optional[str] = None, timeout: int = 30
    ):
        """
        Initialize the Huginn client

        Args:
            base_url: Base URL of your Huginn instance (e.g., 'https://your-huginn.com')
            session_cookie: Session cookie for authentication
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

        if session_cookie:
            self.session.cookies.set("_huginn_session", session_cookie)

    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make an HTTP request to the Huginn API"""
        url = urljoin(self.base_url + "/", endpoint.lstrip("/"))

        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("headers", {})

        if "json" in kwargs:
            kwargs["headers"]["Content-Type"] = "application/json"

        try:
            response = self.session.request(method, url, **kwargs)

            if response.status_code >= 400:
                raise HuginnAPIError(
                    f"HTTP {response.status_code}: {response.reason}",
                    response.status_code,
                    response.text,
                )

            return response

        except requests.exceptions.RequestException as e:
            raise HuginnAPIError(f"Request failed: {str(e)}")

    def _get_json(self, endpoint: str, **kwargs) -> Union[Dict, List]:
        """GET request that returns JSON"""
        response = self._make_request("GET", endpoint, **kwargs)
        return response.json()

    def _post_json(self, endpoint: str, data: Dict, **kwargs) -> Union[Dict, List]:
        """POST request with JSON data"""
        response = self._make_request("POST", endpoint, json=data, **kwargs)
        return response.json() if response.content else {}

    def _put_json(self, endpoint: str, data: Dict, **kwargs) -> Union[Dict, List]:
        """PUT request with JSON data"""
        response = self._make_request("PUT", endpoint, json=data, **kwargs)
        return response.json() if response.content else {}

    def _delete(self, endpoint: str, **kwargs) -> bool:
        """DELETE request"""
        response = self._make_request("DELETE", endpoint, **kwargs)
        return response.status_code in [200, 204]

    # Agent Management Methods

    def get_agents(
        self, page: int = 1, sort: str = "created_at", direction: str = "desc"
    ) -> List[Agent]:
        """
        Get list of agents

        Args:
            page: Page number for pagination
            sort: Sort field (name, created_at, last_check_at, last_event_at, last_receive_at)
            direction: Sort direction (asc, desc)

        Returns:
            List of Agent objects
        """
        params = {"page": page, "sort": sort, "direction": direction}
        agents_data = self._get_json("/agents", params=params)

        return [Agent(**agent) for agent in agents_data]

    def get_agent(self, agent_id: int) -> Agent:
        """
        Get a specific agent by ID

        Args:
            agent_id: Agent ID

        Returns:
            Agent object
        """
        agent_data = self._get_json(f"/agents/{agent_id}")
        return Agent(**agent_data)

    def create_agent(
        self, name: str, agent_type: str, options: Dict[str, Any], **kwargs
    ) -> Agent:
        """
        Create a new agent

        Args:
            name: Agent name
            agent_type: Agent type (e.g., 'Agents::WebhookAgent')
            options: Agent-specific options
            **kwargs: Additional agent properties (schedule, disabled, etc.)

        Returns:
            Created Agent object
        """
        agent_data = {"name": name, "type": agent_type, "options": options, **kwargs}

        created_agent = self._post_json("/agents", agent_data)
        return Agent(**created_agent)

    def update_agent(self, agent_id: int, **kwargs) -> Agent:
        """
        Update an existing agent

        Args:
            agent_id: Agent ID
            **kwargs: Agent properties to update

        Returns:
            Updated Agent object
        """
        updated_agent = self._put_json(f"/agents/{agent_id}", kwargs)
        return Agent(**updated_agent)

    def delete_agent(self, agent_id: int) -> bool:
        """
        Delete an agent

        Args:
            agent_id: Agent ID

        Returns:
            True if successful
        """
        return self._delete(f"/agents/{agent_id}")

    def run_agent(self, agent_id: int) -> bool:
        """
        Manually run an agent

        Args:
            agent_id: Agent ID

        Returns:
            True if successful
        """
        response = self._make_request("POST", f"/agents/{agent_id}/run")
        return response.status_code == 200

    def reemit_agent_events(self, agent_id: int, delete_old: bool = False) -> bool:
        """
        Re-emit all events from an agent

        Args:
            agent_id: Agent ID
            delete_old: Whether to delete old events

        Returns:
            True if successful
        """
        params = {"delete_old_events": "1" if delete_old else "0"}
        response = self._make_request(
            "POST", f"/agents/{agent_id}/reemit_events", params=params
        )
        return response.status_code == 200

    def clear_agent_events(self, agent_id: int) -> bool:
        """
        Remove all events from an agent

        Args:
            agent_id: Agent ID

        Returns:
            True if successful
        """
        return self._delete(f"/agents/{agent_id}/remove_events")

    def clear_agent_memory(self, agent_id: int) -> bool:
        """
        Clear an agent's memory

        Args:
            agent_id: Agent ID

        Returns:
            True if successful
        """
        return self._delete(f"/agents/{agent_id}/memory")

    def get_agent_type_details(self, agent_type: str) -> Dict[str, Any]:
        """
        Get details about a specific agent type

        Args:
            agent_type: Agent type class name

        Returns:
            Agent type details including default options and capabilities
        """
        params = {"type": agent_type}
        return self._get_json("/agents/type_details", params=params)

    def validate_agent_option(
        self, agent_type: str, attribute: str, options: Dict[str, Any]
    ) -> bool:
        """
        Validate an agent option

        Args:
            agent_type: Agent type class name
            attribute: Option attribute to validate
            options: Agent options to validate

        Returns:
            True if valid
        """
        data = {"type": agent_type, "options": options}
        params = {"attribute": attribute}

        try:
            response = self._make_request(
                "POST", "/agents/validate", json=data, params=params
            )
            return response.text.strip() == "ok"
        except HuginnAPIError as e:
            if e.status_code == 403:
                return False
            raise

    # Webhook Methods

    def send_webhook(
        self, user_id: int, agent_id: int, secret: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Send webhook data to an agent

        Args:
            user_id: User ID that owns the agent
            agent_id: Target agent ID
            secret: Secret token for authentication
            data: Payload data to send

        Returns:
            Response from the agent
        """
        url = f"/users/{user_id}/web_requests/{agent_id}/{secret}"
        response = self._make_request("POST", url, json=data)

        try:
            return response.json()
        except ValueError:
            return {"response": response.text, "status_code": response.status_code}

    def get_webhook_feed(
        self, user_id: int, agent_id: int, secret: str, format: str = "json"
    ) -> Union[Dict, str]:
        """
        Get data from a DataOutputAgent webhook

        Args:
            user_id: User ID that owns the agent
            agent_id: Agent ID
            secret: Secret token for authentication
            format: Response format ('json' or 'xml')

        Returns:
            Feed data (JSON dict or XML string)
        """
        url = f"/users/{user_id}/web_requests/{agent_id}/{secret}"
        params = {"format": format}

        response = self._make_request("GET", url, params=params)

        if format == "json":
            return response.json()
        else:
            return response.text

    # Event Methods

    def get_events(self, page: int = 1, agent_id: Optional[int] = None) -> List[Event]:
        """
        Get list of events

        Args:
            page: Page number for pagination
            agent_id: Filter by specific agent ID

        Returns:
            List of Event objects
        """
        params = {"page": page}
        if agent_id:
            params["agent_id"] = agent_id

        events_data = self._get_json("/events", params=params)
        return [Event(**event) for event in events_data]

    def get_event(self, event_id: int) -> Event:
        """
        Get a specific event by ID

        Args:
            event_id: Event ID

        Returns:
            Event object
        """
        event_data = self._get_json(f"/events/{event_id}")
        return Event(**event_data)

    def delete_event(self, event_id: int) -> bool:
        """
        Delete an event

        Args:
            event_id: Event ID

        Returns:
            True if successful
        """
        return self._delete(f"/events/{event_id}")

    def reemit_event(self, event_id: int) -> bool:
        """
        Re-emit a specific event

        Args:
            event_id: Event ID

        Returns:
            True if successful
        """
        response = self._make_request("POST", f"/events/{event_id}/reemit")
        return response.status_code == 200

    # Scenario Methods

    def get_scenarios(self, page: int = 1) -> List[Scenario]:
        """
        Get list of scenarios

        Args:
            page: Page number for pagination

        Returns:
            List of Scenario objects
        """
        params = {"page": page}
        scenarios_data = self._get_json("/scenarios", params=params)
        return [Scenario(**scenario) for scenario in scenarios_data]

    def get_scenario(self, scenario_id: int) -> Scenario:
        """
        Get a specific scenario by ID

        Args:
            scenario_id: Scenario ID

        Returns:
            Scenario object
        """
        scenario_data = self._get_json(f"/scenarios/{scenario_id}")
        return Scenario(**scenario_data)

    def create_scenario(self, name: str, description: str = "", **kwargs) -> Scenario:
        """
        Create a new scenario

        Args:
            name: Scenario name
            description: Scenario description
            **kwargs: Additional scenario properties

        Returns:
            Created Scenario object
        """
        scenario_data = {"name": name, "description": description, **kwargs}

        created_scenario = self._post_json("/scenarios", scenario_data)
        return Scenario(**created_scenario)

    def update_scenario(self, scenario_id: int, **kwargs) -> bool:
        """
        Update a scenario

        Args:
            scenario_id: Scenario ID
            **kwargs: Scenario properties to update

        Returns:
            True if successful
        """
        response = self._make_request("PUT", f"/scenarios/{scenario_id}", json=kwargs)
        return response.status_code in [200, 204]

    def delete_scenario(self, scenario_id: int, mode: str = "scenario_only") -> bool:
        """
        Delete a scenario

        Args:
            scenario_id: Scenario ID
            mode: Deletion mode ('scenario_only' or 'agents_and_scenario')

        Returns:
            True if successful
        """
        params = {"mode": mode}
        return self._delete(f"/scenarios/{scenario_id}", params=params)

    def export_scenario(self, scenario_id: int) -> Dict[str, Any]:
        """
        Export scenario as JSON

        Args:
            scenario_id: Scenario ID

        Returns:
            Scenario export data
        """
        return self._get_json(f"/scenarios/{scenario_id}/export")

    # System Methods

    def get_worker_status(self, since_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Get worker status information

        Args:
            since_id: Only count events with ID greater than this

        Returns:
            Worker status data
        """
        params = {}
        if since_id:
            params["since_id"] = since_id

        return self._get_json("/worker_status", params=params)

    # Convenience Methods

    def create_webhook_agent(self, name: str, secret: str, **options) -> Agent:
        """
        Convenience method to create a WebhookAgent

        Args:
            name: Agent name
            secret: Webhook secret
            **options: Additional webhook options

        Returns:
            Created Agent object
        """
        webhook_options = {
            "secret": secret,
            "expected_receive_period_in_days": 1,
            "payload_path": ".",
            "verbs": "post",
            "response": "Event Created",
            **options,
        }

        return self.create_agent(name, "Agents::WebhookAgent", webhook_options)

    def create_data_output_agent(
        self, name: str, secrets: List[str], template: Dict[str, Any], **options
    ) -> Agent:
        """
        Convenience method to create a DataOutputAgent

        Args:
            name: Agent name
            secrets: List of access secrets
            template: RSS/JSON template
            **options: Additional options

        Returns:
            Created Agent object
        """
        output_options = {
            "secrets": secrets,
            "expected_receive_period_in_days": 2,
            "template": template,
            "events_to_show": 20,
            **options,
        }

        return self.create_agent(name, "Agents::DataOutputAgent", output_options)

    def monitor_events(
        self, callback, agent_ids: Optional[List[int]] = None, poll_interval: int = 5
    ):
        """
        Monitor events in real-time

        Args:
            callback: Function to call for each new event
            agent_ids: List of agent IDs to monitor (None for all)
            poll_interval: Polling interval in seconds
        """
        last_event_id = 0

        print(f"Starting event monitor (polling every {poll_interval}s)")

        try:
            while True:
                events = []

                if agent_ids:
                    for agent_id in agent_ids:
                        agent_events = self.get_events(agent_id=agent_id)
                        events.extend(agent_events)
                else:
                    events = self.get_events()

                new_events = [e for e in events if e.id > last_event_id]
                new_events.sort(key=lambda x: x.id)

                for event in new_events:
                    try:
                        callback(event)
                        last_event_id = max(last_event_id, event.id)
                    except Exception as e:
                        print(f"Error in event callback: {e}")

                time.sleep(poll_interval)

        except KeyboardInterrupt:
            print("Event monitoring stopped")


# Usage Examples
if __name__ == "__main__":
    # Initialize client
    client = HuginnClient(
        "https://your-huginn.com", session_cookie="your-session-cookie"
    )

    try:
        # List agents
        agents = client.get_agents()
        print(f"Found {len(agents)} agents")

        # Create a webhook agent
        webhook_agent = client.create_webhook_agent(
            name="Test Webhook Agent",
            secret="test-secret-123",
            payload_path=".",
            verbs="post",
        )
        print(f"Created webhook agent: {webhook_agent.name} (ID: {webhook_agent.id})")

        # Send webhook data
        webhook_response = client.send_webhook(
            user_id=1,
            agent_id=webhook_agent.id,
            secret="test-secret-123",
            data={
                "message": "Hello from Python client!",
                "timestamp": datetime.now().isoformat(),
            },
        )
        print(f"Webhook response: {webhook_response}")

        # Get recent events
        events = client.get_events()
        print(f"Recent events: {len(events)}")

        # Get worker status
        status = client.get_worker_status()
        print(f"Worker status: {status}")

    except HuginnAPIError as e:
        print(f"API Error: {e.message}")
        if e.response_text:
            print(f"Response: {e.response_text}")
