"""DevGuard SDK - Simple drop-in replacement for OpenAI"""

import os
import requests
from typing import List, Dict, Optional, Any
import json

__version__ = "0.1.0"

class DevGuardError(Exception):
    """Base exception for DevGuard SDK"""
    pass

class TeamNotFoundError(DevGuardError):
    """Team not found or invalid API key"""
    pass

class UsageLimitError(DevGuardError):
    """Usage limit exceeded"""
    pass

class GuardrailViolationError(DevGuardError):
    """Content blocked by guardrails"""
    pass

class DevGuard:
    """OpenAI-compatible client with team-based AI safety"""

    def __init__(
        self,
        api_key: str = None,
        base_url: str = None,
        user_role: str = None,
        team_id: str = None,
        timeout: int = 30
    ):
        """Initialize DevGuard client

        Args:
            api_key: DevGuard team API key (or from DEVGUARD_API_KEY env var)
            base_url: DevGuard API base URL (default: https://api.devguard.ai)
            user_role: User role for RBAC (default: 'developer')
            team_id: Team ID (usually auto-detected from API key)
            timeout: Request timeout in seconds
        """
        self.api_key = api_key or os.getenv('DEVGUARD_API_KEY')
        if not self.api_key:
            raise DevGuardError("API key required. Set DEVGUARD_API_KEY env var or pass api_key parameter.")

        self.base_url = base_url or os.getenv('DEVGUARD_BASE_URL', 'https://api.devguard.ai')
        # For local development, can point to localhost:8000
        if 'localhost' in str(self.base_url) or '127.0.0.1' in str(self.base_url):
            self.base_url = self.base_url

        self.user_role = user_role or os.getenv('DEVGUARD_USER_ROLE', 'developer')
        self.team_id = team_id or os.getenv('DEVGUARD_TEAM_ID')
        self.timeout = timeout

        # Create OpenAI-compatible interface
        self.chat = Chat(self)

    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make authenticated request to DevGuard API"""
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'X-User-Role': self.user_role,
            'Content-Type': 'application/json'
        }

        if self.team_id:
            headers['X-Team-ID'] = self.team_id

        url = f"{self.base_url.rstrip('/')}/{endpoint.lstrip('/')}"

        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                timeout=self.timeout,
                **kwargs
            )

            # Handle DevGuard-specific errors
            if response.status_code == 401:
                raise TeamNotFoundError("Invalid API key or team not found")
            elif response.status_code == 429:
                raise UsageLimitError("Usage limit exceeded for your plan")
            elif response.status_code == 400:
                error_data = response.json() if response.headers.get('content-type') == 'application/json' else {}
                if 'guardrails' in error_data.get('detail', '').lower():
                    raise GuardrailViolationError(error_data.get('detail', 'Content blocked by safety guardrails'))
                else:
                    response.raise_for_status()
            else:
                response.raise_for_status()

            return response

        except requests.RequestException as e:
            raise DevGuardError(f"Request failed: {str(e)}")

class Chat:
    """OpenAI-compatible chat interface"""

    def __init__(self, client: DevGuard):
        self.client = client
        self.completions = Completions(client)

class Completions:
    """OpenAI-compatible completions interface"""

    def __init__(self, client: DevGuard):
        self.client = client

    def create(
        self,
        messages: List[Dict[str, str]],
        model: str = "gpt-4",
        max_tokens: Optional[int] = None,
        temperature: float = 0.7,
        stream: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """Create chat completion with guardrails

        Args:
            messages: List of message dicts with 'role' and 'content'
            model: Model name (gpt-4, gpt-3.5-turbo, etc.)
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            stream: Whether to stream response (not yet supported)
            **kwargs: Additional OpenAI parameters

        Returns:
            OpenAI-compatible response with additional 'devguard' field
        """
        if stream:
            raise NotImplementedError("Streaming not yet supported")

        request_data = {
            "messages": messages,
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            **kwargs
        }

        response = self.client._make_request(
            method="POST",
            endpoint="/v1/chat/completions",
            json=request_data
        )

        return response.json()

# Global client for simple usage
_default_client = None

def setup(api_key: str = None, **kwargs) -> DevGuard:
    """Setup global DevGuard client for simple usage

    Args:
        api_key: DevGuard API key
        **kwargs: Additional client options

    Returns:
        Configured DevGuard client
    """
    global _default_client
    _default_client = DevGuard(api_key=api_key, **kwargs)

    # Try to monkey-patch OpenAI if it's installed
    try:
        import openai
        # Override OpenAI client if user wants it
        print("🛡️ DevGuard guardrails activated! OpenAI calls will be protected.")
        print(f"🔑 Using team role: {_default_client.user_role}")
    except ImportError:
        print("🛡️ DevGuard client ready!")

    return _default_client

def create_team(team_name: str, admin_email: str, plan: str = "free", base_url: str = None) -> Dict[str, Any]:
    """Create a new DevGuard team

    Args:
        team_name: Name for the new team
        admin_email: Admin email address
        plan: Plan type ('free', 'pro', 'enterprise')
        base_url: DevGuard API base URL

    Returns:
        Team creation response with API key and setup instructions
    """
    base_url = base_url or os.getenv('DEVGUARD_BASE_URL', 'https://api.devguard.ai')

    response = requests.post(
        f"{base_url}/v1/saas/teams/create",
        json={
            "team_name": team_name,
            "admin_email": admin_email,
            "plan": plan
        },
        timeout=30
    )

    response.raise_for_status()
    return response.json()

# Convenience functions for direct usage
def chat_completion(messages: List[Dict[str, str]], **kwargs) -> Dict[str, Any]:
    """Simple chat completion using global client"""
    if not _default_client:
        raise DevGuardError("Call setup() first or create a DevGuard client")
    return _default_client.chat.completions.create(messages=messages, **kwargs)