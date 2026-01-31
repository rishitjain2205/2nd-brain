"""
API Connectors Module
Provides integration with external data sources like Gmail, Slack, GitHub, etc.
for comprehensive knowledge capture.
"""

from .base_connector import BaseConnector, ConnectorConfig, Document
from .gmail_connector import GmailConnector
from .slack_connector import SlackConnector
from .github_connector import GitHubConnector
from .connector_manager import ConnectorManager

# Slack multi-tenant modules
from .slack_db import (
    init_db as init_slack_db,
    save_installation,
    get_installation,
    get_bot_token,
    get_all_installations,
    delete_installation
)
from .slack_oauth import slack_oauth_bp
from .slack_events import slack_events_bp, set_rag_query_func

__all__ = [
    'BaseConnector',
    'ConnectorConfig',
    'Document',
    'GmailConnector',
    'SlackConnector',
    'GitHubConnector',
    'ConnectorManager',
    # Slack multi-tenant
    'init_slack_db',
    'save_installation',
    'get_installation',
    'get_bot_token',
    'get_all_installations',
    'delete_installation',
    'slack_oauth_bp',
    'slack_events_bp',
    'set_rag_query_func'
]
