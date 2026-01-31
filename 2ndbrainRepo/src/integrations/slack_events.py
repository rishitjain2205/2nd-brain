"""
Slack Events API Handler
Receives webhook events from Slack and handles:
1. URL verification challenge (required for setup)
2. App mentions (@bot questions)
3. Direct messages
4. Channel messages (for knowledge capture)
"""

import os
import hmac
import hashlib
import time
import re
import threading
from flask import Blueprint, request, jsonify
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from .slack_db import get_bot_token, update_last_event, get_installation

slack_events_bp = Blueprint('slack_events', __name__, url_prefix='/api/slack')

# Configuration
SLACK_SIGNING_SECRET = os.getenv('SLACK_SIGNING_SECRET', '')

# Cache for user names (team_id -> user_id -> name)
user_cache = {}

# RAG query function - will be set by main app
_rag_query_func = None


def set_rag_query_func(func):
    """Set the RAG query function from main app"""
    global _rag_query_func
    _rag_query_func = func
    print("[Slack Events] RAG query function configured")


def verify_slack_signature(req) -> bool:
    """
    Verify the request is actually from Slack using signing secret
    https://api.slack.com/authentication/verifying-requests-from-slack
    """
    if not SLACK_SIGNING_SECRET:
        # Skip verification if not configured (development mode)
        print("[Slack Events] Warning: SLACK_SIGNING_SECRET not set, skipping verification")
        return True

    try:
        timestamp = req.headers.get('X-Slack-Request-Timestamp', '')
        signature = req.headers.get('X-Slack-Signature', '')

        if not timestamp or not signature:
            return False

        # Prevent replay attacks (reject if older than 5 minutes)
        if abs(time.time() - int(timestamp)) > 60 * 5:
            print("[Slack Events] Request timestamp too old")
            return False

        # Compute expected signature
        sig_basestring = f"v0:{timestamp}:{req.get_data(as_text=True)}"
        my_signature = 'v0=' + hmac.new(
            SLACK_SIGNING_SECRET.encode(),
            sig_basestring.encode(),
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(my_signature, signature)
    except Exception as e:
        print(f"[Slack Events] Signature verification error: {e}")
        return False


def get_user_name(client: WebClient, user_id: str, team_id: str) -> str:
    """Get display name for user with caching"""
    cache_key = f"{team_id}:{user_id}"

    if cache_key in user_cache:
        return user_cache[cache_key]

    try:
        result = client.users_info(user=user_id)
        if result['ok']:
            user = result['user']
            name = user.get('real_name') or user.get('name') or user_id
            user_cache[cache_key] = name
            return name
    except SlackApiError as e:
        print(f"[Slack Events] Error getting user info: {e}")

    return user_id


def handle_app_mention(event: dict, team_id: str):
    """Handle @mention of the bot - query RAG and respond"""
    bot_token = get_bot_token(team_id)
    if not bot_token:
        print(f"[Slack Events] No token found for team {team_id}")
        return

    client = WebClient(token=bot_token)

    text = event.get('text', '')
    user_id = event.get('user')
    channel = event.get('channel')
    thread_ts = event.get('thread_ts') or event.get('ts')
    message_ts = event.get('ts')

    # Remove bot mention from text to get the actual question
    question = re.sub(r'<@[A-Z0-9]+>\s*', '', text).strip()

    if not question:
        # Just mentioned without a question
        try:
            client.chat_postMessage(
                channel=channel,
                thread_ts=thread_ts,
                text="Hi! I'm your Knowledge Assistant. Ask me anything and I'll search our knowledge base for answers. :brain:"
            )
        except SlackApiError as e:
            print(f"[Slack Events] Error sending message: {e}")
        return

    # Add thinking reaction
    try:
        client.reactions_add(channel=channel, timestamp=message_ts, name='thinking_face')
    except SlackApiError:
        pass

    # Query RAG for answer
    answer = "I'm sorry, the knowledge base is not configured yet. Please set up the RAG system first."

    if _rag_query_func:
        try:
            answer = _rag_query_func(question, team_id)
        except Exception as e:
            print(f"[Slack Events] RAG query error: {e}")
            answer = f"Sorry, I encountered an error while searching: {str(e)}"

    # Remove thinking reaction, add checkmark
    try:
        client.reactions_remove(channel=channel, timestamp=message_ts, name='thinking_face')
        client.reactions_add(channel=channel, timestamp=message_ts, name='white_check_mark')
    except SlackApiError:
        pass

    # Get user name for nicer response
    user_name = get_user_name(client, user_id, team_id)

    # Send response
    try:
        client.chat_postMessage(
            channel=channel,
            thread_ts=thread_ts,
            text=f"*Question from {user_name}:*\n> {question}\n\n{answer}"
        )
    except SlackApiError as e:
        print(f"[Slack Events] Error sending response: {e}")

    # Update last event timestamp
    update_last_event(team_id)


def handle_direct_message(event: dict, team_id: str):
    """Handle direct message to the bot"""
    bot_token = get_bot_token(team_id)
    if not bot_token:
        return

    client = WebClient(token=bot_token)

    # Get bot's own user ID to avoid responding to self
    try:
        auth_result = client.auth_test()
        bot_user_id = auth_result.get('user_id')
        if event.get('user') == bot_user_id:
            return  # Don't respond to own messages
    except SlackApiError:
        pass

    text = event.get('text', '')
    channel = event.get('channel')
    thread_ts = event.get('thread_ts') or event.get('ts')

    if not text:
        return

    # Query RAG for answer
    answer = "Knowledge base not configured."

    if _rag_query_func:
        try:
            answer = _rag_query_func(text, team_id)
        except Exception as e:
            answer = f"Sorry, I encountered an error: {str(e)}"

    # Send response
    try:
        client.chat_postMessage(
            channel=channel,
            thread_ts=thread_ts,
            text=answer
        )
    except SlackApiError as e:
        print(f"[Slack Events] Error sending DM response: {e}")

    update_last_event(team_id)


def handle_channel_message(event: dict, team_id: str):
    """
    Handle regular channel message (for knowledge capture)
    This can be used to index new messages in real-time
    """
    # For now, just log it
    # TODO: Implement real-time message indexing
    channel = event.get('channel')
    text = event.get('text', '')[:50]
    print(f"[Slack Events] Channel message in {channel}: {text}...")


# ============================================================================
# MAIN EVENTS ENDPOINT
# ============================================================================

@slack_events_bp.route('/events', methods=['POST'])
def slack_events():
    """
    Main Slack Events API endpoint

    This endpoint:
    1. Handles URL verification challenge (required for Slack setup)
    2. Receives and routes all events from connected workspaces
    """
    # Verify request is from Slack (optional in dev, required in prod)
    if SLACK_SIGNING_SECRET and not verify_slack_signature(request):
        print("[Slack Events] Invalid signature - rejecting request")
        return jsonify({'error': 'Invalid signature'}), 401

    data = request.json

    if not data:
        return jsonify({'error': 'No data'}), 400

    # ========================================
    # CRITICAL: Handle URL verification
    # This is required when setting up Events URL in Slack
    # ========================================
    if data.get('type') == 'url_verification':
        challenge = data.get('challenge', '')
        print(f"[Slack Events] URL verification challenge received")
        # Must return the challenge value
        return jsonify({'challenge': challenge})

    # ========================================
    # Handle event callbacks
    # ========================================
    if data.get('type') == 'event_callback':
        event = data.get('event', {})
        team_id = data.get('team_id', '')
        event_type = event.get('type', '')

        print(f"[Slack Events] Received: {event_type} from team {team_id}")

        # Route to appropriate handler
        # Run handlers in background threads to respond within 3 seconds
        if event_type == 'app_mention':
            thread = threading.Thread(
                target=handle_app_mention,
                args=(event, team_id),
                daemon=True
            )
            thread.start()

        elif event_type == 'message':
            # Check message subtype - ignore bot messages, edits, etc.
            subtype = event.get('subtype')
            if subtype in ['bot_message', 'message_changed', 'message_deleted']:
                return jsonify({'ok': True})

            channel_type = event.get('channel_type', '')

            if channel_type == 'im':
                # Direct message to bot
                thread = threading.Thread(
                    target=handle_direct_message,
                    args=(event, team_id),
                    daemon=True
                )
                thread.start()
            else:
                # Regular channel message - can be used for indexing
                handle_channel_message(event, team_id)

    # Always respond quickly with 200 OK
    # Slack requires response within 3 seconds
    return jsonify({'ok': True})


@slack_events_bp.route('/health')
def slack_events_health():
    """Health check for Slack events endpoint"""
    return jsonify({
        'status': 'ok',
        'endpoint': '/api/slack/events',
        'rag_configured': _rag_query_func is not None,
        'signing_secret_configured': bool(SLACK_SIGNING_SECRET)
    })
