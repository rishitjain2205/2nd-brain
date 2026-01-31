"""
Slack OAuth Routes
Handles "Add to Slack" flow for multi-tenant installation
"""

import os
import requests
from flask import Blueprint, request, jsonify, redirect
from urllib.parse import urlencode

from .slack_db import save_installation, get_installation, get_all_installations, delete_installation

slack_oauth_bp = Blueprint('slack_oauth', __name__, url_prefix='/api/slack')

# Configuration from environment
SLACK_CLIENT_ID = os.getenv('SLACK_CLIENT_ID', '')
SLACK_CLIENT_SECRET = os.getenv('SLACK_CLIENT_SECRET', '')
SLACK_SIGNING_SECRET = os.getenv('SLACK_SIGNING_SECRET', '')
BASE_URL = os.getenv('BASE_URL', 'http://localhost:5003')

# Bot Token Scopes needed for full functionality
BOT_SCOPES = [
    'app_mentions:read',      # Receive @mentions
    'channels:history',       # Read public channel messages
    'channels:read',          # List public channels
    'chat:write',             # Send messages
    'groups:history',         # Read private channel messages
    'groups:read',            # List private channels
    'im:history',             # Read DMs
    'im:read',                # List DMs
    'im:write',               # Send DMs
    'users:read',             # Get user info
    'team:read',              # Get workspace info
]


@slack_oauth_bp.route('/install')
def slack_install():
    """
    Generate "Add to Slack" authorization URL
    Users visit this or click the button to start OAuth flow
    """
    if not SLACK_CLIENT_ID:
        return jsonify({
            'error': 'SLACK_CLIENT_ID not configured',
            'message': 'Please set SLACK_CLIENT_ID environment variable'
        }), 500

    # Build authorization URL
    redirect_uri = f"{BASE_URL}/api/slack/oauth/callback"
    params = {
        'client_id': SLACK_CLIENT_ID,
        'scope': ','.join(BOT_SCOPES),
        'redirect_uri': redirect_uri,
    }

    auth_url = f"https://slack.com/oauth/v2/authorize?{urlencode(params)}"

    return jsonify({
        'auth_url': auth_url,
        'redirect_uri': redirect_uri,
        'scopes': BOT_SCOPES,
        'button_html': f'''<a href="{auth_url}"><img alt="Add to Slack" height="40" width="139" src="https://platform.slack-edge.com/img/add_to_slack.png" srcSet="https://platform.slack-edge.com/img/add_to_slack.png 1x, https://platform.slack-edge.com/img/add_to_slack@2x.png 2x" /></a>'''
    })


@slack_oauth_bp.route('/oauth/callback')
def slack_oauth_callback():
    """
    Handle OAuth callback from Slack
    Exchange code for tokens and save installation
    """
    error = request.args.get('error')
    if error:
        error_desc = request.args.get('error_description', 'Unknown error')
        return f"""
        <!DOCTYPE html>
        <html>
        <head><title>Installation Failed</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; padding: 40px; text-align: center; background: #f5f5f5; }}
            .card {{ background: white; border-radius: 12px; padding: 40px; max-width: 500px; margin: 0 auto; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
            h1 {{ color: #e74c3c; }}
            a {{ color: #3498db; }}
        </style>
        </head>
        <body>
            <div class="card">
                <h1>Installation Failed</h1>
                <p><strong>Error:</strong> {error}</p>
                <p>{error_desc}</p>
                <p><a href="/">Go back to dashboard</a></p>
            </div>
        </body>
        </html>
        """, 400

    code = request.args.get('code')
    if not code:
        return "Missing authorization code", 400

    # Exchange code for token
    try:
        redirect_uri = f"{BASE_URL}/api/slack/oauth/callback"
        response = requests.post('https://slack.com/api/oauth.v2.access', data={
            'client_id': SLACK_CLIENT_ID,
            'client_secret': SLACK_CLIENT_SECRET,
            'code': code,
            'redirect_uri': redirect_uri
        }, timeout=30)

        data = response.json()

        if not data.get('ok'):
            error_msg = data.get('error', 'Unknown error')
            return f"""
            <!DOCTYPE html>
            <html>
            <head><title>Installation Failed</title>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; padding: 40px; text-align: center; background: #f5f5f5; }}
                .card {{ background: white; border-radius: 12px; padding: 40px; max-width: 500px; margin: 0 auto; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
                h1 {{ color: #e74c3c; }}
            </style>
            </head>
            <body>
                <div class="card">
                    <h1>Installation Failed</h1>
                    <p>Slack returned an error: <strong>{error_msg}</strong></p>
                    <p><a href="/">Go back to dashboard</a></p>
                </div>
            </body>
            </html>
            """, 400

        # Extract installation data
        team = data.get('team', {})
        team_id = team.get('id', '')
        team_name = team.get('name', 'Unknown Workspace')
        bot_user_id = data.get('bot_user_id', '')
        access_token = data.get('access_token', '')

        installation_data = {
            'team_id': team_id,
            'team_name': team_name,
            'bot_token': access_token,
            'bot_user_id': bot_user_id,
            'app_id': data.get('app_id'),
            'authed_user_id': data.get('authed_user', {}).get('id'),
            'scope': data.get('scope'),
        }

        # Save to database
        saved = save_installation(installation_data)

        if not saved:
            return "Failed to save installation", 500

        # Return success page
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Success - Slack Connected!</title>
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    padding: 0;
                    margin: 0;
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                }}
                .card {{
                    background: white;
                    border-radius: 16px;
                    padding: 48px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                    max-width: 500px;
                    text-align: center;
                }}
                h1 {{ color: #1a1a1a; margin-bottom: 16px; }}
                .team {{ color: #667eea; font-weight: 600; font-size: 1.2em; }}
                .success-icon {{ font-size: 64px; margin-bottom: 20px; }}
                .steps {{
                    text-align: left;
                    background: #f8f9fa;
                    border-radius: 8px;
                    padding: 20px;
                    margin: 24px 0;
                }}
                .step {{ margin: 12px 0; color: #4a4a4a; }}
                .step code {{
                    background: #e9ecef;
                    padding: 2px 6px;
                    border-radius: 4px;
                    font-size: 0.9em;
                }}
                .btn {{
                    background: #667eea;
                    color: white;
                    border: none;
                    padding: 14px 32px;
                    border-radius: 8px;
                    font-size: 16px;
                    cursor: pointer;
                    text-decoration: none;
                    display: inline-block;
                    margin-top: 16px;
                    transition: transform 0.2s, box-shadow 0.2s;
                }}
                .btn:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
                }}
            </style>
        </head>
        <body>
            <div class="card">
                <div class="success-icon">&#10004;</div>
                <h1>Successfully Connected!</h1>
                <p>KnowledgeVault has been added to</p>
                <p class="team">{team_name}</p>

                <div class="steps">
                    <p><strong>Next steps:</strong></p>
                    <p class="step">1. Go to any Slack channel</p>
                    <p class="step">2. Invite the bot: <code>/invite @KnowledgeVault</code></p>
                    <p class="step">3. Ask a question: <code>@KnowledgeVault What do you know?</code></p>
                </div>

                <a href="/integrations" class="btn">Go to Dashboard</a>
            </div>
            <script>
                // Notify parent window if in popup/iframe
                if (window.opener) {{
                    window.opener.postMessage({{
                        type: 'slack_installed',
                        team_id: '{team_id}',
                        team_name: '{team_name}'
                    }}, '*');
                }}
            </script>
        </body>
        </html>
        """

    except requests.Timeout:
        return "Timeout connecting to Slack API", 504
    except Exception as e:
        import traceback
        traceback.print_exc()
        return f"Error during OAuth: {str(e)}", 500


@slack_oauth_bp.route('/installations')
def list_installations():
    """List all connected Slack workspaces"""
    installations = get_all_installations()

    # Remove sensitive data
    safe_installations = []
    for inst in installations:
        safe_installations.append({
            'team_id': inst['team_id'],
            'team_name': inst['team_name'],
            'bot_user_id': inst.get('bot_user_id'),
            'installed_at': inst['installed_at'],
            'last_event_at': inst.get('last_event_at'),
            'is_active': bool(inst.get('is_active', True))
        })

    return jsonify({
        'installations': safe_installations,
        'count': len(safe_installations)
    })


@slack_oauth_bp.route('/installation/<team_id>')
def get_installation_status(team_id):
    """Get status of a specific installation"""
    installation = get_installation(team_id)

    if not installation:
        return jsonify({'error': 'Installation not found', 'connected': False}), 404

    return jsonify({
        'connected': True,
        'team_id': installation['team_id'],
        'team_name': installation['team_name'],
        'bot_user_id': installation.get('bot_user_id'),
        'installed_at': installation['installed_at'],
        'last_event_at': installation.get('last_event_at')
    })


@slack_oauth_bp.route('/uninstall', methods=['POST'])
def uninstall():
    """Uninstall/disconnect a Slack workspace"""
    data = request.get_json() or {}
    team_id = data.get('team_id')

    if not team_id:
        return jsonify({'error': 'team_id required'}), 400

    deleted = delete_installation(team_id)

    if deleted:
        return jsonify({'success': True, 'message': f'Disconnected workspace {team_id}'})
    else:
        return jsonify({'success': False, 'error': 'Failed to disconnect'}), 500


@slack_oauth_bp.route('/status')
def slack_status():
    """Get overall Slack integration status"""
    installations = get_all_installations()

    return jsonify({
        'configured': bool(SLACK_CLIENT_ID and SLACK_CLIENT_SECRET),
        'client_id_set': bool(SLACK_CLIENT_ID),
        'client_secret_set': bool(SLACK_CLIENT_SECRET),
        'signing_secret_set': bool(SLACK_SIGNING_SECRET),
        'connected_workspaces': len(installations),
        'base_url': BASE_URL
    })
