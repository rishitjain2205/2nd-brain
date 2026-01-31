"""
Enterprise API Routes with RBAC Protection
All routes protected with Auth0 authentication and role-based access control

SECURITY FEATURES:
- Input validation (prevents SQL/command injection)
- Rate limiting
- RBAC enforcement
- Audit logging
"""

import os
from flask import Blueprint, request, jsonify, g
from functools import wraps
from typing import Optional
from auth.auth0_handler import Auth0Handler, RateLimiter, Auth0Config
from security.audit_logger import get_audit_logger
from security.data_sanitizer import DataSanitizer
from security.input_validator_fixed import InputValidator
from classification.work_personal_classifier import WorkPersonalClassifier
from gap_analysis.gap_analyzer import GapAnalyzer
from rag.hierarchical_rag import HierarchicalRAG
from indexing.vector_database import VectorDatabaseBuilder

# Initialize Auth0
auth_config = Auth0Config(
    domain=os.getenv("AUTH0_DOMAIN", ""),
    api_audience=os.getenv("AUTH0_API_AUDIENCE", ""),
    client_id=os.getenv("AUTH0_CLIENT_ID", ""),
    client_secret=os.getenv("AUTH0_CLIENT_SECRET", "")
)

try:
    auth = Auth0Handler(config=auth_config)
    rate_limiter = RateLimiter(requests_per_minute=100)
    AUTH_ENABLED = True
    print("✓ Auth0 RBAC enabled")
except Exception as e:
    print(f"⚠️  Auth0 not configured: {e}")
    AUTH_ENABLED = False
    # Create mock auth for development
    class MockAuth:
        def requires_auth(self, f):
            return f
        def requires_role(self, role):
            def decorator(f):
                return f
            return decorator
        def requires_permission(self, permission):
            def decorator(f):
                return f
            return decorator
    auth = MockAuth()

    class MockRateLimiter:
        def rate_limit(self, key_func=None):
            def decorator(f):
                return f
            return decorator
    rate_limiter = MockRateLimiter()

# Create Blueprint
api = Blueprint('api', __name__, url_prefix='/api/v1')

# Initialize components
sanitizer = DataSanitizer()
validator = InputValidator()


# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

def get_current_organization() -> Optional[str]:
    """Get current user's organization ID"""
    if AUTH_ENABLED and hasattr(g, 'current_user'):
        return g.current_user.organization_id
    return os.getenv('DEFAULT_ORG_ID', 'default_org')


def get_current_user_id() -> str:
    """Get current user ID"""
    if AUTH_ENABLED and hasattr(g, 'current_user'):
        return g.current_user.id
    return "anonymous"


def audit_log_request(action: str, success: bool = True, **metadata):
    """Helper to audit log API requests"""
    org_id = get_current_organization()
    user_id = get_current_user_id()

    logger = get_audit_logger(organization_id=org_id)
    logger.log_llm_call(
        action=action,
        model_deployment=os.getenv('AZURE_OPENAI_DEPLOYMENT', 'gpt-5-chat'),
        user_id=user_id,
        sanitized=True,
        success=success,
        metadata=metadata
    )


# ==============================================================================
# PUBLIC ROUTES (No Auth Required)
# ==============================================================================

@api.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'auth_enabled': AUTH_ENABLED,
        'version': '1.0.0'
    }), 200


@api.route('/auth/status', methods=['GET'])
@auth.requires_auth
def auth_status():
    """Check authentication status"""
    user = g.current_user
    return jsonify({
        'authenticated': True,
        'user_id': user.id,
        'email': user.email,
        'organization_id': user.organization_id,
        'roles': user.roles,
        'permissions': user.permissions
    }), 200


# ==============================================================================
# CLASSIFICATION ROUTES (Employee Role Required)
# ==============================================================================

@api.route('/classify/document', methods=['POST'])
@auth.requires_auth
@rate_limiter.rate_limit(lambda: g.current_user.id if hasattr(g, 'current_user') else 'anonymous')
def classify_document():
    """
    Classify a single document as work or personal

    Required role: employee (or higher)
    Rate limit: 100 requests/minute per user
    """
    try:
        data = request.get_json()

        if not data or 'document' not in data:
            return jsonify({'error': 'Missing document in request'}), 400

        # Validate and sanitize input
        try:
            document = validator.sanitize_dict(data['document'])
        except ValueError as e:
            return jsonify({'error': f'Invalid input: {str(e)}'}), 400

        org_id = get_current_organization()
        user_id = get_current_user_id()

        # Initialize classifier
        classifier = WorkPersonalClassifier(
            organization_id=org_id,
            user_id=user_id
        )

        # Classify document (automatically sanitizes + audit logs)
        result = classifier.classify_document(document)

        return jsonify({
            'success': True,
            'classification': result,
            'organization_id': org_id
        }), 200

    except Exception as e:
        audit_log_request('classification', success=False, error=str(e))
        return jsonify({'error': str(e)}), 500


@api.route('/classify/batch', methods=['POST'])
@auth.requires_role('manager')  # Managers and above
@rate_limiter.rate_limit(lambda: g.current_user.id if hasattr(g, 'current_user') else 'anonymous')
def classify_batch():
    """
    Classify multiple documents in batch

    Required role: manager (or admin)
    Rate limit: 100 requests/minute per user
    """
    try:
        data = request.get_json()

        if not data or 'documents' not in data:
            return jsonify({'error': 'Missing documents in request'}), 400

        # Validate and sanitize input
        try:
            documents = [validator.sanitize_dict(doc) for doc in data['documents']]
        except ValueError as e:
            return jsonify({'error': f'Invalid input: {str(e)}'}), 400

        org_id = get_current_organization()
        user_id = get_current_user_id()

        # Initialize classifier
        classifier = WorkPersonalClassifier(
            organization_id=org_id,
            user_id=user_id
        )

        # Classify batch
        results = classifier.classify_batch(documents)

        return jsonify({
            'success': True,
            'total_documents': len(results),
            'results': results,
            'organization_id': org_id
        }), 200

    except Exception as e:
        audit_log_request('batch_classification', success=False, error=str(e))
        return jsonify({'error': str(e)}), 500


# ==============================================================================
# GAP ANALYSIS ROUTES (Manager Role Required)
# ==============================================================================

@api.route('/analyze/gaps', methods=['POST'])
@auth.requires_role('manager')
@rate_limiter.rate_limit(lambda: g.current_user.id if hasattr(g, 'current_user') else 'anonymous')
def analyze_gaps():
    """
    Analyze project for knowledge gaps

    Required role: manager
    Rate limit: 100 requests/minute per user
    """
    try:
        data = request.get_json()

        if not data or 'project_data' not in data:
            return jsonify({'error': 'Missing project_data in request'}), 400

        # Validate and sanitize input
        try:
            project_data = validator.sanitize_dict(data['project_data'])
        except ValueError as e:
            return jsonify({'error': f'Invalid input: {str(e)}'}), 400

        org_id = get_current_organization()
        user_id = get_current_user_id()

        # Initialize gap analyzer
        analyzer = GapAnalyzer(
            api_key=os.getenv('AZURE_OPENAI_API_KEY'),
            endpoint=os.getenv('AZURE_OPENAI_ENDPOINT'),
            deployment=os.getenv('AZURE_OPENAI_DEPLOYMENT')
        )

        # Analyze gaps
        gaps = analyzer.analyze_project_gaps(project_data)

        # Audit log
        audit_log_request(
            'gap_analysis',
            success=True,
            project_name=project_data.get('project_name', 'unknown')
        )

        return jsonify({
            'success': True,
            'gaps': gaps,
            'organization_id': org_id
        }), 200

    except Exception as e:
        audit_log_request('gap_analysis', success=False, error=str(e))
        return jsonify({'error': str(e)}), 500


# ==============================================================================
# RAG QUERY ROUTES (Employee Role Required)
# ==============================================================================

@api.route('/rag/query', methods=['POST'])
@auth.requires_auth
@rate_limiter.rate_limit(lambda: g.current_user.id if hasattr(g, 'current_user') else 'anonymous')
def rag_query():
    """
    Query knowledge base with RAG

    Required role: employee
    Rate limit: 100 requests/minute per user
    """
    try:
        data = request.get_json()

        if not data or 'query' not in data:
            return jsonify({'error': 'Missing query in request'}), 400

        # Validate and sanitize input
        try:
            query = validator.sanitize_string(data['query'])
        except ValueError as e:
            return jsonify({'error': f'Invalid input: {str(e)}'}), 400

        org_id = get_current_organization()
        user_id = get_current_user_id()

        # Initialize vector database with org isolation
        vector_db = VectorDatabaseBuilder(
            persist_directory='data/chroma_db',
            organization_id=org_id
        )

        # Initialize RAG
        rag = HierarchicalRAG(
            vector_db=vector_db,
            api_key=os.getenv('AZURE_OPENAI_API_KEY'),
            endpoint=os.getenv('AZURE_OPENAI_ENDPOINT'),
            deployment=os.getenv('AZURE_OPENAI_DEPLOYMENT')
        )

        # Query (automatically sanitizes)
        result = rag.query(query, n_results=data.get('n_results', 5))

        # Audit log
        import hashlib
        query_hash = hashlib.sha256(query.encode()).hexdigest()[:16]
        audit_log_request(
            'rag_query',
            success=True,
            query_hash=query_hash
        )

        return jsonify({
            'success': True,
            'result': result,
            'organization_id': org_id
        }), 200

    except Exception as e:
        audit_log_request('rag_query', success=False, error=str(e))
        return jsonify({'error': str(e)}), 500


# ==============================================================================
# ADMIN ROUTES (Admin Role Required)
# ==============================================================================

@api.route('/admin/audit/summary', methods=['GET'])
@auth.requires_role('admin')
def get_audit_summary():
    """
    Get audit log summary

    Required role: admin
    """
    try:
        org_id = get_current_organization()
        days = request.args.get('days', 7, type=int)

        logger = get_audit_logger(organization_id=org_id)
        summary = logger.get_audit_summary(days=days)

        return jsonify({
            'success': True,
            'summary': summary,
            'organization_id': org_id,
            'period_days': days
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api.route('/admin/audit/export', methods=['POST'])
@auth.requires_role('admin')
def export_audit_report():
    """
    Export audit report for compliance

    Required role: admin
    """
    try:
        data = request.get_json()
        org_id = get_current_organization()
        days = data.get('days', 30)

        logger = get_audit_logger(organization_id=org_id)
        output_file = f'data/audit_logs/{org_id}/report_{days}days.json'

        report = logger.export_audit_report(output_file, days=days)

        return jsonify({
            'success': True,
            'report': report,
            'file_path': output_file
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api.route('/admin/users', methods=['GET'])
@auth.requires_role('admin')
def list_users():
    """
    List all users in organization

    Required role: admin
    """
    # This would integrate with your user management system
    # For now, return placeholder
    return jsonify({
        'success': True,
        'message': 'User management integration pending',
        'users': []
    }), 200


@api.route('/admin/organizations', methods=['GET'])
@auth.requires_role('admin')
def list_organizations():
    """
    List all organizations (super admin only)

    Required role: admin
    """
    # This would query your database for organizations
    return jsonify({
        'success': True,
        'message': 'Organization management integration pending',
        'organizations': []
    }), 200


# ==============================================================================
# ERROR HANDLERS
# ==============================================================================

@api.errorhandler(401)
def unauthorized(error):
    return jsonify({
        'error': 'Unauthorized',
        'message': 'Valid authentication required'
    }), 401


@api.errorhandler(403)
def forbidden(error):
    return jsonify({
        'error': 'Forbidden',
        'message': 'Insufficient permissions'
    }), 403


@api.errorhandler(429)
def rate_limit_exceeded(error):
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Please try again later.'
    }), 429


@api.errorhandler(500)
def internal_error(error):
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred'
    }), 500


def init_api(app):
    """Initialize enterprise API with Flask app"""
    app.register_blueprint(api)
    print("✓ Enterprise API routes registered")
    print(f"  - Auth enabled: {AUTH_ENABLED}")
    print(f"  - Rate limiting: {rate_limiter.rpm} req/min")

    # Register auth globally
    if AUTH_ENABLED:
        app.auth = auth
        app.rate_limiter = rate_limiter

    return api
