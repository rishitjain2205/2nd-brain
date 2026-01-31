"""
Catalyst Research Lab Matching Platform - Backend API
Flask-based REST API for connecting UCLA students with research opportunities
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import hashlib
import uuid
from datetime import datetime
import os
from typing import List, Dict, Any

# Import AI matching algorithms
try:
    from models import (
        Candidate, Lab, MatchResult, Transcript, Course,
        ResearchExperience, ExperienceLevel
    )
    from lab_ats_algorithm import LabATSAlgorithm
    from nlp_utils import SimpleEmbedding, TextProcessor
    AI_MATCHING_ENABLED = True
except ImportError as e:
    print(f"⚠️  AI matching algorithms not available: {e}")
    AI_MATCHING_ENABLED = False

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend communication

# Database setup
DB_PATH = os.path.join(os.path.dirname(__file__), 'instance', 'catalyst.db')

def init_db():
    """Initialize the database with required tables"""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            user_type TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Research labs table
    c.execute('''
        CREATE TABLE IF NOT EXISTS labs (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            professor_id TEXT NOT NULL,
            pi_name TEXT NOT NULL,
            department TEXT NOT NULL,
            description TEXT,
            requirements TEXT,
            commitment TEXT,
            location TEXT,
            website TEXT,
            research_areas TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (professor_id) REFERENCES users(id)
        )
    ''')

    # Applications table
    c.execute('''
        CREATE TABLE IF NOT EXISTS applications (
            id TEXT PRIMARY KEY,
            lab_id TEXT NOT NULL,
            student_id TEXT NOT NULL,
            cover_letter TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (lab_id) REFERENCES labs(id),
            FOREIGN KEY (student_id) REFERENCES users(id)
        )
    ''')

    # Insert sample data if tables are empty
    c.execute('SELECT COUNT(*) FROM labs')
    if c.fetchone()[0] == 0:
        # Create a sample professor
        prof_id = str(uuid.uuid4())
        c.execute('''
            INSERT INTO users (id, email, password_hash, full_name, user_type)
            VALUES (?, ?, ?, ?, ?)
        ''', (prof_id, 'shahan@ucla.edu', hashlib.sha256('password'.encode()).hexdigest(),
              'Dr. Shahan', 'professor'))

        # Create sample labs
        sample_labs = [
            {
                'id': str(uuid.uuid4()),
                'name': 'Shahan Lab',
                'professor_id': prof_id,
                'pi_name': 'Dr Shahan',
                'department': 'Molecular Biology',
                'description': 'Our lab focuses on molecular mechanisms of gene regulation and cellular signaling pathways. We use cutting-edge techniques including CRISPR gene editing, single-cell RNA sequencing, and advanced microscopy to understand how cells make decisions.',
                'requirements': 'Strong background in molecular biology, lab experience preferred',
                'commitment': '10-15 hours/week',
                'location': 'Life Sciences Building 3rd Floor',
                'website': 'https://www.lifesci.ucla.edu/mcdb-shahan/',
                'research_areas': 'Research,Science,Molecular Biology'
            },
            {
                'id': str(uuid.uuid4()),
                'name': 'Chen Lab - Machine Learning for Healthcare',
                'professor_id': prof_id,
                'pi_name': 'Dr. Sarah Chen',
                'department': 'Computer Science',
                'description': 'Research on applying deep learning models to predict patient outcomes and optimize treatment plans.',
                'requirements': 'Python programming, Calculus and Linear Algebra, Interest in healthcare applications',
                'commitment': '10-15 hours/week',
                'location': 'Boelter Hall 4532',
                'website': 'https://cs.ucla.edu',
                'research_areas': 'Machine Learning,Healthcare,AI'
            },
            {
                'id': str(uuid.uuid4()),
                'name': 'Martinez Lab - Sustainable Energy Materials',
                'professor_id': prof_id,
                'pi_name': 'Dr. James Martinez',
                'department': 'Materials Science',
                'description': 'Developing novel materials for solar cells and energy storage systems to address climate change.',
                'requirements': 'Chemistry background, Lab experience preferred, Commitment to sustainability',
                'commitment': '12-20 hours/week',
                'location': 'Engineering VI 289',
                'website': 'https://engineering.ucla.edu',
                'research_areas': 'Materials Science,Energy,Sustainability'
            }
        ]

        for lab in sample_labs:
            c.execute('''
                INSERT INTO labs (id, name, professor_id, pi_name, department, description,
                                requirements, commitment, location, website, research_areas)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (lab['id'], lab['name'], lab['professor_id'], lab['pi_name'], lab['department'],
                  lab['description'], lab['requirements'], lab['commitment'], lab['location'],
                  lab['website'], lab['research_areas']))

    conn.commit()
    conn.close()
    print("✓ Database initialized successfully")

# Initialize database on startup
init_db()

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

# ==================== Authentication Endpoints ====================

@app.route('/api/auth/signup', methods=['POST'])
def signup():
    """Create new user account"""
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        full_name = data.get('fullName')
        user_type = data.get('userType', 'student')

        if not all([email, password, full_name]):
            return jsonify({'error': 'All fields are required'}), 400

        # Validate UCLA email for students
        if user_type == 'student':
            if not (email.endswith('@ucla.edu') or email.endswith('@g.ucla.edu')):
                return jsonify({'error': 'Students must use a UCLA email'}), 400

        conn = get_db()
        c = conn.cursor()

        # Check if user already exists
        c.execute('SELECT id FROM users WHERE email = ?', (email,))
        if c.fetchone():
            conn.close()
            return jsonify({'error': 'Email already registered'}), 400

        # Create new user
        user_id = str(uuid.uuid4())
        password_hash = hash_password(password)

        c.execute('''
            INSERT INTO users (id, email, password_hash, full_name, user_type)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, email, password_hash, full_name, user_type))

        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'user': {
                'id': user_id,
                'email': email,
                'fullName': full_name,
                'userType': user_type
            }
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Login user"""
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if not all([email, password]):
            return jsonify({'error': 'Email and password are required'}), 400

        conn = get_db()
        c = conn.cursor()

        password_hash = hash_password(password)
        c.execute('''
            SELECT id, email, full_name, user_type
            FROM users
            WHERE email = ? AND password_hash = ?
        ''', (email, password_hash))

        user = c.fetchone()
        conn.close()

        if not user:
            return jsonify({'error': 'Invalid email or password'}), 401

        return jsonify({
            'success': True,
            'user': {
                'id': user['id'],
                'email': user['email'],
                'fullName': user['full_name'],
                'userType': user['user_type']
            }
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== Lab Endpoints ====================

@app.route('/api/labs', methods=['GET'])
def get_labs():
    """Get all research labs"""
    try:
        conn = get_db()
        c = conn.cursor()

        c.execute('''
            SELECT id, name, pi_name, department, description, requirements,
                   commitment, location, website, research_areas
            FROM labs
            ORDER BY created_at DESC
        ''')

        labs = []
        for row in c.fetchall():
            labs.append({
                'id': row['id'],
                'name': row['name'],
                'piName': row['pi_name'],
                'department': row['department'],
                'description': row['description'],
                'requirements': row['requirements'],
                'commitment': row['commitment'],
                'location': row['location'],
                'website': row['website'],
                'researchAreas': row['research_areas'].split(',') if row['research_areas'] else []
            })

        conn.close()
        return jsonify({'labs': labs}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/labs/<lab_id>', methods=['GET'])
def get_lab(lab_id):
    """Get specific lab details"""
    try:
        conn = get_db()
        c = conn.cursor()

        c.execute('''
            SELECT id, name, pi_name, department, description, requirements,
                   commitment, location, website, research_areas
            FROM labs
            WHERE id = ?
        ''', (lab_id,))

        row = c.fetchone()
        conn.close()

        if not row:
            return jsonify({'error': 'Lab not found'}), 404

        lab = {
            'id': row['id'],
            'name': row['name'],
            'piName': row['pi_name'],
            'department': row['department'],
            'description': row['description'],
            'requirements': row['requirements'],
            'commitment': row['commitment'],
            'location': row['location'],
            'website': row['website'],
            'researchAreas': row['research_areas'].split(',') if row['research_areas'] else []
        }

        return jsonify({'lab': lab}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/labs', methods=['POST'])
def create_lab():
    """Create new research lab (professors only)"""
    try:
        data = request.get_json()

        required_fields = ['name', 'professorId', 'piName', 'department', 'description']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400

        lab_id = str(uuid.uuid4())

        conn = get_db()
        c = conn.cursor()

        c.execute('''
            INSERT INTO labs (id, name, professor_id, pi_name, department, description,
                            requirements, commitment, location, website, research_areas)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            lab_id,
            data['name'],
            data['professorId'],
            data['piName'],
            data['department'],
            data['description'],
            data.get('requirements', ''),
            data.get('commitment', ''),
            data.get('location', ''),
            data.get('website', ''),
            ','.join(data.get('researchAreas', []))
        ))

        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'labId': lab_id
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== Application Endpoints ====================

@app.route('/api/labs/<lab_id>/apply', methods=['POST'])
def apply_to_lab(lab_id):
    """Submit application to a lab"""
    try:
        data = request.get_json()
        student_id = data.get('studentId')
        cover_letter = data.get('coverLetter')

        if not all([student_id, cover_letter]):
            return jsonify({'error': 'Student ID and cover letter are required'}), 400

        conn = get_db()
        c = conn.cursor()

        # Check if lab exists
        c.execute('SELECT id FROM labs WHERE id = ?', (lab_id,))
        if not c.fetchone():
            conn.close()
            return jsonify({'error': 'Lab not found'}), 404

        # Check if already applied
        c.execute('''
            SELECT id FROM applications
            WHERE lab_id = ? AND student_id = ?
        ''', (lab_id, student_id))

        if c.fetchone():
            conn.close()
            return jsonify({'error': 'You have already applied to this lab'}), 400

        # Create application
        application_id = str(uuid.uuid4())
        c.execute('''
            INSERT INTO applications (id, lab_id, student_id, cover_letter, status)
            VALUES (?, ?, ?, ?, ?)
        ''', (application_id, lab_id, student_id, cover_letter, 'pending'))

        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'applicationId': application_id,
            'message': 'Application submitted successfully'
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/applications/<student_id>', methods=['GET'])
def get_student_applications(student_id):
    """Get all applications for a student"""
    try:
        conn = get_db()
        c = conn.cursor()

        c.execute('''
            SELECT a.id, a.lab_id, a.cover_letter, a.status, a.created_at,
                   l.name as lab_name, l.pi_name, l.department
            FROM applications a
            JOIN labs l ON a.lab_id = l.id
            WHERE a.student_id = ?
            ORDER BY a.created_at DESC
        ''', (student_id,))

        applications = []
        for row in c.fetchall():
            applications.append({
                'id': row['id'],
                'labId': row['lab_id'],
                'labName': row['lab_name'],
                'piName': row['pi_name'],
                'department': row['department'],
                'coverLetter': row['cover_letter'],
                'status': row['status'],
                'createdAt': row['created_at']
            })

        conn.close()
        return jsonify({'applications': applications}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== Health Check ====================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'Catalyst Research Matching API',
        'timestamp': datetime.now().isoformat()
    }), 200

# ==================== AI Matching Helper Functions ====================

def convert_to_candidate_model(application_data: Dict[str, Any]) -> Candidate:
    """Convert simple application data to AI algorithm's Candidate model"""

    # Create transcript with courses if available
    courses = []
    if 'courses' in application_data:
        for course in application_data['courses']:
            courses.append(Course(
                name=course.get('name', ''),
                grade_points=float(course.get('grade', 3.0)),
                credits=int(course.get('credits', 4))
            ))

    transcript = Transcript(
        university=application_data.get('university', 'UCLA'),
        major=application_data.get('major', ''),
        gpa=float(application_data.get('gpa', 3.0)),
        courses=courses
    )

    # Create research experiences if available
    research_exps = []
    if 'researchExperiences' in application_data:
        for exp in application_data['researchExperiences']:
            research_exps.append(ResearchExperience(
                lab_name=exp.get('labName', ''),
                description=exp.get('description', ''),
                duration_months=int(exp.get('durationMonths', 6)),
                hours_per_week=int(exp.get('hoursPerWeek', 10))
            ))

    # Create candidate
    return Candidate(
        id=application_data.get('id', str(uuid.uuid4())),
        name=application_data.get('studentName', application_data.get('fullName', '')),
        email=application_data.get('email', ''),
        transcript=transcript,
        personal_essay=application_data.get('coverLetter', application_data.get('bio', '')),
        career_goals=[application_data.get('interests', '').split(',')[0]] if application_data.get('interests') else [],
        skills=application_data.get('skills', '').split(',') if application_data.get('skills') else [],
        research_experiences=research_exps,
        experience_level=ExperienceLevel.BEGINNER  # Default for now
    )

def convert_to_lab_model(lab_data: Dict[str, Any]) -> Lab:
    """Convert simple lab data to AI algorithm's Lab model"""

    return Lab(
        id=lab_data.get('id', str(uuid.uuid4())),
        name=lab_data.get('name', lab_data.get('labName', '')),
        pi_name=lab_data.get('pi_name', lab_data.get('piName', '')),
        department=lab_data.get('department', ''),
        description=lab_data.get('description', ''),
        required_skills=lab_data.get('requirements', '').split(',') if lab_data.get('requirements') else [],
        preferred_experience_level=ExperienceLevel.BEGINNER,  # Default
        research_areas=lab_data.get('research_areas', '').split(',') if lab_data.get('research_areas') else []
    )

# ==================== AI Matching Endpoints ====================

@app.route('/api/ai/match-score', methods=['POST'])
def calculate_ai_match_score():
    """
    Calculate AI match score between a student and a lab

    Request body:
    {
        "student": {
            "studentName": "...",
            "email": "...",
            "major": "...",
            "gpa": "3.8",
            "skills": "Python, ML, Data Analysis",
            "coverLetter": "...",
            ...
        },
        "lab": {
            "name": "...",
            "department": "...",
            "description": "...",
            "requirements": "...",
            ...
        }
    }

    Returns:
    {
        "score": 85,
        "reasoning": "Strong match: ...",
        "tier": "high_priority",
        "strengths": [...],
        "gaps": [...]
    }
    """
    if not AI_MATCHING_ENABLED:
        return jsonify({
            'error': 'AI matching not available',
            'fallback': True,
            'score': 75,
            'reasoning': 'Using basic matching (AI modules not loaded)'
        }), 200

    try:
        data = request.get_json()
        student_data = data.get('student', {})
        lab_data = data.get('lab', {})

        if not student_data or not lab_data:
            return jsonify({'error': 'Student and lab data required'}), 400

        # Convert to AI model format
        candidate = convert_to_candidate_model(student_data)
        lab = convert_to_lab_model(lab_data)

        # Initialize AI algorithm with embedding system
        embedding_system = SimpleEmbedding()
        ats = LabATSAlgorithm(embedding_system)

        # Calculate match score
        result = ats.score_candidate(candidate, lab)

        # Return results
        return jsonify({
            'score': int(result.total_score),
            'reasoning': result.explanation,
            'tier': result.tier.value if hasattr(result.tier, 'value') else str(result.tier),
            'strengths': result.strengths,
            'gaps': result.gaps,
            'breakdown': {
                component.name: {
                    'score': component.score,
                    'reasoning': component.reasoning
                }
                for component in result.score_components
            } if hasattr(result, 'score_components') else {}
        }), 200

    except Exception as e:
        print(f"Error in AI matching: {e}")
        import traceback
        traceback.print_exc()

        # Return fallback simple score
        return jsonify({
            'error': str(e),
            'fallback': True,
            'score': 70,
            'reasoning': 'Error occurred, using fallback matching'
        }), 200

@app.route('/api/ai/batch-match', methods=['POST'])
def batch_match_candidates():
    """
    Calculate match scores for multiple candidates against a single lab

    Request body:
    {
        "lab": { ... },
        "candidates": [ { ... }, { ... }, ... ]
    }

    Returns:
    {
        "matches": [
            {
                "candidateId": "...",
                "candidateName": "...",
                "score": 85,
                "reasoning": "...",
                "tier": "high_priority"
            },
            ...
        ]
    }
    """
    if not AI_MATCHING_ENABLED:
        return jsonify({
            'error': 'AI matching not available'
        }), 503

    try:
        data = request.get_json()
        lab_data = data.get('lab', {})
        candidates_data = data.get('candidates', [])

        if not lab_data or not candidates_data:
            return jsonify({'error': 'Lab and candidates data required'}), 400

        # Convert lab to model
        lab = convert_to_lab_model(lab_data)

        # Initialize AI algorithm
        embedding_system = SimpleEmbedding()
        ats = LabATSAlgorithm(embedding_system)

        # Calculate scores for all candidates
        matches = []
        for candidate_data in candidates_data:
            try:
                candidate = convert_to_candidate_model(candidate_data)
                result = ats.score_candidate(candidate, lab)

                matches.append({
                    'candidateId': candidate.id,
                    'candidateName': candidate.name,
                    'candidateEmail': candidate.email,
                    'score': int(result.total_score),
                    'reasoning': result.explanation,
                    'tier': result.tier.value if hasattr(result.tier, 'value') else str(result.tier),
                    'strengths': result.strengths,
                    'gaps': result.gaps
                })
            except Exception as e:
                print(f"Error scoring candidate {candidate_data.get('id', 'unknown')}: {e}")
                continue

        # Sort by score descending
        matches.sort(key=lambda x: x['score'], reverse=True)

        return jsonify({
            'matches': matches,
            'totalProcessed': len(matches)
        }), 200

    except Exception as e:
        print(f"Error in batch matching: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/', methods=['GET'])
def index():
    """Root endpoint"""
    return jsonify({
        'service': 'Catalyst Research Lab Matching Platform',
        'version': '1.0.0',
        'aiMatching': AI_MATCHING_ENABLED,
        'endpoints': {
            'auth': {
                'signup': 'POST /api/auth/signup',
                'login': 'POST /api/auth/login'
            },
            'labs': {
                'list': 'GET /api/labs',
                'get': 'GET /api/labs/<id>',
                'create': 'POST /api/labs',
                'apply': 'POST /api/labs/<id>/apply'
            },
            'applications': {
                'list': 'GET /api/applications/<student_id>'
            },
            'ai': {
                'matchScore': 'POST /api/ai/match-score',
                'batchMatch': 'POST /api/ai/batch-match'
            }
        }
    }), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5002))
    app.run(host='0.0.0.0', port=port, debug=True)
