from flask import Flask, request, jsonify, send_from_directory, render_template_string
from flask_cors import CORS
from pathlib import Path
import json
import sys
import os

# Add the current directory to path to import our modules
sys.path.append('/Users/rishitjain/Downloads')

from rag_chatbot import EnronRAGChatbot
from premium_powerpoint_generator import PremiumPowerPointGenerator

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend requests

# Initialize systems
OPENAI_KEY = "REDACTED_OPENAI_KEY"
PINECONE_KEY = "REDACTED_PINECONE_KEY"

# Initialize chatbot (will be done on first use to save startup time)
chatbot = None
projects_data = None

def get_chatbot():
    """Lazy initialization of chatbot"""
    global chatbot
    if chatbot is None:
        print("Initializing chatbot...")
        chatbot = EnronRAGChatbot(
            data_dir="/Users/rishitjain/Downloads/enron_processed",
            openai_key=OPENAI_KEY,
            pinecone_key=PINECONE_KEY
        )
        # Setup embeddings if not done
        # chatbot.setup_pinecone_index()  # Uncomment if needed
        # chatbot.embed_and_store_corpus()  # Uncomment if needed
        print("Chatbot ready!")
    return chatbot

def get_projects():
    """Load projects data"""
    global projects_data
    if projects_data is None:
        projects_file = Path("/Users/rishitjain/Downloads/enron_processed/identified_projects.json")
        with open(projects_file, 'r') as f:
            data = json.load(f)
            projects_data = data['projects']
    return projects_data

# Serve frontend files
FRONTEND_DIR = '/Users/rishitjain/Downloads/Knowledge-Vault--main'

@app.route('/')
def index():
    return send_from_directory(FRONTEND_DIR, 'index.html')

@app.route('/<path:path>')
def serve_frontend(path):
    try:
        return send_from_directory(FRONTEND_DIR, path)
    except:
        return send_from_directory(FRONTEND_DIR, 'index.html')

# API: Get all emails
@app.route('/api/all-emails', methods=['GET'])
def get_all_emails():
    """Get all emails from the processed Enron dataset"""
    try:
        data_dir = Path("/Users/rishitjain/Downloads/enron_processed/projects")
        print(f"Looking in directory: {data_dir}")
        print(f"Directory exists: {data_dir.exists()}")
        
        all_emails = []
        
        # Load emails from all project files
        project_files = sorted(data_dir.glob("project_*.json"))
        print(f"Found {len(project_files)} project files")
        
        for project_file in project_files:
            print(f"Processing file: {project_file.name}")
            
            if project_file.name in ['project_statistics.json', 'identified_projects.json']:
                print(f"  Skipping {project_file.name}")
                continue
                
            try:
                with open(project_file, 'r') as f:
                    project_data = json.load(f)
                    
                    # Get items from the project file
                    items_list = project_data.get('items', [])
                    print(f"  Found {len(items_list)} items in {project_file.name}")
                    
                    if items_list:
                        for idx, item in enumerate(items_list):
                            # Extract email data from metadata
                            metadata = item.get('metadata', {})
                            
                            # Parse the text field for email content
                            text = item.get('text', '')
                            
                            # Extract body from text
                            body = ''
                            if 'Body:' in text:
                                body = text.split('Body:', 1)[1].strip()
                            
                            email = {
                                'id': item.get('id', f'email_{len(all_emails)}'),
                                'message_id': item.get('id', ''),
                                'subject': metadata.get('subject', 'No Subject'),
                                'from': metadata.get('from', 'kevin.presto@enron.com'),
                                'to': metadata.get('to', ''),
                                'date': metadata.get('date', ''),
                                'body': body,
                                'content': body,
                                'project': project_data.get('project', {}).get('name', project_file.stem),
                                'type': item.get('type', 'email')
                            }
                            all_emails.append(email)
                            
                            if idx == 0:
                                print(f"  Sample email: {email['subject']}")
                                
            except Exception as e:
                print(f"Error reading {project_file}: {e}")
                import traceback
                traceback.print_exc()
                continue
        
        print(f"Total emails collected: {len(all_emails)}")
        
        return jsonify({
            'success': True,
            'emails': all_emails,
            'total': len(all_emails)
        })
    
    except Exception as e:
        print(f"Error in get_all_emails: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e),
            'emails': [],
            'total': 0
        }), 500

# API: Get all projects
@app.route('/api/projects', methods=['GET'])
def get_all_projects():
    """Get list of all projects"""
    try:
        projects = get_projects()
        
        # Load statistics
        stats_file = Path("/Users/rishitjain/Downloads/enron_processed/project_statistics.json")
        with open(stats_file, 'r') as f:
            stats = json.load(f)
        
        # Combine project info with stats
        projects_with_stats = []
        for project in projects:
            project_id = project['id']
            if project_id in stats['project_distribution']:
                project_stats = stats['project_distribution'][project_id]
                projects_with_stats.append({
                    'id': project_id,
                    'name': project['name'],
                    'description': project['description'],
                    'keywords': project['keywords'],
                    'item_count': project_stats['count'],
                    'percentage': project_stats['percentage']
                })
        
        return jsonify({
            'success': True,
            'projects': projects_with_stats
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# API: Chat endpoint
@app.route('/api/chat', methods=['POST'])
def chat():
    """Handle chatbot queries"""
    try:
        data = request.json
        question = data.get('question', '')
        project_filter = data.get('project_id', None)
        
        if not question:
            return jsonify({
                'success': False,
                'error': 'Question is required'
            }), 400
        
        # Get chatbot
        bot = get_chatbot()
        
        # Get answer
        result = bot.answer_question(
            question=question,
            project_filter=project_filter,
            top_k=5
        )
        
        return jsonify({
            'success': True,
            'answer': result['answer'],
            'sources': result['sources'],
            'num_sources': result['num_sources']
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# API: Get training videos/presentations
@app.route('/api/training-materials', methods=['GET'])
def get_training_materials():
    """Get available training materials (presentations/videos)"""
    try:
        materials = {
            'videos': [],
            'documents': []
        }
        
        projects = get_projects()
        
        # Check for videos
        video_dir = Path("/Users/rishitjain/Downloads/final_videos_from_ppt")
        if video_dir.exists():
            for video_file in video_dir.glob("*.mp4"):
                # Extract project_id from filename (e.g., "project_5_ercot_demo_narrated.mp4")
                filename_parts = video_file.stem.split('_')
                if len(filename_parts) >= 2 and filename_parts[0] == 'project':
                    project_id = f"{filename_parts[0]}_{filename_parts[1]}"
                    
                    # Find project info
                    project = next((p for p in projects if p['id'] == project_id), None)
                    
                    if project:
                        # Check for thumbnail
                        thumb_path = Path("/Users/rishitjain/Downloads/thumbnails/videos") / f"{video_file.stem}.png"
                        
                        materials['videos'].append({
                            'id': project_id,
                            'name': project['name'],
                            'description': project['description'],
                            'keywords': project['keywords'],
                            'file': video_file.name,
                            'download_url': f'/api/download/video/{video_file.name}',
                            'thumbnail': f'/api/thumbnail/video/{video_file.stem}.png' if thumb_path.exists() else None,
                            'category': 'Development'  # Default, can be enhanced
                        })
        
        # Check for PowerPoint documents
        ppt_dir = Path("/Users/rishitjain/Downloads/premium_presentations")
        if ppt_dir.exists():
            for ppt_file in ppt_dir.glob("*_comprehensive.pptx"):
                filename_parts = ppt_file.stem.split('_')
                if len(filename_parts) >= 2 and filename_parts[0] == 'project':
                    project_id = f"{filename_parts[0]}_{filename_parts[1]}"
                    
                    project = next((p for p in projects if p['id'] == project_id), None)
                    
                    if project:
                        thumb_path = Path("/Users/rishitjain/Downloads/thumbnails/documents") / f"{ppt_file.stem}.png"
                        
                        materials['documents'].append({
                            'id': project_id,
                            'name': project['name'],
                            'description': project['description'],
                            'keywords': project['keywords'],
                            'file': ppt_file.name,
                            'download_url': f'/api/download/presentation/{ppt_file.name}',
                            'thumbnail': f'/api/thumbnail/document/{ppt_file.stem}.png' if thumb_path.exists() else None,
                            'category': 'Development'
                        })
        
        return jsonify({
            'success': True,
            'materials': materials
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# API: Serve thumbnails
@app.route('/api/thumbnail/<type>/<filename>')
def serve_thumbnail(type, filename):
    """Serve thumbnail images"""
    thumb_dir = Path("/Users/rishitjain/Downloads/thumbnails") / type
    return send_from_directory(thumb_dir, filename)

# API: Download presentation
@app.route('/api/download/presentation/<filename>')
def download_presentation(filename):
    """Download PowerPoint presentation"""
    ppt_dir = Path("/Users/rishitjain/Downloads/premium_presentations")
    return send_from_directory(ppt_dir, filename, as_attachment=True)

# API: Download/stream video
@app.route('/api/download/video/<filename>')
def download_video(filename):
    """Download or stream video"""
    video_dir = Path("/Users/rishitjain/Downloads/final_videos_from_ppt")
    return send_from_directory(video_dir, filename)

# API: Generate new presentation for a project
@app.route('/api/generate/presentation', methods=['POST'])
def generate_presentation():
    """Generate new PowerPoint presentation for a project"""
    try:
        data = request.json
        project_id = data.get('project_id')
        
        if not project_id:
            return jsonify({
                'success': False,
                'error': 'project_id is required'
            }), 400
        
        # Generate presentation
        generator = PremiumPowerPointGenerator(
            data_dir="/Users/rishitjain/Downloads/enron_processed",
            openai_key=OPENAI_KEY
        )
        
        output_file = generator.generate_comprehensive_presentation(project_id)
        
        if output_file:
            return jsonify({
                'success': True,
                'message': 'Presentation generated successfully',
                'file': output_file.name,
                'download_url': f'/api/download/presentation/{output_file.name}'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to generate presentation'
            }), 500
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Health check
@app.route('/api/health')
def health():
    return jsonify({
        'success': True,
        'status': 'running',
        'chatbot_loaded': chatbot is not None
    })

if __name__ == '__main__':
    print("="*70)
    print("KNOWLEDGE VAULT BACKEND SERVER")
    print("="*70)
    print("\nStarting server...")
    print("Frontend: http://localhost:5001")
    print("API Base: http://localhost:5001/api")
    print("\nAvailable endpoints:")
    print("  GET  /api/projects - List all projects")
    print("  POST /api/chat - Chat with AI")
    print("  GET  /api/training-materials - Get presentations/videos")
    print("  POST /api/generate/presentation - Generate new presentation")
    print("\nPress Ctrl+C to stop")
    print("="*70)
    
    app.run(debug=True, host='0.0.0.0', port=5001)
