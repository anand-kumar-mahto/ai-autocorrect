from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from langdetect import detect
from deep_translator import GoogleTranslator
import language_tool_python
import requests
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'
CORS(app)

# DB setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Login manager
login_manager = LoginManager()
login_manager.init_app(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    is_premium = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Serve frontend files
@app.route('/')
def serve_frontend():
    return send_from_directory('../frontend', 'index.html')

@app.route('/<path:path>')
def serve_static_files(path):
    return send_from_directory('../frontend', path)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    first_name = data.get('first_name', '')
    last_name = data.get('last_name', '')
    
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'success': False, 'message': 'Email already registered'}), 400
    
    hashed_password = generate_password_hash(password)
    new_user = User(
        email=email,
        password=hashed_password,
        first_name=first_name,
        last_name=last_name,
        is_premium=False
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Registered successfully!'})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    user = User.query.filter_by(email=email).first()
    
    if user and check_password_hash(user.password, password):
        login_user(user)
        return jsonify({
            'success': True, 
            'email': user.email, 
            'is_premium': user.is_premium,
            'first_name': user.first_name,
            'last_name': user.last_name
        })
    return jsonify({'success': False, 'message': 'Invalid credentials'})

@app.route('/logout', methods=['POST'])
def logout():
    logout_user()
    return jsonify({'success': True})

@app.route('/upgrade', methods=['POST'])
@login_required
def upgrade():
    current_user.is_premium = True
    db.session.commit()
    return jsonify({'success': True})

@app.route('/correct', methods=['POST'])
def correct_text():
    data = request.get_json()
    input_text = data.get('text', '')

    if not input_text.strip():
        return jsonify({'corrected': '', 'alternatives': []})

    try:
        # Using the free LanguageTool API instead of the paid one
        response = requests.post(
            'https://api.languagetool.org/v2/check',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            data={
                'text': input_text,
                'language': 'en-US'
            }
        )

        result = response.json()
        matches = result.get('matches', [])
        corrected_text = input_text
        offset_shift = 0

        alternatives = []

        for match in matches:
            replacements = match.get('replacements', [])
            if not replacements:
                continue

            start = match['offset'] + offset_shift
            end = start + match['length']
            incorrect = corrected_text[start:end]

            best_replacement = replacements[0]['value']
            corrected_text = corrected_text[:start] + best_replacement + corrected_text[end:]
            offset_shift += len(best_replacement) - match['length']

            suggestions = [rep['value'] for rep in replacements[:5]]  # limit to top 5
            message = match.get('message', '')

            alternatives.append({
                'error': incorrect,
                'suggestions': suggestions,
                'message': message
            })

        return jsonify({
            'corrected': corrected_text,
            'alternatives': alternatives
        })

    except Exception as e:
        # Fallback to local language-tool-python if API fails
        try:
            lang_tool = language_tool_python.LanguageToolPublicAPI('en-US')
            matches = lang_tool.check(input_text)
            corrected_text = language_tool_python.utils.correct(input_text, matches)
            
            alternatives = []
            for match in matches:
                if match.replacements:
                    suggestions = [rep.value for rep in match.replacements[:5]]
                    alternatives.append({
                        'error': input_text[match.offset:match.offset + match.length],
                        'suggestions': suggestions,
                        'message': match.message
                    })
            
            lang_tool.close()
            return jsonify({
                'corrected': corrected_text,
                'alternatives': alternatives
            })
        except Exception as fallback_error:
            # If both methods fail, return original text
            return jsonify({
                'corrected': input_text,
                'alternatives': []
            })


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)
