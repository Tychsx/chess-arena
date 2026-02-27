"""
Chess Arena — Python Backend
Flask + Flask-SocketIO + SQLAlchemy + Resend + Google OAuth
"""
import os, string, random, time, json, re, html
from datetime import datetime, timedelta, timezone
from functools import wraps

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bcrypt
import chess

# Optional: Resend
try:
    import resend
    RESEND_AVAILABLE = True
except ImportError:
    RESEND_AVAILABLE = False

# Optional: Google Auth
try:
    from google.oauth2 import id_token as google_id_token
    from google.auth.transport import requests as google_requests
    GOOGLE_AUTH_AVAILABLE = True
except ImportError:
    GOOGLE_AUTH_AVAILABLE = False

# ============ App Setup ============
app = Flask(__name__, static_folder='public', static_url_path='')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'chess-arena-dev-secret-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///chess.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

CORS(app)
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://"
)

# ============ Config ============
RESEND_API_KEY = os.getenv('RESEND_API_KEY', '')
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID', '')
FROM_EMAIL = os.getenv('FROM_EMAIL', 'onboarding@resend.dev')

if RESEND_API_KEY and RESEND_AVAILABLE:
    resend.api_key = RESEND_API_KEY
    print('📧 Resend email configured')
else:
    print('📧 Resend not configured — codes will be shown in API response')
    print('   Get a free API key at https://resend.com')

if GOOGLE_CLIENT_ID and GOOGLE_AUTH_AVAILABLE:
    print(f'🔑 Google Sign-In configured (Client ID: {GOOGLE_CLIENT_ID[:20]}...)')
else:
    print('🔑 Google Sign-In not configured — set GOOGLE_CLIENT_ID in .env')

# ============ Database Models ============
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    verified = db.Column(db.Boolean, default=False)
    google_user = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.utcnow())
    wins = db.Column(db.Integer, default=0)
    losses = db.Column(db.Integer, default=0)
    draws = db.Column(db.Integer, default=0)
    games_played = db.Column(db.Integer, default=0)

    def to_public(self):
        return {
            'email': self.email,
            'username': self.username,
            'verified': self.verified,
            'googleUser': self.google_user,
            'stats': {
                'wins': self.wins, 'losses': self.losses,
                'draws': self.draws, 'gamesPlayed': self.games_played
            },
            'gameHistory': [g.to_dict() for g in GameHistory.query.filter(
                (GameHistory.white_player == self.username) | (GameHistory.black_player == self.username)
            ).order_by(GameHistory.created_at.desc()).limit(50).all()]
        }

class VerificationCode(db.Model):
    __tablename__ = 'verification_codes'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False, index=True)
    code = db.Column(db.String(6), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    attempts = db.Column(db.Integer, default=0)

class ResetCode(db.Model):
    __tablename__ = 'reset_codes'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False, index=True)
    code = db.Column(db.String(6), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    attempts = db.Column(db.Integer, default=0)

class GameHistory(db.Model):
    __tablename__ = 'game_history'
    id = db.Column(db.Integer, primary_key=True)
    white_player = db.Column(db.String(20), nullable=False)
    black_player = db.Column(db.String(20), nullable=False)
    winner = db.Column(db.String(10))  # 'white', 'black', 'draw'
    time_control = db.Column(db.String(10))
    moves_json = db.Column(db.Text, default='[]')
    created_at = db.Column(db.DateTime, default=lambda: datetime.utcnow())

    def to_dict(self):
        return {
            'white': self.white_player, 'black': self.black_player,
            'result': self.winner, 'timeControl': self.time_control,
            'moves': json.loads(self.moves_json or '[]'),
            'date': self.created_at.isoformat() if self.created_at else ''
        }

# ============ Helpers ============
def generate_code():
    return ''.join(random.choices(string.digits, k=6))

def generate_room_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

def sanitize(text, max_len=100):
    if not text:
        return ''
    text = str(text)[:max_len]
    text = html.escape(text)
    text = re.sub(r'<[^>]*>', '', text)
    return text.strip()

def is_valid_email(email):
    return bool(re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email))

def is_strong_password(password):
    return (len(password) >= 6 and
            bool(re.search(r'[A-Z]', password)) and
            bool(re.search(r'[a-z]', password)) and
            bool(re.search(r'[0-9]', password)))

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(12)).decode('utf-8')

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# ============ Email Service ============
def send_email(to, subject, html_content):
    """Send email via Resend. Returns dict with sent status."""
    if not RESEND_API_KEY or not RESEND_AVAILABLE:
        print(f'📧 [DEV] Would send email to {to}: {subject}')
        return {'sent': False}
    try:
        result = resend.Emails.send({
            'from': FROM_EMAIL,
            'to': [to],
            'subject': subject,
            'html': html_content
        })
        print(f'📧 Email sent to {to} — ID: {result.get("id", "?")}')
        return {'sent': True}
    except Exception as e:
        print(f'❌ Email send error: {e}')
        return {'sent': False}

def make_verify_email_html(username, code):
    return f'''
    <div style="font-family:Arial,sans-serif;max-width:460px;margin:0 auto;padding:32px;background:#12121a;color:#e8e8f0;border-radius:12px;">
      <h2 style="text-align:center;color:#a88bfa;">♔ Chess Arena</h2>
      <p>Hi <strong>{html.escape(username)}</strong>,</p>
      <p>Your verification code is:</p>
      <div style="text-align:center;margin:24px 0;">
        <span style="font-size:36px;font-weight:800;letter-spacing:8px;color:#a88bfa;font-family:monospace;">{code}</span>
      </div>
      <p style="color:#8888a8;font-size:13px;">This code expires in 10 minutes. If you didn't create an account, ignore this email.</p>
    </div>'''

def make_reset_email_html(username, code):
    return f'''
    <div style="font-family:Arial,sans-serif;max-width:460px;margin:0 auto;padding:32px;background:#12121a;color:#e8e8f0;border-radius:12px;">
      <h2 style="text-align:center;color:#a88bfa;">♔ Chess Arena</h2>
      <p>Hi <strong>{html.escape(username)}</strong>,</p>
      <p>Your password reset code is:</p>
      <div style="text-align:center;margin:24px 0;">
        <span style="font-size:36px;font-weight:800;letter-spacing:8px;color:#a88bfa;font-family:monospace;">{code}</span>
      </div>
      <p style="color:#8888a8;font-size:13px;">This code expires in 10 minutes. If you didn't request a reset, ignore this email.</p>
    </div>'''

# ============ Static Files ============
@app.route('/')
def index():
    return send_from_directory('public', 'index.html')

@app.route('/<path:filename>')
def static_files(filename):
    # Don't intercept socket.io requests
    if filename.startswith('socket.io'):
        return '', 404
    return send_from_directory('public', filename)

# ============ Auth API ============
@app.route('/api/signup', methods=['POST'])
@limiter.limit("20/15 minutes")
def signup():
    try:
        data = request.get_json()
        username = sanitize(data.get('username', ''), 20)
        email = sanitize(data.get('email', ''), 100).lower()
        password = data.get('password', '')

        if not username or not email or not password:
            return jsonify({'error': 'All fields are required.'}), 400
        if len(username) < 2:
            return jsonify({'error': 'Username must be at least 2 characters.'}), 400
        if not is_valid_email(email):
            return jsonify({'error': 'Invalid email address.'}), 400
        if not is_strong_password(password):
            return jsonify({'error': 'Password needs 6+ chars with uppercase, lowercase, and a number.'}), 400

        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'An account with this email already exists.'}), 409

        user = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
            verified=False,
            google_user=False
        )
        db.session.add(user)

        # Generate verification code
        code = generate_code()
        # Remove old codes
        VerificationCode.query.filter_by(email=email).delete()
        vc = VerificationCode(
            email=email,
            code=code,
            expires_at=datetime.utcnow() + timedelta(minutes=10)
        )
        db.session.add(vc)
        db.session.commit()

        # Send email
        email_result = send_email(email, 'Chess Arena — Verify Your Email',
                                  make_verify_email_html(username, code))

        response = {
            'success': True,
            'message': 'Account created! Check your email for a verification code.',
            'requiresVerification': True,
            'email': email
        }

        if not email_result['sent']:
            response['devCode'] = code
            response['message'] = 'Account created! (Email not configured — code shown below)'

        return jsonify(response)
    except Exception as e:
        db.session.rollback()
        print(f'Signup error: {e}')
        return jsonify({'error': 'Server error. Please try again.'}), 500


@app.route('/api/verify-email', methods=['POST'])
@limiter.limit("10/5 minutes")
def verify_email():
    data = request.get_json()
    email = sanitize(data.get('email', ''), 100).lower()
    code = sanitize(data.get('code', ''), 6)

    vc = VerificationCode.query.filter_by(email=email).first()
    if not vc:
        return jsonify({'error': 'No verification pending for this email.'}), 400

    if vc.attempts >= 5:
        db.session.delete(vc)
        db.session.commit()
        return jsonify({'error': 'Too many failed attempts. Please sign up again.'}), 400

    if datetime.utcnow() > vc.expires_at:
        db.session.delete(vc)
        db.session.commit()
        return jsonify({'error': 'Code expired. Please request a new one.'}), 400

    if vc.code != code:
        vc.attempts += 1
        db.session.commit()
        return jsonify({'error': f'Invalid code. {5 - vc.attempts} attempts remaining.'}), 400

    # Success
    user = User.query.filter_by(email=email).first()
    if user:
        user.verified = True
    db.session.delete(vc)
    db.session.commit()

    return jsonify({'success': True, 'user': user.to_public() if user else None})


@app.route('/api/resend-code', methods=['POST'])
@limiter.limit("5/5 minutes")
def resend_code():
    data = request.get_json()
    email = sanitize(data.get('email', ''), 100).lower()

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'success': True, 'message': 'If account exists, code was sent.'})

    code = generate_code()
    VerificationCode.query.filter_by(email=email).delete()
    vc = VerificationCode(
        email=email, code=code,
        expires_at=datetime.utcnow() + timedelta(minutes=10)
    )
    db.session.add(vc)
    db.session.commit()

    email_result = send_email(email, 'Chess Arena — New Verification Code',
                              make_verify_email_html(user.username, code))

    response = {'success': True, 'message': 'New verification code sent!'}
    if not email_result['sent']:
        response['devCode'] = code
        response['message'] = 'Code generated (email not configured — shown below)'

    return jsonify(response)


@app.route('/api/login', methods=['POST'])
@limiter.limit("20/15 minutes")
def login():
    try:
        data = request.get_json()
        email = sanitize(data.get('email', ''), 100).lower()
        password = data.get('password', '')

        user = User.query.filter_by(email=email).first()
        if not user:
            # Dummy hash to prevent timing attacks
            bcrypt.hashpw(b'dummy', bcrypt.gensalt(4))
            return jsonify({'error': 'Invalid email or password.'}), 401

        if user.google_user and not user.password_hash:
            return jsonify({'error': 'This account uses Google Sign-In. Please use the Google button.'}), 401

        if not user.password_hash or not check_password(password, user.password_hash):
            return jsonify({'error': 'Invalid email or password.'}), 401

        if not user.verified:
            code = generate_code()
            VerificationCode.query.filter_by(email=email).delete()
            vc = VerificationCode(
                email=email, code=code,
                expires_at=datetime.utcnow() + timedelta(minutes=10)
            )
            db.session.add(vc)
            db.session.commit()

            email_result = send_email(email, 'Chess Arena — Verify Your Email',
                                      make_verify_email_html(user.username, code))

            response = {'requiresVerification': True, 'email': email,
                        'message': 'Please verify your email first.'}
            if not email_result['sent']:
                response['devCode'] = code
            return jsonify(response), 403

        return jsonify({'success': True, 'user': user.to_public()})
    except Exception as e:
        print(f'Login error: {e}')
        return jsonify({'error': 'Server error.'}), 500


@app.route('/api/google-login', methods=['POST'])
@limiter.limit("20/15 minutes")
def google_login():
    if not GOOGLE_CLIENT_ID or not GOOGLE_AUTH_AVAILABLE:
        return jsonify({'error': 'Google Sign-In is not configured on the server.'}), 501

    try:
        data = request.get_json()
        credential = data.get('credential', '')
        if not credential:
            return jsonify({'error': 'Missing credential.'}), 400

        idinfo = google_id_token.verify_oauth2_token(
            credential, google_requests.Request(), GOOGLE_CLIENT_ID
        )

        google_email = idinfo.get('email', '').lower()
        google_name = idinfo.get('name', 'Player')

        if not google_email:
            return jsonify({'error': 'Could not retrieve email from Google.'}), 400

        user = User.query.filter_by(email=google_email).first()
        if not user:
            user = User(
                username=sanitize(google_name, 20) or 'Player',
                email=google_email,
                verified=True,
                google_user=True
            )
            db.session.add(user)
            db.session.commit()
        elif not user.google_user:
            user.google_user = True
            user.verified = True
            db.session.commit()

        return jsonify({'success': True, 'user': user.to_public()})
    except ValueError as e:
        return jsonify({'error': 'Invalid Google token.'}), 401
    except Exception as e:
        print(f'Google login error: {e}')
        return jsonify({'error': 'Google sign-in failed.'}), 500


@app.route('/api/forgot-password', methods=['POST'])
@limiter.limit("5/15 minutes")
def forgot_password():
    data = request.get_json()
    email = sanitize(data.get('email', ''), 100).lower()
    success_response = {'success': True, 'message': 'If an account exists, a reset code was sent.'}

    if not email or not is_valid_email(email):
        return jsonify(success_response)

    user = User.query.filter_by(email=email).first()
    if not user or user.google_user:
        return jsonify(success_response)

    code = generate_code()
    ResetCode.query.filter_by(email=email).delete()
    rc = ResetCode(
        email=email, code=code,
        expires_at=datetime.utcnow() + timedelta(minutes=10)
    )
    db.session.add(rc)
    db.session.commit()

    email_result = send_email(email, 'Chess Arena — Password Reset',
                              make_reset_email_html(user.username, code))

    if not email_result['sent']:
        success_response['devCode'] = code
        success_response['message'] = 'Reset code generated (email not configured — shown below)'

    return jsonify(success_response)


@app.route('/api/reset-password', methods=['POST'])
@limiter.limit("10/5 minutes")
def reset_password():
    data = request.get_json()
    email = sanitize(data.get('email', ''), 100).lower()
    code = sanitize(data.get('code', ''), 6)
    new_password = data.get('newPassword', '')

    rc = ResetCode.query.filter_by(email=email).first()
    if not rc:
        return jsonify({'error': 'No reset request found. Please request a new code.'}), 400

    if rc.attempts >= 5:
        db.session.delete(rc)
        db.session.commit()
        return jsonify({'error': 'Too many attempts. Please request a new code.'}), 400

    if datetime.utcnow() > rc.expires_at:
        db.session.delete(rc)
        db.session.commit()
        return jsonify({'error': 'Code expired. Please request a new one.'}), 400

    if rc.code != code:
        rc.attempts += 1
        db.session.commit()
        return jsonify({'error': f'Invalid code. {5 - rc.attempts} attempts remaining.'}), 400

    if not is_strong_password(new_password):
        return jsonify({'error': 'Password needs 6+ chars with uppercase, lowercase, and a number.'}), 400

    user = User.query.filter_by(email=email).first()
    if user:
        user.password_hash = hash_password(new_password)
        user.verified = True
    db.session.delete(rc)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Password reset successfully!'})


@app.route('/api/profile/<email>')
def get_profile(email):
    email = sanitize(email, 100).lower()
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'User not found.'}), 404
    return jsonify(user.to_public())


@app.route('/api/config')
def get_config():
    return jsonify({
        'googleClientId': GOOGLE_CLIENT_ID if GOOGLE_CLIENT_ID else None
    })


# ============ Game State (in-memory — games are ephemeral) ============
games = {}
timers = {}
player_rooms = {}

TIME_CONTROLS = {
    'bullet': 60 * 1000,
    'blitz': 3 * 60 * 1000,
    'rapid': 10 * 60 * 1000
}

def save_game_to_db(game, winner):
    """Save completed game to database and update player stats."""
    try:
        gh = GameHistory(
            white_player=game['players']['white']['name'],
            black_player=game['players']['black']['name'],
            winner=winner if winner != 'draw' else 'draw',
            time_control=game.get('timeControl', 'blitz'),
            moves_json=json.dumps(game.get('moveHistory', []))
        )
        db.session.add(gh)

        for color in ['white', 'black']:
            player_email = game['players'][color].get('email')
            if player_email:
                user = User.query.filter_by(email=player_email).first()
                if user:
                    user.games_played += 1
                    if winner == 'draw':
                        user.draws += 1
                    elif winner == color:
                        user.wins += 1
                    else:
                        user.losses += 1

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f'Error saving game: {e}')


def start_timer(room_code):
    game = games.get(room_code)
    if not game or game.get('timeControl') not in TIME_CONTROLS:
        return
    tc = TIME_CONTROLS[game['timeControl']]
    timers[room_code] = {
        'white': tc, 'black': tc,
        'lastTick': time.time() * 1000,
        'active': True
    }

def tick_timer(room_code):
    t = timers.get(room_code)
    game = games.get(room_code)
    if not t or not t['active'] or not game:
        return
    board = game.get('board')
    if not board:
        return
    turn = 'white' if board.turn == chess.WHITE else 'black'
    now = time.time() * 1000
    elapsed = now - t['lastTick']
    t[turn] -= elapsed
    t['lastTick'] = now

    if t[turn] <= 0:
        t[turn] = 0
        t['active'] = False
        winner = 'black' if turn == 'white' else 'white'
        game['status'] = 'finished'
        save_game_to_db(game, winner)
        socketio.emit('game-over', {
            'reason': 'timeout', 'winner': winner,
            'winnerName': game['players'][winner]['name']
        }, room=room_code)

def get_timer_data(room_code):
    t = timers.get(room_code)
    if not t:
        return None
    return {'white': max(0, t['white']), 'black': max(0, t['black'])}


# ============ Socket.IO Events ============
@socketio.on('connect')
def on_connect():
    print(f'Player connected: {request.sid}')

@socketio.on('disconnect')
def on_disconnect():
    sid = request.sid
    room_code = player_rooms.get(sid)
    if room_code and room_code in games:
        game = games[room_code]
        if game['status'] == 'playing':
            color = None
            for c in ['white', 'black']:
                if game['players'].get(c, {}).get('sid') == sid:
                    color = c
                    break
            if color:
                winner = 'black' if color == 'white' else 'white'
                game['status'] = 'finished'
                if room_code in timers:
                    timers[room_code]['active'] = False
                save_game_to_db(game, winner)
                socketio.emit('game-over', {
                    'reason': 'disconnection', 'winner': winner,
                    'winnerName': game['players'][winner]['name']
                }, room=room_code)
        elif game['status'] == 'waiting':
            del games[room_code]
    player_rooms.pop(sid, None)
    print(f'Player disconnected: {sid}')


@socketio.on('create-game')
def on_create_game(data):
    room_code = generate_room_code()
    name = sanitize(data.get('playerName', 'Player'), 20) or 'Player'
    email = data.get('email')
    tc = data.get('timeControl', 'blitz')
    if tc not in TIME_CONTROLS:
        tc = 'blitz'

    games[room_code] = {
        'status': 'waiting',
        'players': {'white': {'name': name, 'email': email, 'sid': request.sid}},
        'board': None,
        'moveHistory': [],
        'timeControl': tc
    }
    join_room(room_code)
    player_rooms[request.sid] = room_code
    emit('game-created', {'roomCode': room_code, 'timeControl': tc})


@socketio.on('join-game')
def on_join_game(data):
    room_code = sanitize(data.get('roomCode', ''), 6).upper()
    name = sanitize(data.get('playerName', 'Player'), 20) or 'Player'
    email = data.get('email')

    if room_code not in games:
        emit('join-error', 'Room not found.')
        return
    game = games[room_code]
    if game['status'] != 'waiting':
        emit('join-error', 'Game already in progress.')
        return

    game['players']['black'] = {'name': name, 'email': email, 'sid': request.sid}
    game['status'] = 'playing'
    board = chess.Board()
    game['board'] = board

    join_room(room_code)
    player_rooms[request.sid] = room_code

    start_timer(room_code)

    game_data = {
        'roomCode': room_code,
        'white': game['players']['white']['name'],
        'black': game['players']['black']['name'],
        'fen': board.fen(),
        'timers': get_timer_data(room_code)
    }

    emit('game-joined', {**game_data, 'color': 'black'})
    emit('opponent-joined', {**game_data, 'color': 'white'},
         room=game['players']['white']['sid'])


@socketio.on('make-move')
def on_make_move(data):
    room_code = player_rooms.get(request.sid)
    if not room_code or room_code not in games:
        return
    game = games[room_code]
    if game['status'] != 'playing':
        return
    board = game['board']

    # Verify it's this player's turn
    player_color = None
    for c in ['white', 'black']:
        if game['players'].get(c, {}).get('sid') == request.sid:
            player_color = c
            break
    if not player_color:
        return
    expected_turn = 'white' if board.turn == chess.WHITE else 'black'
    if player_color != expected_turn:
        emit('move-error', "Not your turn.")
        return

    try:
        from_sq = data.get('from', '')
        to_sq = data.get('to', '')
        promotion = data.get('promotion')

        # Build move
        from_square = chess.parse_square(from_sq)
        to_square = chess.parse_square(to_sq)
        if promotion:
            promo_piece = {'q': chess.QUEEN, 'r': chess.ROOK, 'b': chess.BISHOP, 'n': chess.KNIGHT}.get(promotion)
            move = chess.Move(from_square, to_square, promotion=promo_piece)
        else:
            move = chess.Move(from_square, to_square)

        if move not in board.legal_moves:
            emit('move-error', 'Illegal move.')
            return

        # Detect special moves
        is_capture = board.is_capture(move)
        is_castle = board.is_castling(move)

        san = board.san(move)
        board.push(move)
        game['moveHistory'].append(san)

        # Tick timer
        tick_timer(room_code)

        is_check = board.is_check()
        is_checkmate = board.is_checkmate()
        is_stalemate = board.is_stalemate()
        is_draw = board.is_game_over() and not is_checkmate
        is_game_over = board.is_game_over()

        move_data = {
            'fen': board.fen(),
            'move': {'from': from_sq, 'to': to_sq, 'captured': is_capture,
                     'flags': ('k' if is_castle else '') + ('c' if is_capture else '')},
            'history': game['moveHistory'],
            'isCheck': is_check,
            'isCheckmate': is_checkmate,
            'isStalemate': is_stalemate,
            'isGameOver': is_game_over,
            'turn': 'w' if board.turn == chess.WHITE else 'b',
            'timers': get_timer_data(room_code)
        }

        socketio.emit('move-made', move_data, room=room_code)

        if is_game_over:
            game['status'] = 'finished'
            if room_code in timers:
                timers[room_code]['active'] = False
            if is_checkmate:
                winner = 'black' if board.turn == chess.WHITE else 'white'
            else:
                winner = 'draw'
            save_game_to_db(game, winner)

    except Exception as e:
        print(f'Move error: {e}')
        emit('move-error', 'Invalid move.')


@socketio.on('resign')
def on_resign():
    room_code = player_rooms.get(request.sid)
    if not room_code or room_code not in games:
        return
    game = games[room_code]
    if game['status'] != 'playing':
        return

    color = None
    for c in ['white', 'black']:
        if game['players'].get(c, {}).get('sid') == request.sid:
            color = c
            break
    if not color:
        return

    winner = 'black' if color == 'white' else 'white'
    game['status'] = 'finished'
    if room_code in timers:
        timers[room_code]['active'] = False
    save_game_to_db(game, winner)
    socketio.emit('game-over', {
        'reason': 'resignation', 'winner': winner,
        'winnerName': game['players'][winner]['name']
    }, room=room_code)


@socketio.on('offer-draw')
def on_offer_draw():
    room_code = player_rooms.get(request.sid)
    if not room_code or room_code not in games:
        return
    game = games[room_code]
    for c in ['white', 'black']:
        if game['players'].get(c, {}).get('sid') != request.sid:
            socketio.emit('draw-offered', room=game['players'][c]['sid'])
            break


@socketio.on('accept-draw')
def on_accept_draw():
    room_code = player_rooms.get(request.sid)
    if not room_code or room_code not in games:
        return
    game = games[room_code]
    game['status'] = 'finished'
    if room_code in timers:
        timers[room_code]['active'] = False
    save_game_to_db(game, 'draw')
    socketio.emit('game-over', {'reason': 'draw-agreement', 'winner': 'draw'}, room=room_code)


@socketio.on('decline-draw')
def on_decline_draw():
    room_code = player_rooms.get(request.sid)
    if not room_code:
        return
    socketio.emit('draw-declined', room=room_code)


@socketio.on('request-rematch')
def on_request_rematch():
    room_code = player_rooms.get(request.sid)
    if not room_code or room_code not in games:
        return
    game = games[room_code]

    if not game.get('rematchRequested'):
        game['rematchRequested'] = request.sid
        for c in ['white', 'black']:
            if game['players'].get(c, {}).get('sid') != request.sid:
                socketio.emit('rematch-requested', room=game['players'][c]['sid'])
                break
    else:
        if game['rematchRequested'] != request.sid:
            # Swap colors
            old_white = game['players']['white']
            old_black = game['players']['black']
            board = chess.Board()
            game['players'] = {'white': old_black, 'black': old_white}
            game['board'] = board
            game['moveHistory'] = []
            game['status'] = 'playing'
            game['rematchRequested'] = None

            start_timer(room_code)

            for c in ['white', 'black']:
                socketio.emit('rematch-start', {
                    'roomCode': room_code,
                    'white': game['players']['white']['name'],
                    'black': game['players']['black']['name'],
                    'fen': board.fen(),
                    'color': c,
                    'timers': get_timer_data(room_code)
                }, room=game['players'][c]['sid'])


@socketio.on('chat-message')
def on_chat(message):
    room_code = player_rooms.get(request.sid)
    if not room_code or room_code not in games:
        return
    game = games[room_code]
    msg = sanitize(message, 200)
    if not msg:
        return

    sender = 'Unknown'
    color = 'white'
    for c in ['white', 'black']:
        if game['players'].get(c, {}).get('sid') == request.sid:
            sender = game['players'][c]['name']
            color = c
            break

    socketio.emit('chat-message', {'sender': sender, 'color': color, 'message': msg}, room=room_code)


# ============ Timer Background Task ============
def timer_tick_loop():
    """Background thread that ticks all active timers."""
    while True:
        socketio.sleep(1)
        for room_code in list(timers.keys()):
            t = timers.get(room_code)
            game = games.get(room_code)
            if t and t['active'] and game and game['status'] == 'playing':
                tick_timer(room_code)
                socketio.emit('timer-update', get_timer_data(room_code), room=room_code)


# ============ Main ============
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print('📦 Database ready (SQLite)')

    socketio.start_background_task(timer_tick_loop)

    PORT = int(os.getenv('PORT', 3000))
    print(f'♔ Chess server running at http://localhost:{PORT}')
    socketio.run(app, host='0.0.0.0', port=PORT, debug=False)
