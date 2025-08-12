from flask import Flask, request, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import uuid

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'simple.db')

app = Flask(__name__, static_folder='static', static_url_path='/')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(50), default='individual')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    access_expires_at = db.Column(db.DateTime, nullable=True)
    revoked = db.Column(db.Boolean, default=False)
    api_key = db.Column(db.String(128), unique=True, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'access_expires_at': self.access_expires_at.isoformat() if self.access_expires_at else None,
            'revoked': bool(self.revoked),
            'created_at': self.created_at.isoformat()
        }

def init_db():
    if not os.path.exists(DB_PATH):
        db.create_all()
        # create default admin
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@example.test', role='admin')
            admin.set_password('admin123')
            admin.api_key = str(uuid.uuid4())
            db.session.add(admin)
            db.session.commit()
            print('Created default admin: admin/admin123')

@app.before_request
def load_user():
    auth = request.headers.get('Authorization', '')
    token = None
    if auth.startswith('Bearer '):
        token = auth.split(' ',1)[1]
    if token:
        user = User.query.filter_by(api_key=token).first()
        if user:
            g.current_user = user
        else:
            g.current_user = None
    else:
        g.current_user = None

def require_auth(func):
    from functools import wraps
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not getattr(g, 'current_user', None):
            return jsonify({'error':'unauthorized'}), 401
        # check revoked or expired
        u=g.current_user
        if u.revoked:
            return jsonify({'error':'revoked'}), 403
        if u.access_expires_at and u.access_expires_at < datetime.utcnow():
            return jsonify({'error':'expired'}), 403
        return func(*args, **kwargs)
    return wrapper

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username') or data.get('email')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error':'username and password required'}), 400
    user = User.query.filter((User.username==username)|(User.email==username)).first()
    if not user or not user.check_password(password):
        return jsonify({'error':'invalid credentials'}), 401
    # generate api key
    user.api_key = str(uuid.uuid4())
    db.session.commit()
    return jsonify({'token': user.api_key, 'user': user.to_dict()})

@app.route('/api/users', methods=['GET'])
@require_auth
def list_users():
    # only admin/admin2/business can view list (business only own workers)
    u=g.current_user
    role=u.role
    if role=='business':
        users = User.query.filter_by(role='worker').filter_by().all()
        # we don't have parent relation in this simple DB -> return all workers for business
    else:
        users = User.query.all()
    return jsonify([x.to_dict() for x in users])

@app.route('/api/users', methods=['POST'])
@require_auth
def create_user():
    data = request.get_json() or {}
    u=g.current_user
    role = data.get('role','individual')
    # permissions: admin can create all except main admin; admin2 same; business can only create workers
    if u.role not in ['admin','admin2','business']:
        return jsonify({'error':'forbidden'}), 403
    if u.role=='business' and role!='worker':
        return jsonify({'error':'business can only create workers'}), 403
    if role=='admin' and u.role!='admin':
        return jsonify({'error':'only main admin can create admin'}), 403
    username = data.get('username') or data.get('email').split('@')[0]
    email = data.get('email')
    password = data.get('password') or 'changeme123'
    if User.query.filter((User.username==username)|(User.email==email)).first():
        return jsonify({'error':'user exists'}), 400
    new = User(username=username, email=email, role=role)
    new.set_password(password)
    expires = data.get('access_expires_at')
    if expires:
        try:
            new.access_expires_at = datetime.fromisoformat(expires)
        except:
            pass
    db.session.add(new)
    db.session.commit()
    return jsonify(new.to_dict()), 201

@app.route('/api/users/<int:user_id>/approve', methods=['POST'])
@require_auth
def approve_user(user_id):
    u=g.current_user
    if u.role not in ['admin','admin2','business']:
        return jsonify({'error':'forbidden'}), 403
    target=User.query.get_or_404(user_id)
    # approval here could be a flag; for simplicity, approval removes revoked flag and clears expiry
    target.revoked=False
    target.access_expires_at=None
    db.session.commit()
    return jsonify(target.to_dict())

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@require_auth
def delete_user(user_id):
    u=g.current_user
    target=User.query.get_or_404(user_id)
    # prevent deleting main admin (username 'admin')
    if target.username=='admin':
        return jsonify({'error':'cannot delete main admin'}), 403
    # role rules
    if u.role=='admin' or (u.role=='admin2' and target.username!='admin') or (u.role=='business' and target.role=='worker'):
        db.session.delete(target)
        db.session.commit()
        return '',204
    return jsonify({'error':'forbidden'}), 403

@app.route('/api/users/<int:user_id>/restrict', methods=['POST'])
@require_auth
def restrict_user(user_id):
    u=g.current_user
    target=User.query.get_or_404(user_id)
    if u.role not in ['admin','admin2','business']:
        return jsonify({'error':'forbidden'}), 403
    if u.role=='business' and target.role!='worker':
        return jsonify({'error':'business can only restrict workers'}), 403
    data = request.get_json() or {}
    revoked = data.get('revoked', False)
    expires = data.get('access_expires_at')  # ISO string
    if revoked:
        target.revoked = True
    elif expires:
        try:
            target.access_expires_at = datetime.fromisoformat(expires)
        except:
            return jsonify({'error':'invalid date format'}), 400
    else:
        return jsonify({'error':'no action provided'}), 400
    db.session.commit()
    return jsonify(target.to_dict())

if __name__=='__main__':
    init_db()
    app.run(port=5000, host='0.0.0.0', debug=True)
