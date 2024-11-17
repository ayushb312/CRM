import os
from dotenv import load_dotenv
load_dotenv()
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key_here')
app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{os.getenv("DB_USER")}:{os.getenv("DB_PASSWORD")}@{os.getenv("DB_HOST")}/{os.getenv("DB_NAME")}'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(100))  # Full name for display

class Lead(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    mobile = db.Column(db.String(12), nullable=False)
    followup_date = db.Column(db.DateTime, nullable=False)
    remarks = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))

    user = db.relationship('User', foreign_keys=[user_id])
    creator = db.relationship('User', foreign_keys=[created_by])

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Initial setup function to create admin and users
def setup_users():
    # Create admin if not exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            password_hash=generate_password_hash('admin123'),
            is_admin=True,
            name='Administrator'
        )
        db.session.add(admin)

    # Create some example users
    users_data = [
        ('john', 'john123', 'John Smith'),
        ('sarah', 'sarah123', 'Sarah Johnson'),
        ('mike', 'mike123', 'Mike Wilson')
    ]

    for username, password, name in users_data:
        if not User.query.filter_by(username=username).first():
            user = User(
                username=username,
                password_hash=generate_password_hash(password),
                is_admin=False,
                name=name
            )
            db.session.add(user)

    db.session.commit()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        
        flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/add_lead', methods=['POST'])
@login_required
def add_lead():
    mobile = request.form.get('mobile')
    followup_date = request.form.get('followup_date')
    remarks = request.form.get('remarks')

    if not re.match(r'^\d{10}$|^\d{12}$', mobile):
        flash('Mobile number must be either 10 or 12 digits', 'error')
        return redirect(url_for('index'))

    followup_date = datetime.strptime(followup_date, '%Y-%m-%d')

    new_lead = Lead(
        user_id=current_user.id,  # Assign lead to current user
        mobile=mobile,
        followup_date=followup_date,
        remarks=remarks,
        created_by=current_user.id
    )
    
    db.session.add(new_lead)
    db.session.commit()
    
    flash('Lead added successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/followups')
@login_required
def followups():
    date = request.args.get('date', '')
    query = Lead.query

    # For non-admin users, show only their leads
    if not current_user.is_admin:
        query = query.filter(Lead.user_id == current_user.id)
    else:
        # For admin, allow filtering by user
        user_id = request.args.get('user_id')
        if user_id:
            query = query.filter(Lead.user_id == user_id)

    if date:
        selected_date = datetime.strptime(date, '%Y-%m-%d')
        query = query.filter(db.func.date(Lead.followup_date) == selected_date.date())
    
    followups = query.order_by(Lead.followup_date.desc()).all()
    users = User.query.filter_by(is_admin=False).all()  # For admin's user filter
    return render_template('followups.html', followups=followups, users=users)

# Create all database tables and setup initial users
with app.app_context():
    db.create_all()
    setup_users()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
