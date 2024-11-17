from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crm.db'
db = SQLAlchemy(app)

# Database Models
class Lead(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(100), nullable=False)
    mobile = db.Column(db.String(12), nullable=False)
    followup_date = db.Column(db.DateTime, nullable=False)
    remarks = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# List of team members
TEAM_MEMBERS = ['John', 'Sarah', 'Mike', 'Emma', 'David']

@app.route('/')
def index():
    return render_template('index.html', team_members=TEAM_MEMBERS)

@app.route('/add_lead', methods=['POST'])
def add_lead():
    user = request.form.get('user')
    mobile = request.form.get('mobile')
    followup_date = request.form.get('followup_date')
    remarks = request.form.get('remarks')

    # Validate mobile number
    if not re.match(r'^\d{10}$|^\d{12}$', mobile):
        flash('Mobile number must be either 10 or 12 digits', 'error')
        return redirect(url_for('index'))

    # Convert date string to datetime
    followup_date = datetime.strptime(followup_date, '%Y-%m-%d')

    new_lead = Lead(
        user=user,
        mobile=mobile,
        followup_date=followup_date,
        remarks=remarks
    )
    
    db.session.add(new_lead)
    db.session.commit()
    
    flash('Lead added successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/followups')
def followups():
    user = request.args.get('user', '')
    date = request.args.get('date', '')
    
    query = Lead.query
    
    if user:
        query = query.filter(Lead.user == user)
    if date:
        selected_date = datetime.strptime(date, '%Y-%m-%d')
        query = query.filter(db.func.date(Lead.followup_date) == selected_date.date())
    
    followups = query.all()
    return render_template('followups.html', followups=followups, team_members=TEAM_MEMBERS)

# Create all database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
