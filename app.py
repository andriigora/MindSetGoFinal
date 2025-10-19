from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from config import SETTINGS
from flask_migrate import Migrate
from sqlalchemy import func
from email.message import EmailMessage
import smtplib
import json
from datetime import datetime, timedelta, date
from zoneinfo import ZoneInfo
import re
import secrets
from functools import wraps
from sqlalchemy import event
from sqlalchemy.engine import Engine
import sqlite3
import os
from collections import defaultdict
import random


app = Flask(__name__, instance_relative_config=True)
app.config.update(SETTINGS)

app.config.setdefault("ENABLE_REMINDER_SCHEDULER", True)
app.config.setdefault("AUTO_ADD_DEFAULT_REMINDER", True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)

RECOMMENDED_HABITS = [
    {"name": "Drink water",             "frequency": "daily",  "goal": 8},
    {"name": "Read pages",              "frequency": "daily",  "goal": 10},
    {"name": "Walk (minutes)",          "frequency": "daily",  "goal": 20},
    {"name": "Stretch (minutes)",       "frequency": "daily",  "goal": 10},
    {"name": "Meditate (minutes)",      "frequency": "daily",  "goal": 5},
    {"name": "Journal (sentences)",     "frequency": "daily",  "goal": 3},
    {"name": "Learn (minutes)",         "frequency": "daily",  "goal": 15},
    {"name": "Practice instrument",     "frequency": "daily",  "goal": 15},
    {"name": "Cold shower (minutes)",   "frequency": "daily",  "goal": 1},
    {"name": "Pomodoros",               "frequency": "daily",  "goal": 3},
    {"name": "Gym sessions",            "frequency": "weekly", "goal": 3},
    {"name": "Run days",                "frequency": "weekly", "goal": 3},
    {"name": "Cook at home",            "frequency": "weekly", "goal": 4},
    {"name": "No sugar days",           "frequency": "weekly", "goal": 5},
    {"name": "Meet a friend",           "frequency": "weekly", "goal": 2},
    {"name": "Clean room",              "frequency": "weekly", "goal": 1},
]

@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.close()
class UserAchievement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), index=True, nullable=False)
    code = db.Column(db.String(40), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    icon = db.Column(db.String(16), default="🏅")
    unlocked_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('user_id', 'code', name='uq_user_ach_code'),)

class User(db.Model):
    __table_args__ = {'sqlite_autoincrement': True}
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    points = db.Column(db.Integer, nullable=False, default=0)
    email_verified = db.Column(db.Boolean, default=False)
    email_verification_code = db.Column(db.String(6), nullable=True)
    email_verification_sent_at = db.Column(db.DateTime, nullable=True)
    reset_code = db.Column(db.String(6), nullable=True)
    reset_sent_at = db.Column(db.DateTime, nullable=True)
    habits = db.relationship('Habit', backref='user',
                             cascade='all, delete-orphan', passive_deletes=True)
    achievements = db.relationship(
        'UserAchievement',
        backref='user',
        cascade='all, delete-orphan',
        passive_deletes=True,
    )
    def __repr__(self):
        return f"<User {self.username}>"

class Habit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    frequency = db.Column(db.String(50), nullable=False)   # 'daily' or 'weekly'
    goal = db.Column(db.Integer, nullable=False)
    status = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.Date, nullable=False, default=date.today)
    current_streak = db.Column(db.Integer, nullable=False, default=0)
    longest_streak = db.Column(db.Integer, nullable=False, default=0)
    reminders = db.relationship('HabitReminder', backref='habit', cascade='all, delete-orphan')
    progresses = db.relationship(
        'Progress',
        backref='habit',
        cascade='all, delete-orphan',
        passive_deletes=True,
    )

    def __repr__(self):
        return f"<Habit {self.name}>"

class Progress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    habit_id = db.Column(db.Integer, db.ForeignKey('habit.id', ondelete='CASCADE'), nullable=False)
    date = db.Column(db.Date, nullable=False, default=date.today)
    count = db.Column(db.Integer, nullable=False, default=0)
    __table_args__ = (db.UniqueConstraint('habit_id', 'date', name='unique_daily_progress'),)

    def __repr__(self):
        return f"<Progress Habit:{self.habit_id} on {self.date} = {self.count}>"


class HabitReminder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    habit_id = db.Column(
        db.Integer,
        db.ForeignKey('habit.id', ondelete='CASCADE'),
        nullable=False,
        index=True
    )
    hour = db.Column(db.Integer, nullable=False)
    minute = db.Column(db.Integer, nullable=False)
    last_sent_date = db.Column(db.Date, nullable=True)

    __table_args__ = (
        db.UniqueConstraint('habit_id', 'hour', 'minute', name='uq_habit_reminder_time'),
    )

def now_local():
    tz = ZoneInfo(app.config.get('TIMEZONE', 'Europe/Zurich'))
    return datetime.now(tz)

def send_email(to: str, subject: str, body_text=None, body_html=None, body=None):
    if not app.config.get('EMAIL_ENABLED', False):
        return
    if not to:
        return

    if body_text is None and body is not None:
        body_text = body
    if body_text is None and body_html is None:
        body_text = "(HTML email)"

    msg = EmailMessage()
    msg['From'] = app.config.get('MAIL_DEFAULT_SENDER', 'MindSetGo <no-reply@example>')
    msg['To'] = to
    msg['Subject'] = subject
    msg.set_content(body_text or "")
    if body_html:
        msg.add_alternative(body_html, subtype='html')
    try:
        with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as smtp:
            if app.config.get('MAIL_USE_TLS', False):
                smtp.starttls()
            if app.config.get('MAIL_USERNAME'):
                smtp.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
            smtp.send_message(msg)
    except Exception as e:
        print(f"[email] failed: {e}")

def build_reminders(user, habits):
    reminders = []
    hour_threshold = int(session.get('reminder_hour', app.config.get('REMINDER_HOUR_LOCAL', 18)))
    if not session.get('reminder_enabled', True):
        return reminders

    now = now_local()
    if now.hour < hour_threshold:
        return reminders

    today = now.date()
    week_start = today - timedelta(days=today.weekday())
    days_left = 6 - today.weekday()

    for h in habits:
        if h.frequency == 'daily':
            p = Progress.query.filter_by(habit_id=h.id, date=today).first()
            done = (p.count if p else 0)
            if done < h.goal:
                missing = h.goal - done
                reminders.append({'category': 'warning',
                                  'text': f"⏰ Daily: «{h.name}» needs {missing} more today ({done}/{h.goal})."})
        else:
            total = db.session.query(func.coalesce(func.sum(Progress.count), 0)).filter(
                Progress.habit_id == h.id,
                Progress.date >= week_start,
                Progress.date <= today
            ).scalar() or 0
            if total < h.goal and days_left <= 2:
                missing = h.goal - total
                day_word = "day" if days_left == 1 else "days"
                reminders.append({'category': 'info',
                                  'text': f"📆 Weekly: «{h.name}» needs {missing} more this week ({total}/{h.goal}). {days_left} {day_word} left."})
    return reminders

def make_code(n=6):
    return ''.join(secrets.choice('0123456789') for _ in range(n))

def code_is_fresh(sent_at):
    if not sent_at:
        return False
    ttl = int(app.config.get('CODE_TTL_MINUTES', 15))
    return (datetime.utcnow() - sent_at) <= timedelta(minutes=ttl)

def current_user_or_redirect():
    uid = session.get('user_id')
    if not uid:
        flash('Please log in.', 'warning')
        return None
    return User.query.get(uid)

def login_required_view(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

def verified_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        uid = session.get('user_id')
        if not uid:
            flash('Please log in.', 'warning')
            return redirect(url_for('login'))
        user = User.query.get(uid)
        if not user.email_verified:
            if not code_is_fresh(user.email_verification_sent_at):
                user.email_verification_code = make_code()
                user.email_verification_sent_at = datetime.utcnow()
                db.session.commit()
                send_email(
                    to=user.email,
                    subject="[MindSetGo] Verify your email",
                    body=f"Your verification code is: {user.email_verification_code}\nThis code expires in {app.config.get('CODE_TTL_MINUTES', 15)} minutes."
                )
            flash("Please verify your email to continue. We sent a code.", "warning")
            return redirect(url_for('verify_email'))
        return f(*args, **kwargs)
    return wrapper
def achievements_catalog():
    return [
        {"code":"FIRST_HABIT","name":"First Habit","description":"Created your first habit.","icon":"🌱"},
        {"code":"FIRST_GOAL","name":"First Goal","description":"Completed your first goal.","icon":"🎯"},
        {"code":"P100","name":"100 Points","description":"Total points reached 100.","icon":"💯","kind":"points","threshold":100},
        {"code":"P250","name":"250 Points","description":"Total points reached 250.","icon":"🏅","kind":"points","threshold":250},
        {"code":"P500","name":"500 Points","description":"Total points reached 500.","icon":"🥉","kind":"points","threshold":500},
        {"code":"P1000","name":"1,000 Points","description":"Total points reached 1,000.","icon":"🥈","kind":"points","threshold":1000},
        {"code":"P2500","name":"2,500 Points","description":"Total points reached 2,500.","icon":"🥇","kind":"points","threshold":2500},
        {"code":"P5000","name":"5,000 Points","description":"Total points reached 5,000.","icon":"🏆","kind":"points","threshold":5000},
        {"code":"D3","name":"Daily x3","description":"Daily streak reached 3.","icon":"🔥","kind":"streak","frequency":"daily","threshold":3},
        {"code":"D7","name":"Daily x7","description":"Daily streak reached 7.","icon":"🔥","kind":"streak","frequency":"daily","threshold":7},
        {"code":"D14","name":"Daily x14","description":"Daily streak reached 14.","icon":"🔥","kind":"streak","frequency":"daily","threshold":14},
        {"code":"D30","name":"Daily x30","description":"Daily streak reached 30.","icon":"🔥","kind":"streak","frequency":"daily","threshold":30},
        {"code":"W2","name":"Weekly x2","description":"Weekly streak reached 2.","icon":"📆","kind":"streak","frequency":"weekly","threshold":2},
        {"code":"W4","name":"Weekly x4","description":"Weekly streak reached 4.","icon":"📆","kind":"streak","frequency":"weekly","threshold":4},
        {"code":"W8","name":"Weekly x8","description":"Weekly streak reached 8.","icon":"📆","kind":"streak","frequency":"weekly","threshold":8},
        {"code":"W12","name":"Weekly x12","description":"Weekly streak reached 12.","icon":"📆","kind":"streak","frequency":"weekly","threshold":12},
    ]

def has_achievement(user, code: str) -> bool:
    return UserAchievement.query.filter_by(user_id=user.id, code=code).first() is not None

def award_achievement(user, code: str) -> bool:
    cat = next((c for c in achievements_catalog() if c["code"] == code), None)
    if not cat or has_achievement(user, code):
        return False
    rec = UserAchievement(user_id=user.id, code=code, name=cat["name"],
                          description=cat["description"], icon=cat.get("icon", "🏅"))
    db.session.add(rec)
    db.session.commit()
    flash(f'{rec.icon} Achievement unlocked: {rec.name} - {rec.description}', 'success')
    return True

def check_award_points(user):
    for thr, code in [(100,'P100'),(250,'P250'),(500,'P500'),(1000,'P1000'),(2500,'P2500'),(5000,'P5000')]:
        if user.points >= thr:
            award_achievement(user, code)

def check_award_streak(user, habit):
    mapping = ([(3,'D3'),(7,'D7'),(14,'D14'),(30,'D30')] if habit.frequency=='daily'
               else [(2,'W2'),(4,'W4'),(8,'W8'),(12,'W12')])
    for thr, code in mapping:
        if habit.current_streak >= thr:
            award_achievement(user, code)

@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("habits"))
    return redirect(url_for("login"))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = (request.form['username'] or '').strip()
        email = (request.form['email'] or '').strip().lower()
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('index.html', form_type='register')

        policy = [
            (r'.{8,}', 'at least 8 characters'),
            (r'[A-Z]', 'an uppercase letter'),
            (r'[a-z]', 'a lowercase letter'),
            (r'\d', 'a digit'),
            (r'[\W_]', 'a special character')
        ]
        missing = [msg for regex, msg in policy if not re.search(regex, password)]
        if missing:
            piece = ', '.join(missing[:-1]) + (' and ' + missing[-1] if len(missing) > 1 else missing[0])
            flash('Password must contain ' + piece + '.', 'danger')
            return render_template('index.html', form_type='register')

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
        except Exception:
            db.session.rollback()
            flash('Error: Username or email may already exist.', 'danger')
            return render_template('index.html', form_type='register')

        # send verify code AFTER user is stored
        new_user.email_verified = False
        new_user.email_verification_code = make_code()
        new_user.email_verification_sent_at = datetime.utcnow()
        db.session.commit()

        send_email(
            to=new_user.email,
            subject="[MindSetGo] Verify your email",
            body=f"Your verification code is: {new_user.email_verification_code}\nThis code expires in {app.config.get('CODE_TTL_MINUTES', 15)} minutes."
        )

        session['user_id'] = new_user.id
        flash("We sent a 6-digit code to your email. Please verify.", "info")
        return redirect(url_for('verify_email'))

    return render_template('index.html', form_type='register')

@app.route('/verify-email', methods=['GET', 'POST'])
@login_required_view
def verify_email():
    user = current_user_or_redirect()
    if not user:
        return redirect(url_for('login'))
    if user.email_verified:
        return redirect(url_for('habits'))

    if request.method == 'POST':
        code = (request.form.get('code') or '').strip()
        if not code:
            flash("Enter the code.", "error")
        elif not code_is_fresh(user.email_verification_sent_at):
            flash("Code expired. Click resend.", "error")
        elif code != (user.email_verification_code or ''):
            flash("Incorrect code.", "error")
        else:
            user.email_verified = True
            user.email_verification_code = None
            user.email_verification_sent_at = None
            db.session.commit()
            flash("Email verified. Welcome!", "success")
            return redirect(url_for('habits'))

    return render_template('verify_email.html')

@app.post('/verify-email/resend')
@login_required_view
def resend_verification():
    user = current_user_or_redirect()
    if not user:
        return redirect(url_for('login'))
    if user.email_verified:
        return redirect(url_for('habits'))

    user.email_verification_code = make_code()
    user.email_verification_sent_at = datetime.utcnow()
    db.session.commit()
    send_email(
        to=user.email,
        subject="[MindSetGo] Verify your email",
        body=f"Your verification code is: {user.email_verification_code}\nThis code expires in {app.config.get('CODE_TTL_MINUTES',15)} minutes."
    )
    flash("New code sent.", "success")
    return redirect(url_for('verify_email'))

@app.route('/change_username', methods=['POST'])
@login_required_view
def change_username():
    user = current_user_or_redirect()
    new_username = (request.form['new_username'] or '').strip()

    if User.query.filter_by(username=new_username).first():
        flash('Username already in use. Try another.', 'warning')
    else:
        user.username = new_username
        try:
            db.session.commit()
            flash('Username updated successfully.', 'success')
        except Exception:
            db.session.rollback()
            flash('An error occurred while updating username.', 'danger')

    return redirect(url_for('dashboard'))

@app.route('/change_password', methods=['POST'])
@login_required_view
def change_password():
    user = current_user_or_redirect()
    current_password = request.form['current_password']
    new_password = request.form['new_password']

    if bcrypt.check_password_hash(user.password, current_password):
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.password = hashed_password
        try:
            db.session.commit()
            flash('Password updated successfully.', 'success')
        except Exception:
            db.session.rollback()
            flash('An error occurred while updating password.', 'danger')
    else:
        flash('Current password is incorrect.', 'danger')

    return redirect(url_for('dashboard'))

@app.route('/delete_account', methods=['POST'])
@login_required_view
def delete_account():
    user = current_user_or_redirect()
    try:
        db.session.delete(user)
        db.session.commit()
        session.pop('user_id', None)
        flash('Your account has been deleted successfully.', 'success')
        return redirect(url_for('register'))
    except Exception:
        db.session.rollback()
        flash('An error occurred during account deletion.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = (request.form['email'] or '').strip().lower()
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session.permanent = True

            # Enforce verification
            if not user.email_verified:
                if not code_is_fresh(user.email_verification_sent_at):
                    user.email_verification_code = make_code()
                    user.email_verification_sent_at = datetime.utcnow()
                    db.session.commit()
                    send_email(
                        to=user.email,
                        subject="[MindSetGo] Verify your email",
                        body=f"Your verification code is: {user.email_verification_code}\nThis code expires in {app.config.get('CODE_TTL_MINUTES', 15)} minutes."
                    )
                flash('Please verify your email to continue. We sent you a code.', 'warning')
                return redirect(url_for('verify_email'))

            flash('Logged in successfully!', 'success')
            return redirect(url_for('habits'))
        else:
            flash('Login unsuccessful. Please check your credentials.', 'danger')

    return render_template('index.html', form_type='login')

@app.route('/dashboard')
@login_required_view
def dashboard():
    user = current_user_or_redirect()
    return render_template('index.html', form_type='dashboard', user=user)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.post('/settings/notifications', endpoint='save_notification_settings')
@login_required_view
def save_notification_settings():
    enabled = request.form.get('reminder_enabled') in ('on', 'true', '1', 'yes')
    hour_raw = (request.form.get('reminder_hour') or '').strip()
    try:
        hour = int(hour_raw)
        if not (0 <= hour <= 23):
            raise ValueError()
    except Exception:
        hour = int(app.config.get('REMINDER_HOUR_LOCAL', 18))
        flash("Invalid hour. Using default.", "warning")

    session['reminder_enabled'] = enabled
    session['reminder_hour'] = hour
    flash("Reminder settings saved.", "success")
    return redirect(url_for('dashboard'))

@app.route('/habits', methods=['GET', 'POST'])
@login_required_view
def habits():
    user = current_user_or_redirect()
    hero_quote = random.choice(QUOTES)
    if request.method == 'POST':
        had_any_before = Habit.query.filter_by(user_id=user.id).count() > 0

        name = request.form['name']
        frequency = request.form['frequency']
        goal = int(request.form['goal'])

        new_habit = Habit(user_id=user.id, name=name, frequency=frequency, goal=goal)
        db.session.add(new_habit)
        db.session.commit()

        if app.config.get("AUTO_ADD_DEFAULT_REMINDER", True):
            try:
                default_hour = int(app.config.get('REMINDER_HOUR_LOCAL', 18))
                db.session.add(HabitReminder(habit_id=new_habit.id, hour=default_hour, minute=0))
                db.session.commit()
                flash(f"Default reminder at {default_hour:02d}:00 added.", "info")
            except Exception as e:
                db.session.rollback()
                app.logger.warning("Auto reminder not added: %s", e)

        if not had_any_before:
            award_achievement(user, "FIRST_HABIT")

        flash(f"Habit «{name}» created!", 'success')
        return redirect(url_for('habits'))

    habits = Habit.query.filter_by(user_id=user.id).all()
    today = now_local().date()

    for h in habits:
        if h.frequency == 'daily':
            yesterday = today - timedelta(days=1)
            prev = Progress.query.filter_by(habit_id=h.id, date=yesterday).first()
            today_p = Progress.query.filter_by(habit_id=h.id, date=today).first()
            if (not prev or prev.count < h.goal) and (not today_p or today_p.count < h.goal):
                h.current_streak = 0
        else:
            week_start = today - timedelta(days=today.weekday())
            prev_start = week_start - timedelta(days=7)
            prev_end = week_start - timedelta(days=1)

            total_prev = db.session.query(func.coalesce(func.sum(Progress.count), 0)).filter(
                Progress.habit_id == h.id,
                Progress.date >= prev_start,
                Progress.date <= prev_end
            ).scalar() or 0

            total_curr = db.session.query(func.coalesce(func.sum(Progress.count), 0)).filter(
                Progress.habit_id == h.id,
                Progress.date >= week_start,
                Progress.date <= today
            ).scalar() or 0

            if total_prev < h.goal and total_curr < h.goal:
                h.current_streak = 0

    db.session.commit()

    p_today = Progress.query.filter_by(date=today).all()
    done_today = {p.habit_id for p in p_today}
    progress_today = {p.habit_id: p.count for p in p_today}

    week_start = today - timedelta(days=today.weekday())
    weekly_progress = {}
    for h in habits:
        if h.frequency == 'weekly':
            total = db.session.query(func.coalesce(func.sum(Progress.count), 0)).filter(
                Progress.habit_id == h.id,
                Progress.date >= week_start,
                Progress.date <= today
            ).scalar()
            weekly_progress[h.id] = total or 0
        else:
            weekly_progress[h.id] = progress_today.get(h.id, 0)

    reminders = build_reminders(user, habits)
    today = now_local().date()

    def week_start(d):
        return d - timedelta(days=d.weekday())

    week0 = week_start(today) - timedelta(weeks=7)
    fetch_start = week0
    habit_ids = [h.id for h in habits] or [-1]

    rows = (
        db.session.query(
            Progress.habit_id,
            Progress.date,
            func.coalesce(func.sum(Progress.count), 0)
        )
        .filter(
            Progress.habit_id.in_(habit_ids),
            Progress.date >= fetch_start,
            Progress.date <= today
        )
        .group_by(Progress.habit_id, Progress.date)
        .all()
    )

    by_habit = defaultdict(dict)
    for hid, d, s in rows:
        by_habit[hid][d] = int(s or 0)
    history_data = {}
    last7_start = today - timedelta(days=6)
    last7_days = [last7_start + timedelta(days=i) for i in range(7)]
    weeks8 = [week0 + timedelta(days=7 * i) for i in range(8)]

    for h in habits:
        if h.frequency == 'weekly':
            bins = [0] * 8
            for d, s in by_habit.get(h.id, {}).items():
                idx = (week_start(d) - week0).days // 7
                if 0 <= idx < 8:
                    bins[idx] += s
            labels = [w.strftime("%b %d") for w in weeks8]
            history_data[h.id] = {"values": bins, "labels": labels, "scope": "weeks"}
        else:
            vals = [by_habit.get(h.id, {}).get(d, 0) for d in last7_days]
            labels = [d.strftime("%a") for d in last7_days]  # Mon, Tue, ...
            history_data[h.id] = {"values": vals, "labels": labels, "scope": "days"}
    TOP_N = 3

    lb_rows = (
        db.session.query(User.id, User.username, User.points)
        .order_by(User.points.desc(), User.username.asc())
        .limit(TOP_N)
        .all()
    )
    leaderboard = [dict(id=r.id, username=r.username, points=r.points) for r in lb_rows]
    in_top = any(r['id'] == user.id for r in leaderboard)
    more_count = (
                     db.session.query(func.count(User.id))
                     .filter(User.points > user.points)
                     .scalar()
                 ) or 0
    my_rank = more_count + 1
    recs = None
    if len(habits) == 0:
        recs = random.sample(RECOMMENDED_HABITS, k=min(8, len(RECOMMENDED_HABITS)))
    return render_template(
        'habits.html',
        user=user,
        habits=habits,
        done_today=done_today,
        progress_today=progress_today,
        weekly_progress=weekly_progress,
        week_start=week_start,
        reminders=reminders,
        leaderboard=leaderboard,
        my_rank=my_rank,
        in_top=in_top,
        history_data=history_data,
        hero_quote=hero_quote,
        recommended=recs
    )

@app.route('/habits/<int:habit_id>/edit', methods=['POST'])
@login_required_view
def edit_habit(habit_id):
    habit = Habit.query.get_or_404(habit_id)
    if habit.user_id != session.get('user_id'):
        flash('Not authorized.', 'danger')
        return redirect(url_for('habits'))
    habit.name = request.form['name']
    habit.frequency = request.form['frequency']
    habit.goal = int(request.form['goal'])
    db.session.commit()
    flash('Habit updated.', 'success')
    return redirect(url_for('habits'))

@app.route('/habits/<int:habit_id>/delete', methods=['POST'])
@login_required_view
def delete_habit(habit_id):
    habit = Habit.query.get_or_404(habit_id)
    if habit.user_id != session.get('user_id'):
        flash('Not authorized.', 'danger')
        return redirect(url_for('habits'))
    db.session.delete(habit)
    db.session.commit()
    flash('Habit deleted.', 'info')
    return redirect(url_for('habits'))

@app.route('/habits/<int:habit_id>/complete', methods=['POST'])
@login_required_view
def complete_habit(habit_id):
    user = current_user_or_redirect()
    habit = Habit.query.get_or_404(habit_id)
    if habit.user_id != session.get('user_id'):
        flash('Not authorized.', 'danger')
        return redirect(url_for('habits'))

    today = now_local().date()
    try:
        count = int(request.form.get('count', 0))
    except ValueError:
        flash('Write number.', 'warning')
        return redirect(url_for('habits'))

    today_progress = Progress.query.filter_by(habit_id=habit_id, date=today).first()
    old_count = today_progress.count if today_progress else 0

    if habit.frequency == 'daily':
        crossed = (old_count < habit.goal and count >= habit.goal)
        if crossed:
            pts = 1 * (10 + habit.current_streak)
            user.points += pts
            yesterday = today - timedelta(days=1)
            prev = Progress.query.filter_by(habit_id=habit_id, date=yesterday).first()
            habit.current_streak = (habit.current_streak + 1) if (prev and prev.count >= habit.goal) else 1
            habit.longest_streak = max(habit.longest_streak, habit.current_streak)
            award_achievement(user, "FIRST_GOAL")
            check_award_points(user)
            check_award_streak(user, habit)
        else:
            if count < habit.goal:
                habit.current_streak = 0

        if not today_progress:
            db.session.add(Progress(habit_id=habit_id, date=today, count=count))
        else:
            today_progress.count = count

    else:
        week_start = today - timedelta(days=today.weekday())
        week_end = week_start + timedelta(days=6)
        total_before = db.session.query(func.coalesce(func.sum(Progress.count), 0)).filter(
            Progress.habit_id == habit_id,
            Progress.date >= week_start,
            Progress.date <= today
        ).scalar() or 0

        total_after = total_before - old_count + count
        crossed = (total_before < habit.goal and total_after >= habit.goal)
        if crossed:
            pts = 1 * (10 + habit.current_streak) * 7
            user.points += pts
            prev_start = week_start - timedelta(days=7)
            prev_end = week_start - timedelta(days=1)
            total_prev = db.session.query(func.coalesce(func.sum(Progress.count), 0)).filter(
                Progress.habit_id == habit_id,
                Progress.date >= prev_start,
                Progress.date <= prev_end
            ).scalar() or 0
            habit.current_streak = (habit.current_streak + 1) if total_prev >= habit.goal else 1
            habit.longest_streak = max(habit.longest_streak, habit.current_streak)
            award_achievement(user, "FIRST_GOAL")
            check_award_points(user)
            check_award_streak(user, habit)
        else:
            if total_after < habit.goal:
                habit.current_streak = 0

        if not today_progress:
            db.session.add(Progress(habit_id=habit_id, date=today, count=count))
        else:
            today_progress.count = count

    db.session.commit()
    flash(f"Save: «{habit.name}» – {count} from {habit.goal}", 'success')
    return redirect(url_for('habits'))

@app.route('/habits/<int:habit_id>/progress_data')
@login_required_view
def progress_data(habit_id):
    habit = Habit.query.filter_by(id=habit_id, user_id=session['user_id']).first_or_404()
    today = now_local().date()

    if habit.frequency == 'weekly':
        curr_start = today - timedelta(days=today.weekday())
        labels, data = [], []
        for i in range(11, -1, -1):
            ws = curr_start - timedelta(weeks=i)
            we = ws + timedelta(days=6)
            total = db.session.query(func.coalesce(func.sum(Progress.count), 0)).filter(
                Progress.habit_id == habit.id,
                Progress.date >= ws,
                Progress.date <= we
            ).scalar() or 0
            labels.append(ws.isoformat())
            data.append(total)
        return jsonify({'labels': labels, 'data': data})

    start = today - timedelta(days=29)
    entries = Progress.query.filter(
        Progress.habit_id == habit.id,
        Progress.date >= start,
        Progress.date <= today
    ).order_by(Progress.date).all()

    data_map = {e.date.isoformat(): e.count for e in entries}
    labels = [(start + timedelta(days=i)).isoformat() for i in range(30)]
    data = [data_map.get(d, 0) for d in labels]
    return jsonify({'labels': labels, 'data': data})

@app.route('/forgot-password', methods=['GET', 'POST'], endpoint='forgot_password')
def forgot_password():
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        user = User.query.filter_by(email=email).first()
        if user:
            user.reset_code = make_code()
            user.reset_sent_at = datetime.utcnow()
            db.session.commit()
            send_email(
                to=user.email,
                subject="[MindSetGo] Password reset code",
                body=f"Your reset code is: {user.reset_code}\nThis code expires in {app.config.get('CODE_TTL_MINUTES',15)} minutes."
            )
        flash("If the email is registered, a reset code has been sent.", "info")
        return redirect(url_for('reset_password'))
    return render_template('forgot_password.html')

@app.route('/reset-password', methods=['GET', 'POST'], endpoint='reset_password')
def reset_password():
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        code = (request.form.get('code') or '').strip()
        pw1 = request.form.get('password') or ''
        pw2 = request.form.get('password2') or ''

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Invalid email or code.", "error")
        elif not code_is_fresh(user.reset_sent_at):
            flash("Code expired. Request a new code.", "error")
        elif code != (user.reset_code or ''):
            flash("Invalid email or code.", "error")
        elif len(pw1) < 8 or pw1 != pw2:
            flash("Passwords must match and be at least 8 characters.", "error")
        else:
            user.password = bcrypt.generate_password_hash(pw1).decode('utf-8')
            user.reset_code = None
            user.reset_sent_at = None
            db.session.commit()
            flash("Password updated. You can log in now.", "success")
            return redirect(url_for('login'))

    return render_template('reset_password.html')

@app.get('/achievements')
@login_required_view
def achievements_page():
    user = current_user_or_redirect()
    unlocked = {ua.code: ua for ua in user.achievements}
    catalog = achievements_catalog()
    items = []
    for a in catalog:
        ua = unlocked.get(a["code"])
        items.append({
            "code": a["code"],
            "name": a["name"],
            "description": a["description"],
            "icon": a.get("icon","🏅"),
            "unlocked": bool(ua),
            "unlocked_at": getattr(ua, "unlocked_at", None)
        })
    items.sort(key=lambda x: (not x["unlocked"], x["unlocked_at"] or datetime.min), reverse=False)
    return render_template('achievements.html', items=items)

@app.post('/habits/<int:habit_id>/reminders/add')
@login_required_view
def add_reminder(habit_id):
    habit = Habit.query.get_or_404(habit_id)
    if habit.user_id != session.get('user_id'):
        flash('Not authorized.', 'danger')
        return redirect(url_for('habits'))

    time_str = (request.form.get('time') or '').strip()  # "HH:MM"
    m = re.match(r'^([01]?\d|2[0-3]):([0-5]\d)$', time_str)
    if not m:
        flash('Please use time as HH:MM (24-hour).', 'warning')
        return redirect(url_for('habits'))

    hour = int(m.group(1))
    minute = int(m.group(2))

    if HabitReminder.query.filter_by(habit_id=habit.id, hour=hour, minute=minute).first():
        flash('That time already exists for this habit.', 'info')
        return redirect(url_for('habits'))

    db.session.add(HabitReminder(habit_id=habit.id, hour=hour, minute=minute))
    db.session.commit()
    flash('Reminder time added.', 'success')
    return redirect(url_for('habits'))

@app.post('/habits/<int:habit_id>/reminders/<int:rid>/delete')
@login_required_view
def delete_reminder(habit_id, rid):
    habit = Habit.query.get_or_404(habit_id)
    if habit.user_id != session.get('user_id'):
        flash('Not authorized.', 'danger')
        return redirect(url_for('habits'))

    r = HabitReminder.query.filter_by(id=rid, habit_id=habit.id).first_or_404()
    db.session.delete(r)
    db.session.commit()
    flash('Reminder removed.', 'info')
    return redirect(url_for('habits'))


QUOTES = [
    "Small steps every day add up to big results.",
    "You don’t have to be extreme, just consistent.",
    "The secret of getting ahead is getting started. - Mark Twain",
    "What you do every day matters more than what you do once in a while. - Gretchen Rubin",
    "Success is the sum of small efforts, repeated day in and day out. - Robert Collier",
    "We are what we repeatedly do. Excellence, then, is not an act, but a habit. - Will Durant",
    "Motivation gets you going, habit keeps you growing.",
    "Win the day. Then do it again tomorrow.",
]

def send_due_reminders():
    with app.app_context():
        if not app.config.get('EMAIL_ENABLED', False):
            return

        now = now_local()
        today = now.date()
        due = HabitReminder.query.filter_by(hour=now.hour, minute=now.minute).all()
        print(f"[reminder] {now.strftime('%Y-%m-%d %H:%M')} - due reminders: {len(due)}")

        for r in due:
            if r.last_sent_date == today:
                continue

            habit = r.habit
            user = User.query.get(habit.user_id)
            if not user or not user.email_verified:
                continue
            if habit.frequency == 'daily':
                p = Progress.query.filter_by(habit_id=habit.id, date=today).first()
                done = p.count if p else 0
                summary = f"Today's progress: {done}/{habit.goal}."
            else:
                week_start = today - timedelta(days=today.weekday())  # Monday
                total = (
                    db.session.query(func.coalesce(func.sum(Progress.count), 0))
                    .filter(
                        Progress.habit_id == habit.id,
                        Progress.date >= week_start,
                        Progress.date <= today,
                    )
                    .scalar()
                    or 0
                )
                days_left = max(0, 6 - today.weekday())
                day_word = 'day' if days_left == 1 else 'days'
                summary = f"This week: {total}/{habit.goal}. {days_left} {day_word} left."
            base = (app.config.get('APP_BASE_URL') or 'https://adriigo.pythonanywhere.com').rstrip('/')
            link = f"{base}/habits"

            quote = random.choice(QUOTES)
            body_text = (
                f"⏰ Reminder for «{habit.name}» at {r.hour:02d}:{r.minute:02d}\n"
                f"{summary}\n\n"
                f"{quote}\n\n"
                f"Open: {link}"
            )
            body_html = f"""\
<!doctype html>
<html>
  <body style="margin:0;padding:24px;background:#0b1220;color:#e8eefc;font-family:Inter,Segoe UI,Roboto,Arial,sans-serif;">
    <div style="max-width:560px;margin:auto;background:#121a2b;border-radius:14px;padding:24px;border:1px solid rgba(255,255,255,.08)">
      <h2 style="margin:0 0 8px 0;font-weight:700;letter-spacing:.2px;">⏰ {habit.name}</h2>
      <p style="margin:0 0 14px 0;opacity:.9;">Reminder at <strong>{r.hour:02d}:{r.minute:02d}</strong></p>
      <p style="margin:0 0 16px 0;opacity:.9;">{summary}</p>
      <blockquote style="margin:0 0 18px 0;padding:12px 14px;border-left:3px solid #7c9cff;background:rgba(124,156,255,.08);border-radius:10px;">
        <em style="opacity:.95;">“{quote}”</em>
      </blockquote>
      <p style="margin:0 0 16px 0;">
        <a href="{link}"
           style="display:inline-block;background:#7c9cff;color:#0b1220;text-decoration:none;font-weight:600;
                  padding:10px 16px;border-radius:10px;box-shadow:0 6px 20px rgba(124,156,255,.25)">
          Open MindSetGo
        </a>
      </p>
      <p style="margin:12px 0 0 0;font-size:12px;opacity:.6;">If the button doesn’t work, open: <a href="{link}" style="color:#9eb3ff">{link}</a></p>
    </div>
  </body>
</html>"""
            send_email(
                to=user.email,
                subject=f"[MindSetGo] Reminder - {habit.name}",
                body_text=body_text,
                body_html=body_html,
            )

            r.last_sent_date = today

        db.session.commit()

@app.get('/_debug/reminders')
def debug_reminders():
    now = now_local()
    items = []
    for r in HabitReminder.query_all():
        items.append({
            "id": r.id,
            "habit_id": r.habit_id,
            "time": f"{r.hour:02d}:{r.minute:02d}",
            "last_sent_date": r.last_sent_date.isoformat() if r.last_sent_date else None,
            "due_now": (r.hour == now.hour and r.minute == now.minute)
        })
    return jsonify({
        "scheduler_started": getattr(app, "_scheduler_started", False),
        "now_local": now.strftime("%Y-%m-%d %H:%M"),
        "due_now_count": sum(1 for x in items if x["due_now"]),
        "reminders": items
    })

@app.get('/cron/run')
def cron_run():
    token = request.args.get('token') or request.headers.get('X-CRON-TOKEN', '')
    expected = app.config.get('CRON_TOKEN')
    if not expected or token != expected:
        return ("Forbidden", 403)
    send_due_reminders()
    return jsonify({"status": "ok", "ran_at": now_local().strftime("%Y-%m-%d %H:%M")})

@app.get('/cron/test')
def cron_test():
    token = request.args.get('token') or request.headers.get('X-CRON-TOKEN', '')
    expected = app.config.get('CRON_TOKEN')
    if not expected or token != expected:
        return ("Forbidden", 403)
    now = now_local()
    due = HabitReminder.query.filter_by(hour=now.hour, minute=now.minute).all()
    items = [{
        "id": r.id,
        "habit_id": r.habit_id,
        "time": f"{r.hour:02d}:{r.minute:02d}",
        "last_sent_date": r.last_sent_date.isoformat() if r.last_sent_date else None
    } for r in due]
    return jsonify({
        "now_local": now.strftime("%Y-%m-%d %H:%M"),
        "due_now_count": len(items),
        "due_now": items
    })
if __name__ == '__main__':
    db.create_all()
    app.run()
