#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
实时攻防平台后端主程序
红黑色调主题，支持管理员和红队成员功能
"""
import os
import json
import random
import string
import time
import threading
from datetime import datetime, timedelta,timezone
from flask import Flask, request, jsonify, session, send_from_directory, render_template
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from flask_sqlalchemy import SQLAlchemy
# =============================================================================
# 配置信息 - 集中管理所有配置项
# =============================================================================

# 数据库配置
DB_CONFIG = {
    'URI': 'mysql+pymysql://root:root@localhost/Red_Game?charset=utf8mb4',
    'TRACK_MODIFICATIONS': False
}

# 应用配置
APP_CONFIG = {
    'SECRET_KEY': os.urandom(24).hex(),  # 随机生成SECRET_KEY
    'UPLOAD_FOLDER': 'static/uploads',
    'DEBUG': True
}

# 服务器配置
SERVER_CONFIG = {
    'HOST': '0.0.0.0',
    'PORT': 5000
}

# =============================================================================
# Flask应用初始化
# =============================================================================

app = Flask(__name__)

# 应用配置
app.config['SECRET_KEY'] = APP_CONFIG['SECRET_KEY']
app.config['SQLALCHEMY_DATABASE_URI'] = DB_CONFIG['URI']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = DB_CONFIG['TRACK_MODIFICATIONS']
app.config['UPLOAD_FOLDER'] = APP_CONFIG['UPLOAD_FOLDER']

# 初始化扩展
db = SQLAlchemy(app)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# 确保上传目录存在
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# 全局变量
online_users = {}

# =============================================================================
# 数据库模型定义
# =============================================================================
#定义获取本地时间函数
def get_local_time():
    """获取本地时间（北京时间）"""
    return datetime.now()


class User(db.Model):
    """用户模型"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100))
    role = db.Column(db.Enum('admin', 'red_team'), default='red_team')
    team_id = db.Column(db.Integer, db.ForeignKey('teams.id'), nullable=True)
    nickname = db.Column(db.String(100))
    avatar = db.Column(db.String(255))
    total_score = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    updated_at = db.Column(db.TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)

    team = db.relationship('Team', backref='members')
    created_at = db.Column(db.TIMESTAMP, default=get_local_time)
    updated_at = db.Column(db.TIMESTAMP, default=get_local_time, onupdate=get_local_time)

class Team(db.Model):
    """队伍模型"""
    __tablename__ = 'teams'
    id = db.Column(db.Integer, primary_key=True)
    team_name = db.Column(db.String(100), unique=True, nullable=False)
    team_icon = db.Column(db.String(255))
    total_score = db.Column(db.Integer, default=0)
    member_count = db.Column(db.Integer, default=0)
    max_members = db.Column(db.Integer, default=3)  # 新增字段
    created_at = db.Column(db.TIMESTAMP, default=get_local_time)
    updated_at = db.Column(db.TIMESTAMP, default=get_local_time, onupdate=get_local_time)

class Competition(db.Model):
    """比赛模型"""
    __tablename__ = 'competitions'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    background_story = db.Column(db.Text)
    theme_image = db.Column(db.String(255))
    start_time = db.Column(db.DateTime)
    end_time = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=False)
    is_ended = db.Column(db.Boolean, default=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.TIMESTAMP, default=get_local_time)
    updated_at = db.Column(db.TIMESTAMP, default=get_local_time, onupdate=get_local_time)

class Target(db.Model):
    """靶标模型"""
    __tablename__ = 'targets'

    id = db.Column(db.Integer, primary_key=True)
    competition_id = db.Column(db.Integer, db.ForeignKey('competitions.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    flag = db.Column(db.String(255), nullable=False)
    points = db.Column(db.Integer, default=100)
    description = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)

    competition = db.relationship('Competition', backref='targets')
    created_at = db.Column(db.TIMESTAMP, default=get_local_time)

class FlagSubmission(db.Model):
    """Flag提交模型"""
    __tablename__ = 'flag_submissions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    target_id = db.Column(db.Integer, db.ForeignKey('targets.id'), nullable=True)
    submitted_flag = db.Column(db.String(255), nullable=False)
    is_correct = db.Column(db.Boolean, default=False)
    points_earned = db.Column(db.Integer, default=0)
    submitted_at = db.Column(db.TIMESTAMP, default=get_local_time)

    user = db.relationship('User', backref='flag_submissions')
    target = db.relationship('Target', backref='submissions')


class SystemLog(db.Model):
    """系统日志模型"""
    __tablename__ = 'system_logs'

    id = db.Column(db.Integer, primary_key=True)
    log_type = db.Column(db.Enum('login', 'attack', 'system', 'error', 'success', 'warning', 'network', 'file_integrity', 'malware_detection'), default='system')
    source_ip = db.Column(db.String(45))
    target_ip = db.Column(db.String(45))
    message = db.Column(db.Text, nullable=False)
    severity = db.Column(db.Enum('low', 'medium', 'high', 'critical'), default='medium')
    team_id = db.Column(db.Integer, db.ForeignKey('teams.id'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    raw_data = db.Column(db.JSON)
    created_at = db.Column(db.TIMESTAMP, default=get_local_time)

    team = db.relationship('Team', backref='logs')
    user = db.relationship('User', backref='logs')

class AttackLog(db.Model):
    """攻击日志模型"""
    __tablename__ = 'attack_logs'

    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column(db.Integer, db.ForeignKey('teams.id'), nullable=False)
    source_ip = db.Column(db.String(45), nullable=False)
    target_ip = db.Column(db.String(45), nullable=False)
    attack_type = db.Column(db.String(50))
    traffic_volume = db.Column(db.Integer, default=0)
    timestamp = db.Column(db.TIMESTAMP, default=get_local_time)

    team = db.relationship('Team', backref='attack_logs')

# =============================================================================
# 工具函数
# =============================================================================



def generate_random_username(length=8):
    """生成随机用户名"""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def generate_random_password(length=12):
    """生成随机密码，只包含字母、数字和@."""
    characters = string.ascii_letters + string.digits + '@.'
    return ''.join(random.choices(characters, k=length))

def generate_random_flag():
    """生成随机Flag"""
    return f"FLAG{{{''.join(random.choices(string.ascii_uppercase + string.digits, k=16))}}}"

def check_duplicate_log(message, log_type, timestamp, source_ip):
    """检查是否为重复日志"""
    try:
        query = SystemLog.query.filter(
            SystemLog.message == message,
            SystemLog.log_type == log_type
        )

        if timestamp:
            try:
                log_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                time_window_start = log_time - timedelta(seconds=5)
                time_window_end = log_time + timedelta(seconds=5)
                query = query.filter(SystemLog.created_at.between(time_window_start, time_window_end))
            except:
                pass

        if source_ip:
            query = query.filter(SystemLog.source_ip == source_ip)

        duplicate = query.first()
        return duplicate is not None

    except Exception as e:
        print(f"检查重复日志失败: {e}")
        return False

def broadcast_score_update():
    """广播积分更新"""
    teams = Team.query.filter(Team.member_count > 0).order_by(Team.total_score.desc()).limit(10).all()

    socketio.emit('score_update', {
        'teams': [{
            'id': t.id,
            'team_name': t.team_name,
            'total_score': t.total_score
        } for t in teams]
    })

def broadcast_log_update(log_data):
    """广播日志更新"""
    socketio.emit('log_update', log_data)

# =============================================================================
# 页面路由
# =============================================================================

@app.route('/')
def index():
    """主页"""
    return render_template('index.html')

@app.route('/login')
def login_page():
    """登录页面"""
    return render_template('login.html')

@app.route('/admin')
def admin_page():
    """管理员页面"""
    return render_template('admin.html')

@app.route('/dashboard')
def dashboard_page():
    """用户面板页面"""
    return render_template('dashboard.html')

@app.route('/situation')
def situation_page():
    """实时态势页面"""
    return render_template('situation.html')

@app.route('/change_password')
def change_password_page():
    """修改密码页面"""
    return render_template('change_password.html')

# =============================================================================
# API路由 - 认证相关
# =============================================================================

@app.route('/api/login', methods=['POST'])
def login():
    """用户登录"""
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'success': False, 'message': '用户名和密码不能为空'}), 400

    user = User.query.filter_by(username=username, is_active=True).first()

    if not user or user.password != password:
        log_entry = SystemLog(
            log_type='login',
            message=f'登录失败: 用户名 {username}',
            severity='medium'
        )
        db.session.add(log_entry)
        db.session.commit()
        return jsonify({'success': False, 'message': '用户名或密码错误'}), 401

    log_entry = SystemLog(
        log_type='login',
        message=f'用户 {user.username} 登录成功',
        severity='low',
        user_id=user.id,
        team_id=user.team_id
    )
    db.session.add(log_entry)
    db.session.commit()

    session['user_id'] = user.id
    session['username'] = user.username
    session['role'] = user.role
    session['team_id'] = user.team_id
    session['nickname'] = user.nickname
    session['total_score'] = user.total_score
    # 添加这一行：设置头像到session
    if user.avatar:
        session['avatar'] = f"/static/{user.avatar}"

    return jsonify({
        'success': True,
        'message': '登录成功',
        'user': {
            'id': user.id,
            'username': user.username,
            'role': user.role,
            'team_id': user.team_id,
            'nickname': user.nickname,
            'total_score': user.total_score,
            'avatar': user.avatar  # 返回头像信息
        }
    })



@app.route('/api/logout', methods=['POST'])
def logout():
    """用户登出"""
    session.clear()
    return jsonify({'success': True, 'message': '登出成功'})

@app.route('/api/check_auth', methods=['GET'])
def check_auth():
    """检查用户认证状态"""
    if 'user_id' not in session:
        return jsonify({'authenticated': False}), 401

    user = User.query.get(session['user_id'])
    if not user or not user.is_active:
        session.clear()
        return jsonify({'authenticated': False}), 401

    if session.get('total_score') != user.total_score:
        session['total_score'] = user.total_score

    # 确保session中有头像信息
    if user.avatar and 'avatar' not in session:
        session['avatar'] = f"/static/{user.avatar}"

    return jsonify({
        'authenticated': True,
        'user': {
            'id': user.id,
            'username': user.username,
            'role': user.role,
            'team_id': user.team_id,
            'nickname': user.nickname,
            'total_score': user.total_score,
            'avatar': user.avatar  # 返回头像信息
        }
    })


# =============================================================================
# API路由 - 用户功能
# =============================================================================

@app.route('/api/user/profile', methods=['GET', 'PUT'])
def user_profile():
    """用户个人信息管理"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '请先登录'}), 401

    user = User.query.get(session['user_id'])

    if request.method == 'GET':
        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'nickname': user.nickname,
                'team_id': user.team_id,
                'total_score': user.total_score,
                'created_at': user.created_at.isoformat(),
                'avatar': user.avatar
            }
        })

    elif request.method == 'PUT':
        data = request.json

        if 'nickname' in data:
            user.nickname = data['nickname']

        if 'email' in data:
            user.email = data['email']

        db.session.commit()

        return jsonify({
            'success': True,
            'message': '个人信息更新成功'
        })

@app.route('/api/user/change_password', methods=['POST'])
def change_password():
    """修改用户密码"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '请先登录'}), 401

    data = request.json
    old_password = data.get('old_password')
    new_password = data.get('new_password')

    if not old_password or not new_password:
        return jsonify({'success': False, 'message': '原密码和新密码不能为空'}), 400

    if len(new_password) < 6:
        return jsonify({'success': False, 'message': '新密码至少需要6位'}), 400

    user = User.query.get(session['user_id'])

    if user.password != old_password:
        return jsonify({'success': False, 'message': '原密码错误'}), 400

    user.password = new_password
    db.session.commit()

    log_entry = SystemLog(
        log_type='system',
        message=f'用户 {user.username} 修改了密码',
        severity='low',
        user_id=user.id,
        team_id=user.team_id
    )
    db.session.add(log_entry)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': '密码修改成功'
    })

@app.route('/api/team/rename', methods=['PUT'])
def rename_team():
    """队伍重命名"""
    if 'user_id' not in session or session.get('role') != 'red_team':
        return jsonify({'success': False, 'message': '无权限访问'}), 403

    user = User.query.get(session['user_id'])
    if not user.team_id:
        return jsonify({'success': False, 'message': '您不属于任何队伍'}), 400

    data = request.json
    new_name = data.get('team_name')

    if not new_name or len(new_name) < 3:
        return jsonify({'success': False, 'message': '队伍名称至少需要3个字符'}), 400

    team = Team.query.get(user.team_id)
    existing_team = Team.query.filter_by(team_name=new_name).first()

    if existing_team and existing_team.id != team.id:
        return jsonify({'success': False, 'message': '队伍名称已存在'}), 400

    old_name = team.team_name
    team.team_name = new_name
    db.session.commit()

    log_entry = SystemLog(
        log_type='system',
        message=f'队伍 {old_name} 更名为 {new_name}',
        severity='low',
        user_id=user.id,
        team_id=team.id
    )
    db.session.add(log_entry)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': '队伍名称更新成功'
    })

# =============================================================================
# API路由 - 头像上传
# =============================================================================

@app.route('/api/user/avatar', methods=['POST'])
def upload_avatar():
    """上传用户头像"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '请先登录'}), 401

    if 'avatar' not in request.files:
        return jsonify({'success': False, 'message': '请选择头像文件'}), 400

    avatar_file = request.files['avatar']
    
    if avatar_file.filename == '':
        return jsonify({'success': False, 'message': '请选择有效的头像文件'}), 400

    # 检查文件类型
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
    if '.' not in avatar_file.filename or \
       avatar_file.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
        return jsonify({'success': False, 'message': '只支持PNG、JPG、JPEG、GIF格式的图片'}), 400

    # 检查文件大小（限制为2MB）
    avatar_file.seek(0, 2)  # 移动到文件末尾
    file_size = avatar_file.tell()
    avatar_file.seek(0)  # 重置文件指针
    if file_size > 2 * 1024 * 1024:
        return jsonify({'success': False, 'message': '头像文件大小不能超过2MB'}), 400

    try:
        user = User.query.get(session['user_id'])
        
        # 生成唯一文件名
        import uuid
        file_extension = avatar_file.filename.rsplit('.', 1)[1].lower()
        filename = f"avatar_{user.id}_{uuid.uuid4().hex[:8]}.{file_extension}"
        
        # 保存文件
        upload_folder = app.config['UPLOAD_FOLDER']
        avatar_path = os.path.join(upload_folder, 'avatars')
        os.makedirs(avatar_path, exist_ok=True)
        
        file_path = os.path.join(avatar_path, filename)
        avatar_file.save(file_path)
        
        # 更新用户头像路径（相对路径）
        user.avatar = f"uploads/avatars/{filename}"
        db.session.commit()

        # 更新session中的头像信息
        session['avatar'] = f"/static/uploads/avatars/{filename}"

        # 记录日志
        log_entry = SystemLog(
            log_type='system',
            message=f'用户 {user.username} 更新了头像',
            severity='low',
            user_id=user.id,
            team_id=user.team_id
        )
        db.session.add(log_entry)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': '头像上传成功',
            'avatar_url': f"/static/uploads/avatars/{filename}"
        })

    except Exception as e:
        print(f"头像上传失败: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': '头像上传失败'}), 500


# =============================================================================
# API路由 - 比赛和靶标功能
# =============================================================================

@app.route('/api/targets', methods=['GET'])
def get_targets():
    """获取靶标列表"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '请先登录'}), 401

    active_competition = Competition.query.filter_by(is_active=True, is_ended=False).first()
    if not active_competition:
        return jsonify({'success': True, 'targets': []})

    targets = Target.query.filter_by(
        competition_id=active_competition.id,
        is_active=True
    ).all()

    return jsonify({
        'success': True,
        'targets': [{
            'id': t.id,
            'name': t.name,
            'ip_address': t.ip_address,
            'points': t.points,
            'description': t.description
        } for t in targets]
    })

@app.route('/api/flag/submit', methods=['POST'])
def submit_flag():
    """提交Flag"""
    if 'user_id' not in session or session.get('role') != 'red_team':
        return jsonify({'success': False, 'message': '无权限访问'}), 403

    user = User.query.get(session['user_id'])

    active_competition = Competition.query.filter_by(is_active=True, is_ended=False).first()
    if not active_competition:
        return jsonify({'success': False, 'message': '当前没有活跃的比赛'}), 400

    data = request.json
    submitted_flag = data.get('flag', '').strip()  # 只做基本的去除前后空格处理

    if not submitted_flag:
        return jsonify({'success': False, 'message': 'Flag不能为空'}), 400

    # 直接查询与提交的flag完全一致的靶标
    target = Target.query.filter_by(
        flag=submitted_flag,  # 直接比较，不做大小写转换
        competition_id=active_competition.id,
        is_active=True
    ).first()

    if not target:
        any_target = Target.query.filter_by(flag=submitted_flag).first()
        target_id = any_target.id if any_target else None

        submission = FlagSubmission(
            user_id=user.id,
            target_id=target_id,
            submitted_flag=submitted_flag,
            is_correct=False,
            points_earned=0
        )
        db.session.add(submission)
        db.session.commit()

        log_entry = SystemLog(
            log_type='attack',
            message=f'用户 {user.username} 提交了错误的Flag: {submitted_flag}',
            severity='medium',
            user_id=user.id,
            team_id=user.team_id
        )
        db.session.add(log_entry)
        db.session.commit()

        return jsonify({'success': False, 'message': 'Flag错误'}), 400

    existing_submission = FlagSubmission.query.filter_by(
        user_id=user.id,
        target_id=target.id,
        is_correct=True
    ).first()

    if existing_submission:
        return jsonify({'success': False, 'message': '您已经提交过这个Flag了'}), 400

    submission = FlagSubmission(
        user_id=user.id,
        target_id=target.id,
        submitted_flag=submitted_flag,
        is_correct=True,
        points_earned=target.points
    )
    db.session.add(submission)

    user.total_score += target.points

    if user.team_id:
        team = Team.query.get(user.team_id)
        team.total_score += target.points

    score_log = SystemLog(
        log_type='success',
        message=f'用户 {user.username} 成功提交Flag，获得 {target.points} 分',
        severity='low',
        user_id=user.id,
        team_id=user.team_id
    )
    db.session.add(score_log)

    db.session.commit()

    session['total_score'] = user.total_score

    broadcast_score_update()

    return jsonify({
        'success': True,
        'message': f'Flag提交成功！获得 {target.points} 分',
        'points': target.points
    })


@app.route('/api/rankings', methods=['GET'])
def get_rankings():
    """获取排行榜"""
    teams = Team.query.filter(Team.member_count > 0).order_by(Team.total_score.desc()).all()

    users = User.query.filter_by(role='red_team', is_active=True).order_by(User.total_score.desc()).all()

    return jsonify({
        'success': True,
        'team_rankings': [{
            'id': t.id,
            'team_name': t.team_name,
            'team_icon': t.team_icon,
            'total_score': t.total_score,
            'member_count': t.member_count
        } for t in teams],
        'user_rankings': [{
            'id': u.id,
            'username': u.username,
            'nickname': u.nickname,
            'total_score': u.total_score,
            'team_name': u.team.team_name if u.team else None
        } for u in users]
    })

# =============================================================================
# API路由 - 管理员功能
# =============================================================================

@app.route('/api/admin/create_teams', methods=['POST'])
def create_teams():
    """批量创建队伍和账户"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': '无权限访问'}), 403
    
    data = request.json
    team_count = data.get('team_count', 1)
    max_members = data.get('max_members', 3)  # 新增：获取队伍人数
    
    if not isinstance(team_count, int) or team_count < 1:
        return jsonify({'success': False, 'message': '队伍数量必须是正整数'}), 400
    
    if not isinstance(max_members, int) or max_members < 1 or max_members > 10:
        return jsonify({'success': False, 'message': '队伍人数必须在1-10之间'}), 400
    
    created_teams = []
    for i in range(team_count):
        team_counter = 1
        while True:
            team_name = f"红队{team_counter}"
            if not Team.query.filter_by(team_name=team_name).first():
                break
            team_counter += 1
        
        team = Team(
            team_name=team_name, 
            team_icon=f"team_icon_{i+1}.png",
            max_members=max_members  # 新增：设置队伍最大人数
        )
        db.session.add(team)
        db.session.flush()
        
        team_members = []
        for j in range(max_members):  # 修改：根据max_members创建成员
            username = generate_random_username()
            password = generate_random_password()
            nickname = f"{team_name}-Member{j+1}"
            
            user = User(
                username=username,
                password=password,
                role='red_team',
                team_id=team.id,
                nickname=nickname
            )
            db.session.add(user)
            team_members.append({
                'username': username,
                'password': password,
                'nickname': nickname
            })
        
        team.member_count = max_members  # 修改：设置实际成员数量
        created_teams.append({
            'team_name': team_name,
            'max_members': max_members,  # 新增：返回队伍人数信息
            'members': team_members
        })
    
    db.session.commit()
    
    log_entry = SystemLog(
        log_type='system',
        message=f'管理员批量创建了 {team_count} 个队伍，每队 {max_members} 人',
        severity='low',
        user_id=session['user_id']
    )
    db.session.add(log_entry)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': f'成功创建 {team_count} 个队伍，每队 {max_members} 人',
        'teams': created_teams
    })


@app.route('/api/admin/delete_all_users', methods=['DELETE'])
def delete_all_users():
    """一键删除所有红队账户"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': '无权限访问'}), 403

    FlagSubmission.query.filter(FlagSubmission.user_id.in_(
        db.session.query(User.id).filter_by(role='red_team')
    )).delete(synchronize_session=False)

    SystemLog.query.filter(SystemLog.user_id.in_(
        db.session.query(User.id).filter_by(role='red_team')
    )).delete(synchronize_session=False)

    AttackLog.query.filter(AttackLog.team_id.in_(
        db.session.query(Team.id)
    )).delete(synchronize_session=False)

    SystemLog.query.filter(SystemLog.team_id.in_(
        db.session.query(Team.id)
    )).delete(synchronize_session=False)

    User.query.filter_by(role='red_team').delete()
    Team.query.delete()

    db.session.commit()

    log_entry = SystemLog(
        log_type='system',
        message='管理员一键删除了所有红队账户',
        severity='medium',
        user_id=session['user_id']
    )
    db.session.add(log_entry)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': '所有红队账户已删除'
    })

@app.route('/api/admin/reset_scores', methods=['POST'])
def reset_scores():
    """重置所有积分"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': '无权限访问'}), 403

    try:
        User.query.filter_by(role='red_team').update({'total_score': 0})
        Team.query.update({'total_score': 0})
        FlagSubmission.query.delete()

        db.session.commit()

        log_entry = SystemLog(
            log_type='system',
            message='管理员重置了所有积分',
            severity='high',
            user_id=session['user_id']
        )
        db.session.add(log_entry)
        db.session.commit()

        broadcast_score_update()

        return jsonify({
            'success': True,
            'message': '所有积分已重置'
        })

    except Exception as e:
        print(f"重置积分失败: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': '重置积分失败'}), 500

# =============================================================================
# API路由 - 管理员队伍管理
# =============================================================================

@app.route('/api/admin/teams/<int:team_id>/rename', methods=['PUT'])
def admin_rename_team(team_id):
    """管理员修改队伍名称"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': '无权限访问'}), 403

    data = request.json
    new_name = data.get('team_name')

    if not new_name or len(new_name) < 3:
        return jsonify({'success': False, 'message': '队伍名称至少需要3个字符'}), 400

    team = Team.query.get_or_404(team_id)

    existing_team = Team.query.filter_by(team_name=new_name).first()
    if existing_team and existing_team.id != team.id:
        return jsonify({'success': False, 'message': '队伍名称已存在'}), 400

    old_name = team.team_name
    team.team_name = new_name
    db.session.commit()

    log_entry = SystemLog(
        log_type='system',
        message=f'管理员将队伍 {old_name} 更名为 {new_name}',
        severity='low',
        user_id=session['user_id']
    )
    db.session.add(log_entry)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': '队伍名称修改成功'
    })

@app.route('/api/admin/teams/<int:team_id>/accounts', methods=['GET'])
def get_team_accounts(team_id):
    """获取队伍的所有账户信息"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': '无权限访问'}), 403

    team = Team.query.get_or_404(team_id)
    users = User.query.filter_by(team_id=team_id, role='red_team').all()

    return jsonify({
        'success': True,
        'team': {
            'id': team.id,
            'team_name': team.team_name,
            'member_count': team.member_count
        },
        'accounts': [{
            'id': user.id,
            'username': user.username,
            'password': user.password,
            'nickname': user.nickname,
            'email': user.email,
            'total_score': user.total_score,
            'is_active': user.is_active,
            'created_at': user.created_at.isoformat()
        } for user in users]
    })

@app.route('/api/admin/teams/<int:team_id>/captured_targets', methods=['GET'])
def get_team_captured_targets(team_id):
    """获取队伍攻下的所有靶标"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': '无权限访问'}), 403

    try:
        team_members = User.query.filter_by(team_id=team_id).all()
        member_ids = [member.id for member in team_members]

        print(f"队伍 {team_id} 的成员ID: {member_ids}")

        if not member_ids:
            return jsonify({
                'success': True,
                'team_id': team_id,
                'captured_targets': []
            })

        correct_submissions = FlagSubmission.query.filter(
            FlagSubmission.user_id.in_(member_ids),
            FlagSubmission.is_correct == True
        ).all()

        print(f"队伍 {team_id} 的正确提交数量: {len(correct_submissions)}")

        captured_targets = []
        for submission in correct_submissions:
            target = Target.query.get(submission.target_id)
            if target:
                captured_targets.append({
                    'id': target.id,
                    'name': target.name,
                    'ip_address': target.ip_address,
                    'points': target.points,
                    'description': target.description
                })
                print(f"找到靶标: {target.name}")

        unique_targets = {}
        for target in captured_targets:
            if target['id'] not in unique_targets:
                unique_targets[target['id']] = target

        print(f"队伍 {team_id} 的攻下靶标数量: {len(unique_targets)}")

        return jsonify({
            'success': True,
            'team_id': team_id,
            'captured_targets': list(unique_targets.values())
        })

    except Exception as e:
        print(f"获取队伍靶标失败: {e}")
        return jsonify({
            'success': False,
            'message': '获取数据失败'
        }), 500

@app.route('/api/admin/all_users', methods=['GET'])
def get_all_users():
    """获取所有用户信息（用于关联队伍）"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': '无权限访问'}), 403

    users = User.query.all()

    return jsonify({
        'success': True,
        'users': [{
            'id': user.id,
            'username': user.username,
            'team_id': user.team_id,
            'role': user.role
        } for user in users]
    })

# =============================================================================
# API路由 - 管理员靶标管理
# =============================================================================

@app.route('/api/admin/targets', methods=['GET', 'POST', 'DELETE'])
def manage_targets():
    """靶标管理"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': '无权限访问'}), 403

    if request.method == 'GET':
        targets = Target.query.all()
        return jsonify({
            'success': True,
            'targets': [{
                'id': t.id,
                'name': t.name,
                'ip_address': t.ip_address,
                'flag': t.flag,
                'points': t.points,
                'description': t.description,
                'competition_id': t.competition_id,
                'competition_name': t.competition.name if t.competition else None,
                'is_active': t.is_active,
                'created_at': t.created_at.isoformat()
            } for t in targets]
        })

    elif request.method == 'POST':
        data = request.json

        active_competition = Competition.query.filter_by(is_active=True, is_ended=False).first()
        if not active_competition:
            active_competition = Competition(
                name='默认比赛',
                description='系统自动创建的默认比赛',
                is_active=True,
                is_ended=False,
                created_by=session['user_id']
            )
            db.session.add(active_competition)
            db.session.flush()

        target = Target(
            competition_id=active_competition.id,
            name=data.get('name'),
            ip_address=data.get('ip_address'),
            flag=data.get('flag', generate_random_flag()),
            points=data.get('points', 100),
            description=data.get('description', '')
        )

        db.session.add(target)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': '靶标添加成功',
            'target_id': target.id
        })

    elif request.method == 'DELETE':
        target_id = request.json.get('target_id')
        target = Target.query.get_or_404(target_id)

        db.session.delete(target)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': '靶标删除成功'
        })

@app.route('/api/admin/targets/<int:target_id>', methods=['GET', 'PUT'])
def update_target(target_id):
    """获取和更新靶标"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': '无权限访问'}), 403

    target = Target.query.get_or_404(target_id)

    if request.method == 'GET':
        return jsonify({
            'success': True,
            'target': {
                'id': target.id,
                'name': target.name,
                'ip_address': target.ip_address,
                'flag': target.flag,
                'points': target.points,
                'description': target.description,
                'is_active': target.is_active,
                'competition_id': target.competition_id
            }
        })

    elif request.method == 'PUT':
        data = request.json

        if 'name' in data:
            target.name = data['name']
        if 'ip_address' in data:
            target.ip_address = data['ip_address']
        if 'flag' in data:
            target.flag = data['flag']
        if 'points' in data:
            target.points = data['points']
        if 'description' in data:
            target.description = data['description']
        if 'is_active' in data:
            target.is_active = data['is_active']

        db.session.commit()

        return jsonify({
            'success': True,
            'message': '靶标更新成功'
        })

@app.route('/api/admin/targets/<int:target_id>/captured_teams', methods=['GET'])
def get_target_captured_teams(target_id):
    """获取攻破特定靶标的队伍数量"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': '无权限访问'}), 403

    correct_submissions = db.session.query(FlagSubmission, User).join(
        User, FlagSubmission.user_id == User.id
    ).filter(
        FlagSubmission.target_id == target_id,
        FlagSubmission.is_correct == True
    ).all()

    unique_team_ids = set()
    for submission, user in correct_submissions:
        if user.team_id:
            unique_team_ids.add(user.team_id)

    return jsonify({
        'success': True,
        'target_id': target_id,
        'captured_teams_count': len(unique_team_ids),
        'team_ids': list(unique_team_ids)
    })

# =============================================================================
# API路由 - 管理员比赛管理
# =============================================================================

@app.route('/api/admin/competitions', methods=['GET', 'POST'])
def manage_competitions():
    """比赛管理"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': '无权限访问'}), 403

    if request.method == 'GET':
        # 获取比赛列表
        try:
            competitions = Competition.query.order_by(Competition.created_at.desc()).all()
            return jsonify({
                'success': True,
                'competitions': [{
                    'id': c.id,
                    'name': c.name,
                    'description': c.description,
                    'background_story': c.background_story,
                    'theme_image': c.theme_image,
                    'start_time': c.start_time.isoformat() if c.start_time else None,
                    'end_time': c.end_time.isoformat() if c.end_time else None,
                    'is_active': c.is_active,
                    'is_ended': c.is_ended,
                    'created_at': c.created_at.isoformat()
                } for c in competitions]
            })
        except Exception as e:
            print(f"获取比赛列表失败: {e}")
            return jsonify({'success': False, 'message': '获取比赛列表失败'}), 500

    elif request.method == 'POST':
        # 创建比赛
        data = request.json
        print(f"收到创建比赛请求: {data}")

        # 验证必要字段
        if not data.get('name'):
            return jsonify({'success': False, 'message': '比赛名称不能为空'}), 400

        try:
            # 简化时间处理逻辑 - 修复时区问题
            def parse_combined_datetime(date_str, time_str):
                """解析组合的日期和时间，直接存储为本地时间"""
                if not date_str or not time_str:
                    return None
                try:
                    # 组合成标准格式，直接作为本地时间存储
                    datetime_str = f"{date_str}T{time_str}"
                    local_dt = datetime.fromisoformat(datetime_str)
                    
                    print(f"时间存储: {local_dt} (本地时间)")
                    return local_dt  # 直接返回本地时间，不转换时区
                except Exception as e:
                    print(f"时间解析错误: {e}")
                    return None

            # 使用统一的时间解析方法
            start_time = parse_combined_datetime(data.get('start_date'), data.get('start_time'))
            end_time = parse_combined_datetime(data.get('end_date'), data.get('end_time'))

            # 如果没有分开的字段，尝试直接解析组合字段
            if not start_time and data.get('start_time'):
                try:
                    start_str = data.get('start_time')
                    if 'T' in start_str:
                        # 直接解析为本地时间
                        start_time = datetime.fromisoformat(start_str.replace('Z', ''))
                    else:
                        # 处理没有T的情况
                        start_time = datetime.strptime(start_str, '%Y-%m-%d %H:%M')
                except Exception as e:
                    print(f"开始时间解析失败: {e}")

            if not end_time and data.get('end_time'):
                try:
                    end_str = data.get('end_time')
                    if 'T' in end_str:
                        end_time = datetime.fromisoformat(end_str.replace('Z', ''))
                    else:
                        end_time = datetime.strptime(end_str, '%Y-%m-%d %H:%M')
                except Exception as e:
                    print(f"结束时间解析失败: {e}")

            # 验证时间逻辑
            if start_time and end_time:
                if start_time >= end_time:
                    return jsonify({'success': False, 'message': '结束时间必须晚于开始时间'}), 400
            else:
                return jsonify({'success': False, 'message': '开始时间和结束时间不能为空'}), 400
            # 创建比赛对象
            competition = Competition(
                name=data.get('name'),
                description=data.get('description'),
                background_story=data.get('background_story'),
                theme_image=data.get('theme_image'),
                start_time=start_time,
                end_time=end_time,
                created_by=session['user_id'],
                is_active=True
            )

            db.session.add(competition)
            db.session.flush()  # 获取competition.id

            # 创建默认靶标
            default_targets = [
                {
                    'name': 'Web服务器',
                    'ip_address': '192.168.1.100',
                    'points': 100,
                    'description': 'Web应用服务靶标'
                },
                {
                    'name': '数据库服务器', 
                    'ip_address': '192.168.1.101',
                    'points': 150,
                    'description': '数据库服务靶标'
                },
                {
                    'name': '文件服务器',
                    'ip_address': '192.168.1.102', 
                    'points': 80,
                    'description': '文件服务靶标'
                }
            ]

            for target_data in default_targets:
                target = Target(
                    competition_id=competition.id,
                    name=target_data['name'],
                    ip_address=target_data['ip_address'],
                    flag=generate_random_flag(),
                    points=target_data['points'],
                    description=target_data['description']
                )
                db.session.add(target)

            db.session.commit()

            log_entry = SystemLog(
                log_type='system',
                message=f'管理员创建了比赛: {competition.name}',
                severity='low',
                user_id=session['user_id']
            )
            db.session.add(log_entry)
            db.session.commit()

            return jsonify({
                'success': True,
                'message': '比赛创建成功',
                'competition_id': competition.id
            })

        except Exception as e:
            print(f"创建比赛失败: {e}")
            db.session.rollback()
            return jsonify({'success': False, 'message': f'创建比赛失败: {str(e)}'}), 500

@app.route('/api/admin/competitions/<int:competition_id>', methods=['GET', 'PUT'])
def manage_competition(competition_id):
    """获取和更新比赛信息"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': '无权限访问'}), 403

    competition = Competition.query.get_or_404(competition_id)

    if request.method == 'GET':
        return jsonify({
            'success': True,
            'competition': {
                'id': competition.id,
                'name': competition.name,
                'description': competition.description,
                'background_story': competition.background_story,
                'theme_image': competition.theme_image,
                'start_time': competition.start_time.isoformat() if competition.start_time else None,
                'end_time': competition.end_time.isoformat() if competition.end_time else None,
                'is_active': competition.is_active,
                'is_ended': competition.is_ended,
                'created_at': competition.created_at.isoformat()
            }
        })

    elif request.method == 'PUT':
        data = request.json
        print(f"更新比赛请求数据: {data}")

        # 改进的时间解析函数，修复时区问题
        def parse_datetime(dt_str):
            if not dt_str:
                return None
            try:
                # 处理datetime-local输入格式 (YYYY-MM-DDTHH:MM)
                if 'T' in dt_str:
                    # 直接解析为本地时间，不进行时区转换
                    local_dt = datetime.fromisoformat(dt_str)
                    print(f"时间解析: {local_dt} (本地时间)")
                    return local_dt
                else:
                    # 处理其他格式的时间
                    return datetime.strptime(dt_str, '%Y-%m-%d %H:%M:%S')
            except Exception as e:
                print(f"时间解析错误: {e}")
                return None

        if 'name' in data:
            competition.name = data['name']
        if 'description' in data:
            competition.description = data['description']
        if 'background_story' in data:
            competition.background_story = data['background_story']
        if 'start_time' in data:
            # 如果传递了空字符串，设置为None
            if data['start_time'] == '':
                competition.start_time = None
            else:
                parsed_start = parse_datetime(data['start_time'])
                if parsed_start:
                    competition.start_time = parsed_start
        if 'end_time' in data:
            # 如果传递了空字符串，设置为None
            if data['end_time'] == '':
                competition.end_time = None
            else:
                parsed_end = parse_datetime(data['end_time'])
                if parsed_end:
                    competition.end_time = parsed_end
        if 'is_active' in data:
            competition.is_active = data['is_active']

        # 验证时间逻辑
        if competition.start_time and competition.end_time:
            if competition.start_time >= competition.end_time:
                return jsonify({'success': False, 'message': '结束时间必须晚于开始时间'}), 400

        try:
            db.session.commit()

            log_entry = SystemLog(
                log_type='system',
                message=f'管理员更新了比赛: {competition.name}',
                severity='low',
                user_id=session['user_id']
            )
            db.session.add(log_entry)
            db.session.commit()

            return jsonify({
                'success': True,
                'message': '比赛信息更新成功'
            })

        except Exception as e:
            print(f"更新比赛失败: {e}")
            db.session.rollback()
            return jsonify({'success': False, 'message': f'更新比赛失败: {str(e)}'}), 500



@app.route('/api/admin/competitions/<int:competition_id>/end', methods=['POST'])
def end_competition(competition_id):
    """结束比赛"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': '无权限访问'}), 403

    competition = Competition.query.get_or_404(competition_id)
    competition.is_ended = True
    competition.is_active = False

    db.session.commit()

    log_entry = SystemLog(
        log_type='system',
        message=f'管理员结束了比赛: {competition.name}',
        severity='medium',
        user_id=session['user_id']
    )
    db.session.add(log_entry)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': '比赛已结束'
    })

@app.route('/api/admin/competitions/<int:competition_id>', methods=['DELETE'])
def delete_competition(competition_id):
    """删除比赛"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': '无权限访问'}), 403

    competition = Competition.query.get_or_404(competition_id)

    Target.query.filter_by(competition_id=competition_id).delete()

    db.session.delete(competition)
    db.session.commit()

    log_entry = SystemLog(
        log_type='system',
        message=f'管理员删除了比赛: {competition.name}',
        severity='medium',
        user_id=session['user_id']
    )
    db.session.add(log_entry)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': '比赛删除成功'
    })

# =============================================================================
# API路由 - 日志管理
# =============================================================================

@app.route('/api/home/logs', methods=['GET'])
def get_home_logs():
    """获取首页最新日志"""
    try:
        print("开始获取首页日志...")

        logs = SystemLog.query.order_by(SystemLog.created_at.desc()).limit(10).all()

        print(f"查询到 {len(logs)} 条日志")

        log_data = []
        for log in logs:
            log_data.append({
                'id': log.id,
                'type': log.log_type,
                'message': log.message,
                'severity': log.severity,
                'created_at': log.created_at.isoformat()
            })

        print("日志数据构建完成")

        return jsonify({
            'success': True,
            'logs': log_data
        })

    except Exception as e:
        print(f"获取首页日志失败: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': '获取日志失败'}), 500

@app.route('/api/admin/logs', methods=['GET'])
def get_system_logs():
    """获取系统日志"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': '无权限访问'}), 403

    log_type = request.args.get('type', '')
    limit = request.args.get('limit', 50, type=int)

    query = SystemLog.query

    if log_type:
        query = query.filter_by(log_type=log_type)

    logs = query.order_by(SystemLog.created_at.desc()).limit(limit).all()

    return jsonify({
        'success': True,
        'logs': [{
            'id': log.id,
            'type': log.log_type,
            'message': log.message,
            'severity': log.severity,
            'team_id': log.team_id,
            'user_id': log.user_id,
            'created_at': log.created_at.isoformat()
        } for log in logs]
    })

@app.route('/api/admin/clear_logs', methods=['POST'])
def clear_system_logs():
    """清除系统收集的日志"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': '无权限访问'}), 403

    try:
        logs_to_delete = SystemLog.query.all()
        deleted_count = len(logs_to_delete)

        SystemLog.query.delete()

        db.session.commit()

        unique_id = int(time.time())
        log_entry = SystemLog(
            log_type='system',
            message=f'管理员清除了系统日志 - ID:{unique_id}',
            severity='medium',
            user_id=session['user_id']
        )
        db.session.add(log_entry)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'成功清除 {deleted_count} 条系统日志'
        })

    except Exception as e:
        print(f"清除日志失败: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': '清除日志失败'}), 500

@app.route('/api/admin/flag_submissions', methods=['GET'])
def get_flag_submissions():
    """获取所有Flag提交记录"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': '无权限访问'}), 403

    submissions = FlagSubmission.query.all()

    return jsonify({
        'success': True,
        'submissions': [{
            'id': s.id,
            'user_id': s.user_id,
            'target_id': s.target_id,
            'submitted_flag': s.submitted_flag,
            'is_correct': s.is_correct,
            'points_earned': s.points_earned,
            'submitted_at': s.submitted_at.isoformat()
        } for s in submissions]
    })

@app.route('/api/logs/collect', methods=['POST'])
def collect_logs():
    """收集来自Agent的日志数据"""
    try:
        data = request.json
        logs = data.get('logs', [])
        target_id = data.get('target_id')
        target_name = data.get('target_name')
        target_ip = data.get('target_ip')

        if not logs:
            return jsonify({'success': False, 'message': '没有日志数据'}), 400

        saved_logs = []
        duplicate_count = 0

        for log_data in logs:
            recent_duplicate = SystemLog.query.filter(
                SystemLog.message == log_data.get('message', ''),
                SystemLog.log_type == log_data.get('type', 'system'),
                SystemLog.created_at >= datetime.utcnow() - timedelta(minutes=1)
            ).first()

            if recent_duplicate:
                duplicate_count += 1
                continue

            system_log = SystemLog(
                log_type=log_data.get('type', 'system'),
                source_ip=log_data.get('details', {}).get('source_ip') or target_ip,
                target_ip=log_data.get('details', {}).get('target_ip') or target_ip,
                message=log_data.get('message', '未知日志'),
                severity=log_data.get('severity', 'medium'),
                raw_data=log_data.get('details', {})
            )

            db.session.add(system_log)
            saved_logs.append(system_log)

        db.session.commit()

        for log in saved_logs:
            broadcast_log_update({
                'id': log.id,
                'type': log.log_type,
                'message': log.message,
                'severity': log.severity,
                'created_at': log.created_at.isoformat()
            })

        return jsonify({
            'success': True,
            'message': f'成功收集 {len(saved_logs)} 条日志，跳过 {duplicate_count} 条重复日志',
            'logs_received': len(logs),
            'logs_saved': len(saved_logs),
            'duplicates_skipped': duplicate_count
        })

    except Exception as e:
        print(f"日志收集错误: {e}")
        return jsonify({'success': False, 'message': '日志收集失败'}), 500

# =============================================================================
# API路由 - 实时态势
# =============================================================================

@app.route('/api/situation/data', methods=['GET'])
def get_situation_data():
    """获取实时态势数据"""
    competition = Competition.query.filter_by(is_active=True).first()

    top_teams = Team.query.filter(Team.member_count > 0).order_by(Team.total_score.desc()).limit(10).all()

    recent_logs = SystemLog.query.order_by(SystemLog.created_at.desc()).limit(50).all()

    one_hour_ago = datetime.utcnow() - timedelta(hours=1)
    recent_attacks = AttackLog.query.filter(AttackLog.timestamp >= one_hour_ago).all()

    total_attacks = SystemLog.query.filter_by(log_type='attack').count()
    flags_captured = FlagSubmission.query.filter_by(is_correct=True).count()

    targets = []
    if competition:
        targets = Target.query.filter_by(competition_id=competition.id, is_active=True).all()

    return jsonify({
        'success': True,
        'competition': {
            'name': competition.name if competition else '无活跃比赛',
            'is_active': competition.is_active if competition else False
        } if competition else None,
        'teams': [{
            'id': t.id,
            'team_name': t.team_name,
            'team_icon': t.team_icon,
            'total_score': t.total_score,
            'member_count': t.member_count
        } for t in top_teams],
        'targets': [{
            'id': t.id,
            'name': t.name,
            'ip_address': t.ip_address,
            'points': t.points
        } for t in targets],
        'logs': [{
            'id': l.id,
            'log_type': l.log_type,
            'message': l.message,
            'severity': l.severity,
            'team_id': l.team_id,
            'created_at': l.created_at.isoformat()
        } for l in recent_logs],
        'attacks': [{
            'id': a.id,
            'team_id': a.team_id,
            'source_ip': a.source_ip,
            'target_ip': a.target_ip,
            'attack_type': a.attack_type,
            'traffic_volume': a.traffic_volume,
            'timestamp': a.timestamp.isoformat()
        } for a in recent_attacks],
        'statistics': {
            'total_attacks': total_attacks,
            'flags_captured': flags_captured,
            'active_teams': len(top_teams)
        }
    })

@app.route('/api/admin/online_users', methods=['GET'])
def get_online_users():
    """获取在线用户数（基于WebSocket连接）"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': '无权限访问'}), 403

    online_count = len([data for data in online_users.values() if data.get('user_id')])

    print(f'Online users debug - Total connections: {len(online_users)}, With user_id: {online_count}')

    return jsonify({
        'success': True,
        'online_users': online_count,
        'total_connections': len(online_users)
    })

# =============================================================================
# WebSocket事件处理
# =============================================================================

@socketio.on('connect')
def handle_connect():
    """处理WebSocket连接"""
    print(f'Client connected: {request.sid}')

    online_users[request.sid] = {
        'connected_at': datetime.utcnow(),
        'user_id': None,
        'ip_address': request.environ.get('REMOTE_ADDR')
    }
    print(f'Online users after connect: {len(online_users)}')

@socketio.on('disconnect')
def handle_disconnect():
    """处理WebSocket断开连接"""
    print(f'Client disconnected: {request.sid}')
    online_users.pop(request.sid, None)

@socketio.on('associate_user')
def handle_associate_user(data=None):
    """关联WebSocket连接和用户"""
    try:
        user_id = session.get('user_id')
        if user_id and request.sid in online_users:
            online_users[request.sid]['user_id'] = user_id
            print(f'User {user_id} associated with socket {request.sid}')
    except Exception as e:
        print(f"关联用户时出错: {e}")

# =============================================================================
# 静态文件服务
# =============================================================================

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

# =============================================================================
# 定时任务 - 检查比赛状态
# =============================================================================

def check_competition_status():
    """定期检查比赛状态，自动结束到期的比赛"""
    with app.app_context():
        try:
            now = datetime.now()
            print(f"检查比赛状态 - 当前时间: {now}")
            
            # 查找需要结束的比赛（结束时间已到但未标记为结束的）
            competitions_to_end = Competition.query.filter(
                Competition.end_time <= now,
                Competition.is_ended == False
            ).all()
            
            for competition in competitions_to_end:
                print(f"自动结束比赛: {competition.name} (ID: {competition.id})")
                competition.is_ended = True
                competition.is_active = False
                
                # 记录系统日志
                log_entry = SystemLog(
                    log_type='system',
                    message=f'比赛自动结束: {competition.name}',
                    severity='medium'
                )
                db.session.add(log_entry)
            
            if competitions_to_end:
                db.session.commit()
                print(f"已自动结束 {len(competitions_to_end)} 个比赛")
                
                # 广播状态更新
                broadcast_score_update()
            
        except Exception as e:
            print(f"检查比赛状态时出错: {e}")
            db.session.rollback()

# 启动定时任务
def start_background_tasks():
    """启动后台任务"""
    def run_check():
        while True:
            check_competition_status()
            time.sleep(60)  # 每分钟检查一次
    
    # 在单独的线程中运行定时任务
    thread = threading.Thread(target=run_check, daemon=True)
    thread.start()
    print("后台任务已启动：比赛状态检查（每分钟一次）")

# =============================================================================
# 应用启动
# =============================================================================

# 创建数据库表
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    print("🚀 启动实时攻防平台...")
    
    # 启动后台任务
    start_background_tasks()
    
    socketio.run(app,
                host=SERVER_CONFIG['HOST'],
                port=SERVER_CONFIG['PORT'],
                debug=APP_CONFIG['DEBUG'])
