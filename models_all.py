#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据库模型定义
包含所有ATK和AWD模式的模型
"""
from datetime import datetime
from database import db


def get_local_time():
    """获取本地时间（北京时间）"""
    return datetime.now()


# =============================================================================
# ATK模式模型
# =============================================================================

class User(db.Model):
    """用户模型"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100))
    role = db.Column(db.Enum('admin', 'red_team', 'judge', 'attacker', 'defender'), default='red_team')
    team_id = db.Column(db.Integer, db.ForeignKey('teams.id'), nullable=True)
    nickname = db.Column(db.String(100))
    avatar = db.Column(db.String(255))
    total_score = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.TIMESTAMP, default=get_local_time)
    updated_at = db.Column(db.TIMESTAMP, default=get_local_time, onupdate=get_local_time)

    team = db.relationship('Team', backref='members')


class Team(db.Model):
    """队伍模型"""
    __tablename__ = 'teams'
    id = db.Column(db.Integer, primary_key=True)
    team_name = db.Column(db.String(100), unique=True, nullable=False)
    team_icon = db.Column(db.String(255))
    total_score = db.Column(db.Integer, default=0)
    member_count = db.Column(db.Integer, default=0)
    max_members = db.Column(db.Integer, default=3)
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
# AWD模式模型
# =============================================================================

class CompetitionConfig(db.Model):
    """比赛配置模型 - 存储比赛模式设置"""
    __tablename__ = 'competition_configs'

    id = db.Column(db.Integer, primary_key=True)
    mode = db.Column(db.Enum('ATK', 'AWD', name='competition_mode'), nullable=False, default='ATK')
    created_at = db.Column(db.TIMESTAMP, default=get_local_time)
    updated_at = db.Column(db.TIMESTAMP, default=get_local_time, onupdate=get_local_time)


class AttackTarget(db.Model):
    """攻击目标模型 - AWD模式下的攻击资产"""
    __tablename__ = 'attack_targets'

    id = db.Column(db.Integer, primary_key=True)
    asset_name = db.Column(db.String(100), nullable=False)
    target_info = db.Column(db.String(255), nullable=False)
    notes = db.Column(db.Text)
    created_at = db.Column(db.TIMESTAMP, default=get_local_time)

    assignments = db.relationship('TargetAssignment', backref='attack_target', lazy='dynamic',
                                  cascade='all, delete-orphan')


class TargetAssignment(db.Model):
    """目标分配模型 - 队伍与攻击目标的多对多关系"""
    __tablename__ = 'target_assignments'

    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey('attack_targets.id'), nullable=False)
    team_id = db.Column(db.Integer, db.ForeignKey('teams.id'), nullable=False)
    team_type = db.Column(db.Enum('attack', 'defense', name='team_type'), nullable=False, default='attack')
    created_at = db.Column(db.TIMESTAMP, default=get_local_time)

    team = db.relationship('Team', backref='target_assignments')


class Report(db.Model):
    """报告模型 - 攻防报告"""
    __tablename__ = 'reports'

    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    report_type = db.Column(db.Enum('attack', 'defense', name='report_type'), nullable=False)
    target_id = db.Column(db.Integer, db.ForeignKey('attack_targets.id'), nullable=False)
    report_title = db.Column(db.String(200), nullable=False)
    file_path = db.Column(db.String(255))
    file_name = db.Column(db.String(100))
    status = db.Column(db.Enum('pending', 'approved', 'rejected', name='report_status'),
                       nullable=False, default='pending')
    review_reason = db.Column(db.Text)
    reviewer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    score = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.TIMESTAMP, default=get_local_time)
    reviewed_at = db.Column(db.TIMESTAMP, nullable=True)

    reporter = db.relationship('User', foreign_keys=[reporter_id], backref='submitted_reports')
    reviewer = db.relationship('User', foreign_keys=[reviewer_id], backref='reviewed_reports')
    target = db.relationship('AttackTarget', backref='reports')
