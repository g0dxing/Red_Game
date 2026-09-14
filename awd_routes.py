#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AWD模式API路由
包含比赛模式管理、批量创建、靶标管理、报告管理和排行榜功能
"""
import os
import uuid
from datetime import datetime
from io import BytesIO

from flask import Blueprint, request, jsonify, session, send_from_directory, send_file
from database import db
from models_all import (
    User, Team, SystemLog, CompetitionConfig,
    AttackTarget, TargetAssignment, Report
)

# 创建蓝图
awd_bp = Blueprint('awd', __name__, url_prefix='/awd')

# 上传文件配置
UPLOAD_DIR = os.path.join('static', 'uploads', 'reports')
os.makedirs(UPLOAD_DIR, exist_ok=True)


# =============================================================================
# 工具函数
# =============================================================================

def admin_required():
    """管理员权限检查装饰器"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return None, (jsonify({'success': False, 'message': '无权限访问'}), 403)
    return session.get('user_id'), None


def judge_required():
    """评委权限检查"""
    if 'user_id' not in session or session.get('role') != 'judge':
        return None, (jsonify({'success': False, 'message': '无权限访问'}), 403)
    return session.get('user_id'), None


def login_required():
    """登录检查"""
    if 'user_id' not in session:
        return None, (jsonify({'success': False, 'message': '请先登录'}), 401)
    return session.get('user_id'), None


def attacker_or_defender_required():
    """攻击手或防守方权限检查"""
    if 'user_id' not in session or session.get('role') not in ('attacker', 'defender'):
        return None, (jsonify({'success': False, 'message': '无权限访问'}), 403)
    return session.get('user_id'), None


def log_operation(log_type, message, severity='low', user_id=None, team_id=None):
    """记录操作日志"""
    try:
        log_entry = SystemLog(
            log_type=log_type,
            message=message,
            severity=severity,
            user_id=user_id or session.get('user_id'),
            team_id=team_id
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        print(f"记录日志失败: {e}")
        db.session.rollback()


# =============================================================================
# 1. 比赛模式管理
# =============================================================================

@awd_bp.route('/api/admin/mode', methods=['GET'])
def get_competition_mode():
    """获取当前比赛模式"""
    user_id, error = admin_required()
    if error:
        return error

    try:
        config = CompetitionConfig.query.first()
        if not config:
            config = CompetitionConfig(mode='ATK')
            db.session.add(config)
            db.session.commit()

        return jsonify({
            'success': True,
            'mode': config.mode,
            'updated_at': config.updated_at.isoformat() if config.updated_at else None
        })
    except Exception as e:
        print(f"获取比赛模式失败: {e}")
        return jsonify({'success': False, 'message': '获取比赛模式失败'}), 500


@awd_bp.route('/api/mode', methods=['GET'])
def get_competition_mode_public():
    """获取当前比赛模式（公开接口，无需登录）"""
    try:
        config = CompetitionConfig.query.first()
        if not config:
            config = CompetitionConfig(mode='ATK')
            db.session.add(config)
            db.session.commit()

        return jsonify({
            'success': True,
            'mode': config.mode
        })
    except Exception as e:
        print(f"获取比赛模式失败: {e}")
        return jsonify({'success': True, 'mode': 'ATK'})


@awd_bp.route('/api/admin/mode', methods=['PUT'])
def set_competition_mode():
    """设置比赛模式"""
    user_id, error = admin_required()
    if error:
        return error

    data = request.json
    mode = data.get('mode', '').upper()

    if mode not in ('ATK', 'AWD'):
        return jsonify({'success': False, 'message': '无效的比赛模式，只支持ATK或AWD'}), 400

    try:
        config = CompetitionConfig.query.first()
        if not config:
            config = CompetitionConfig(mode=mode)
            db.session.add(config)
        else:
            config.mode = mode

        db.session.commit()

        log_operation('system', f'管理员切换比赛模式为 {mode}', 'low', user_id)

        return jsonify({
            'success': True,
            'message': f'比赛模式已设置为 {mode}',
            'mode': mode
        })
    except Exception as e:
        print(f"设置比赛模式失败: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': '设置比赛模式失败'}), 500


# =============================================================================
# 2. 批量创建账户
# =============================================================================

@awd_bp.route('/api/admin/batch_create', methods=['POST'])
def batch_create_accounts():
    """批量创建评委/攻击手/防守方账户"""
    user_id, error = admin_required()
    if error:
        return error

    data = request.json
    role = data.get('role', '')
    team_count = data.get('team_count', 1)
    members_per_team = data.get('members_per_team', 3)

    if role not in ('judge', 'attacker', 'defender'):
        return jsonify({'success': False, 'message': '无效的角色类型，只支持judge/attacker/defender'}), 400

    if not isinstance(team_count, int) or team_count < 1 or team_count > 50:
        return jsonify({'success': False, 'message': '队伍数量必须在1-50之间'}), 400

    if not isinstance(members_per_team, int) or members_per_team < 1 or members_per_team > 10:
        return jsonify({'success': False, 'message': '每队人数必须在1-10之间'}), 400

    role_names = {'judge': '裁判', 'attacker': '红队', 'defender': '蓝队'}
    role_prefix = {'judge': 'jd', 'attacker': 'rd', 'defender': 'bf'}
    team_prefix = {'attacker': '红队', 'defender': '蓝队'}

    try:
        import random
        created_accounts = []
        used_usernames = set()

        # 裁判不创建队伍，直接创建用户
        if role == 'judge':
            for i in range(team_count):
                prefix = role_prefix[role]
                while True:
                    random_digits = ''.join(random.choices('0123456789', k=4))
                    username = f"{prefix}{random_digits}"
                    if username not in used_usernames:
                        existing = User.query.filter_by(username=username).first()
                        if not existing:
                            used_usernames.add(username)
                            break

                password = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@.', k=12))
                user = User(
                    username=username,
                    password=password,
                    role='judge',
                    nickname=f"裁判{random_digits}",
                    is_active=True
                )
                db.session.add(user)
                created_accounts.append({'username': username, 'password': password, 'role': 'judge'})
            
            db.session.commit()
            log_operation('system', f'管理员批量创建了 {team_count} 个裁判账户', 'low', user_id)
            return jsonify({
                'success': True,
                'message': f'成功创建 {team_count} 个裁判账户',
                'accounts': created_accounts
            })

        # 攻击队/蓝队：创建队伍并分配成员
        for team_idx in range(team_count):
            # 找到不重复的队伍名
            team_counter = 1
            while True:
                team_name = f"{team_prefix[role]}{team_counter}"
                if not Team.query.filter_by(team_name=team_name).first():
                    break
                team_counter += 1

            team = Team(
                team_name=team_name,
                team_icon=f"{role}_{team_idx+1}.png",
                max_members=members_per_team,
                member_count=members_per_team
            )
            db.session.add(team)
            db.session.flush()

            # 为每个队伍创建成员
            for member_idx in range(members_per_team):
                prefix = role_prefix[role]
                while True:
                    random_digits = ''.join(random.choices('0123456789', k=4))
                    username = f"{prefix}{random_digits}"
                    if username not in used_usernames:
                        existing = User.query.filter_by(username=username).first()
                        if not existing:
                            used_usernames.add(username)
                            break

                password = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@.', k=12))
                user = User(
                    username=username,
                    password=password,
                    role=role,
                    team_id=team.id,
                    nickname=f"{team_name}-成员{member_idx+1}",
                    is_active=True
                )
                db.session.add(user)
                created_accounts.append({
                    'username': username,
                    'password': password,
                    'role': role,
                    'team_name': team_name
                })

        db.session.commit()

        log_operation('system', f'管理员批量创建了 {team_count} 个{role_names[role]}队伍，每队 {members_per_team} 人', 'low', user_id)

        return jsonify({
            'success': True,
            'message': f'成功创建 {team_count} 个{role_names[role]}队伍，每队 {members_per_team} 人',
            'accounts': created_accounts
        })
    except Exception as e:
        print(f"批量创建账户失败: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': '批量创建账户失败'}), 500


# =============================================================================
# 3. 靶标资产管理
# =============================================================================

@awd_bp.route('/api/admin/targets/assets', methods=['GET'])
def list_attack_targets():
    """获取所有攻击目标（管理员用）"""
    user_id, error = admin_required()
    if error:
        return error

    try:
        targets = AttackTarget.query.order_by(AttackTarget.created_at.desc()).all()
        return jsonify({
            'success': True,
            'targets': [{
                'id': t.id,
                'asset_name': t.asset_name,
                'target_info': t.target_info,
                'notes': t.notes,
                'created_at': t.created_at.isoformat() if t.created_at else None
            } for t in targets]
        })
    except Exception as e:
        print(f"获取攻击目标失败: {e}")
        return jsonify({'success': False, 'message': '获取攻击目标失败'}), 500


@awd_bp.route('/api/user/targets/assets', methods=['GET'])
def list_user_attack_targets():
    """获取当前用户可访问的攻击目标（普通用户用）"""
    user_id, error = login_required()
    if error:
        return error

    try:
        user = User.query.get(user_id)
        if not user or not user.team_id:
            return jsonify({'success': True, 'targets': []})

        # 获取当前队伍被分配的目标ID
        assignment_target_ids = [a.target_id for a in TargetAssignment.query.filter_by(team_id=user.team_id).all()]
        
        # 只返回被分配的目标
        targets = AttackTarget.query.filter(AttackTarget.id.in_(assignment_target_ids)).all() if assignment_target_ids else []
        
        return jsonify({
            'success': True,
            'targets': [{
                'id': t.id,
                'asset_name': t.asset_name,
                'target_info': t.target_info,
                'notes': t.notes
            } for t in targets]
        })
    except Exception as e:
        print(f"获取用户攻击目标失败: {e}")
        return jsonify({'success': False, 'message': '获取目标失败'}), 500


@awd_bp.route('/api/admin/targets/assets', methods=['POST'])
def add_attack_target():
    """手动添加攻击目标"""
    user_id, error = admin_required()
    if error:
        return error

    data = request.json
    asset_name = data.get('asset_name', '').strip()
    target_info = data.get('target_info', '').strip()
    notes = data.get('notes', '')

    if not asset_name:
        return jsonify({'success': False, 'message': '资产名称不能为空'}), 400
    if not target_info:
        return jsonify({'success': False, 'message': '目标信息不能为空'}), 400

    try:
        target = AttackTarget(
            asset_name=asset_name,
            target_info=target_info,
            notes=notes
        )
        db.session.add(target)
        db.session.commit()

        log_operation('system', f'管理员添加了攻击目标: {asset_name}', 'low', user_id)

        return jsonify({
            'success': True,
            'message': '攻击目标添加成功',
            'target_id': target.id
        })
    except Exception as e:
        print(f"添加攻击目标失败: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': '添加攻击目标失败'}), 500


@awd_bp.route('/api/admin/targets/import', methods=['POST'])
def import_targets_from_xlsx():
    """从xlsx文件导入攻击目标"""
    user_id, error = admin_required()
    if error:
        return error

    if 'file' not in request.files:
        return jsonify({'success': False, 'message': '请选择要上传的文件'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': '未选择文件'}), 400

    if not file.filename.endswith('.xlsx'):
        return jsonify({'success': False, 'message': '只支持xlsx格式的文件'}), 400

    try:
        import openpyxl
        from io import BytesIO

        file_content = file.read()
        wb = openpyxl.load_workbook(BytesIO(file_content))
        ws = wb.active

        imported_count = 0
        skipped_count = 0
        errors = []

        for row_idx, row in enumerate(ws.iter_rows(min_row=2, values_only=True), start=2):
            if not row or len(row) < 2:
                continue

            asset_name = str(row[0]).strip() if row[0] else ''
            target_info = str(row[1]).strip() if row[1] else ''
            notes = str(row[2]).strip() if len(row) > 2 and row[2] else ''

            if not asset_name or not target_info:
                skipped_count += 1
                continue

            existing = AttackTarget.query.filter_by(
                asset_name=asset_name,
                target_info=target_info
            ).first()

            if existing:
                skipped_count += 1
                continue

            try:
                target = AttackTarget(
                    asset_name=asset_name,
                    target_info=target_info,
                    notes=notes
                )
                db.session.add(target)
                imported_count += 1
            except Exception as e:
                errors.append(f"第{row_idx}行导入失败: {str(e)}")

        db.session.commit()

        log_operation('system', f'管理员从xlsx导入了 {imported_count} 个攻击目标', 'low', user_id)

        return jsonify({
            'success': True,
            'message': f'导入完成：成功 {imported_count} 条，跳过 {skipped_count} 条',
            'imported_count': imported_count,
            'skipped_count': skipped_count,
            'errors': errors[:10] if errors else []
        })
    except ImportError:
        return jsonify({'success': False, 'message': '请先安装openpyxl库: pip install openpyxl'}), 500
    except Exception as e:
        print(f"导入攻击目标失败: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': f'导入失败: {str(e)}'}), 500


@awd_bp.route('/api/admin/targets/template', methods=['GET'])
def download_target_template():
    """下载目标导入模板xlsx文件"""
    user_id, error = admin_required()
    if error:
        return error

    try:
        import openpyxl

        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = '目标导入模板'

        headers = ['资产名称', '目标信息', '备注']
        ws.append(headers)

        sample_row = ['Web服务器A', '192.168.1.100', '示例数据']
        ws.append(sample_row)

        for col in ws.columns:
            max_length = 0
            column_letter = col[0].column_letter
            for cell in col:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(str(cell.value))
                except:
                    pass
            adjusted_width = min(max_length + 2, 50)
            ws.column_dimensions[column_letter].width = adjusted_width

        output = BytesIO()
        wb.save(output)
        output.seek(0)

        log_operation('system', '管理员下载了目标导入模板', 'low', user_id)

        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name='目标导入模板.xlsx'
        )
    except ImportError:
        return jsonify({'success': False, 'message': '请先安装openpyxl库: pip install openpyxl'}), 500
    except Exception as e:
        print(f"下载目标模板失败: {e}")
        return jsonify({'success': False, 'message': '下载模板失败'}), 500


@awd_bp.route('/api/admin/targets/assets/<int:target_id>', methods=['DELETE'])
def delete_attack_target(target_id):
    """删除攻击目标"""
    user_id, error = admin_required()
    if error:
        return error

    try:
        target = AttackTarget.query.get(target_id)
        if not target:
            return jsonify({'success': False, 'message': '攻击目标不存在'}), 404

        asset_name = target.asset_name
        db.session.delete(target)
        db.session.commit()

        log_operation('system', f'管理员删除了攻击目标: {asset_name}', 'low', user_id)

        return jsonify({
            'success': True,
            'message': f'攻击目标 {asset_name} 删除成功'
        })
    except Exception as e:
        print(f"删除攻击目标失败: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': '删除攻击目标失败'}), 500


@awd_bp.route('/api/admin/targets/assignments', methods=['PUT'])
def set_target_assignments():
    """设置目标分配（队伍可以攻击/防守哪些目标）"""
    user_id, error = admin_required()
    if error:
        return error

    data = request.json
    target_id = data.get('target_id')
    assignments = data.get('assignments', [])

    if not target_id:
        return jsonify({'success': False, 'message': '缺少target_id'}), 400

    if not isinstance(assignments, list):
        return jsonify({'success': False, 'message': '无效的分配数据格式'}), 400

    try:
        # 只删除当前目标的归属，不影响其他目标
        TargetAssignment.query.filter_by(target_id=target_id).delete()

        created_count = 0
        for item in assignments:
            team_id = item.get('team_id')
            team_type = item.get('team_type', 'attack')

            if team_type not in ('attack', 'defense'):
                continue

            target = AttackTarget.query.get(target_id)
            team = Team.query.get(team_id)

            if not target or not team:
                continue

            assignment = TargetAssignment(
                target_id=target_id,
                team_id=team_id,
                team_type=team_type
            )
            db.session.add(assignment)
            created_count += 1

        db.session.commit()

        log_operation('system', f'管理员设置了目标 {target_id} 的 {created_count} 条归属', 'low', user_id)

        return jsonify({
            'success': True,
            'message': f'成功设置 {created_count} 条归属',
            'created_count': created_count
        })
    except Exception as e:
        print(f"设置目标分配失败: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': '设置目标分配失败'}), 500


@awd_bp.route('/api/admin/targets/assignments', methods=['GET'])
def get_target_assignments():
    """获取所有目标分配（管理员用）"""
    user_id, error = admin_required()
    if error:
        return error

    try:
        assignments = TargetAssignment.query.all()
        return jsonify({
            'success': True,
            'assignments': [{
                'id': a.id,
                'target_id': a.target_id,
                'target_name': a.attack_target.asset_name if a.attack_target else None,
                'target_info': a.attack_target.target_info if a.attack_target else None,
                'team_id': a.team_id,
                'team_name': a.team.team_name if a.team else None,
                'team_type': a.team_type,
                'created_at': a.created_at.isoformat() if a.created_at else None
            } for a in assignments]
        })
    except Exception as e:
        print(f"获取目标分配失败: {e}")
        return jsonify({'success': False, 'message': '获取目标分配失败'}), 500


@awd_bp.route('/api/user/targets/assignments', methods=['GET'])
def get_user_target_assignments():
    """获取当前用户队伍的目标分配（普通用户用）"""
    user_id, error = login_required()
    if error:
        return error

    try:
        user = User.query.get(user_id)
        if not user or not user.team_id:
            return jsonify({'success': True, 'assignments': []})

        assignments = TargetAssignment.query.filter_by(team_id=user.team_id).all()
        return jsonify({
            'success': True,
            'assignments': [{
                'id': a.id,
                'target_id': a.target_id,
                'target_name': a.attack_target.asset_name if a.attack_target else None,
                'target_info': a.attack_target.target_info if a.attack_target else None,
                'team_id': a.team_id,
                'team_type': a.team_type
            } for a in assignments]
        })
    except Exception as e:
        print(f"获取用户目标分配失败: {e}")
        return jsonify({'success': False, 'message': '获取目标分配失败'}), 500


# =============================================================================
# 4. 报告管理
# =============================================================================

@awd_bp.route('/api/reports/submit', methods=['POST'])
def submit_report():
    """提交报告（攻击/防御）"""
    user_id, error = attacker_or_defender_required()
    if error:
        return error

    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': '用户不存在'}), 404

    if 'file' not in request.files:
        return jsonify({'success': False, 'message': '请上传报告文件'}), 400

    report_title = request.form.get('report_title', '').strip()
    report_type = request.form.get('report_type', '').strip()
    target_id = request.form.get('target_id', 0, type=int)

    if not report_title:
        return jsonify({'success': False, 'message': '报告标题不能为空'}), 400
    if report_type not in ('attack', 'defense'):
        return jsonify({'success': False, 'message': '无效的报告类型，只支持attack或defense'}), 400

    target = AttackTarget.query.get(target_id)
    if not target:
        return jsonify({'success': False, 'message': '攻击目标不存在'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': '未选择文件'}), 400

    if not file.filename.lower().endswith('.pdf'):
        return jsonify({'success': False, 'message': '只支持PDF格式的报告'}), 400

    try:
        team = Team.query.get(user.team_id) if user.team_id else None
        team_name = team.team_name if team else user.username
        timestamp = int(datetime.now().timestamp())
        safe_title = report_title[:30].replace(' ', '_').replace('/', '_')
        filename = f"{team_name}_{timestamp}_{safe_title}.pdf"
        filepath = os.path.join(UPLOAD_DIR, filename)
        file.save(filepath)

        report = Report(
            reporter_id=user_id,
            report_type=report_type,
            target_id=target_id,
            report_title=report_title,
            file_path=filepath,
            file_name=filename,
            status='pending'
        )
        db.session.add(report)
        db.session.commit()

        log_operation('attack' if report_type == 'attack' else 'system',
                      f'用户 {user.username} 提交了{report_type}报告: {report_title}',
                      'low', user_id, user.team_id)

        return jsonify({
            'success': True,
            'message': '报告提交成功',
            'report_id': report.id
        })
    except Exception as e:
        print(f"提交报告失败: {e}")
        db.session.rollback()
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'success': False, 'message': '报告提交失败'}), 500


@awd_bp.route('/api/reports/my', methods=['GET'])
def get_my_reports():
    """获取当前用户的报告"""
    user_id, error = login_required()
    if error:
        return error

    try:
        reports = Report.query.filter_by(reporter_id=user_id).order_by(Report.created_at.desc()).all()
        return jsonify({
            'success': True,
            'reports': [{
                'id': r.id,
                'report_type': r.report_type,
                'target_id': r.target_id,
                'target_name': r.target.asset_name if r.target else None,
                'report_title': r.report_title,
                'file_name': r.file_name,
                'status': r.status,
                'score': r.score,
                'review_reason': r.review_reason,
                'created_at': r.created_at.isoformat() if r.created_at else None,
                'reviewed_at': r.reviewed_at.isoformat() if r.reviewed_at else None
            } for r in reports]
        })
    except Exception as e:
        print(f"获取我的报告失败: {e}")
        return jsonify({'success': False, 'message': '获取报告失败'}), 500


@awd_bp.route('/api/reports/pending', methods=['GET'])
def get_pending_reports():
    """获取待审核的报告（评委专用）"""
    user_id, error = judge_required()
    if error:
        return error

    try:
        reports = Report.query.filter_by(status='pending').order_by(Report.created_at.asc()).all()
        
        # 统计各状态数量
        pending_count = Report.query.filter_by(status='pending').count()
        approved_count = Report.query.filter_by(status='approved').count()
        rejected_count = Report.query.filter_by(status='rejected').count()
        
        return jsonify({
            'success': True,
            'pending_count': pending_count,
            'approved_count': approved_count,
            'rejected_count': rejected_count,
            'reports': [{
                'id': r.id,
                'report_type': r.report_type,
                'target_id': r.target_id,
                'target_name': r.target.asset_name if r.target else None,
                'target_info': r.target.target_info if r.target else None,
                'report_title': r.report_title,
                'file_name': r.file_name,
                'reporter_name': r.reporter.nickname if r.reporter else None,
                'reporter_team': r.reporter.team.team_name if r.reporter and r.reporter.team else None,
                'status': r.status,
                'created_at': r.created_at.isoformat() if r.created_at else None
            } for r in reports]
        })
    except Exception as e:
        print(f"获取待审核报告失败: {e}")
        return jsonify({'success': False, 'message': '获取待审核报告失败'}), 500


@awd_bp.route('/api/reports/all', methods=['GET'])
def get_all_reports():
    """获取所有报告（评委专用，用于回看）"""
    user_id, error = judge_required()
    if error:
        return error

    try:
        status = request.args.get('status', '')
        report_type = request.args.get('type', '')
        
        query = Report.query
        
        if status:
            query = query.filter_by(status=status)
        if report_type:
            query = query.filter_by(report_type=report_type)
        
        reports = query.order_by(Report.created_at.desc()).all()
        
        return jsonify({
            'success': True,
            'reports': [{
                'id': r.id,
                'report_type': r.report_type,
                'target_name': r.target.asset_name if r.target else None,
                'report_title': r.report_title,
                'file_name': r.file_name,
                'reporter_name': r.reporter.nickname if r.reporter else None,
                'reporter_team': r.reporter.team.team_name if r.reporter and r.reporter.team else None,
                'status': r.status,
                'score': r.score,
                'review_reason': r.review_reason,
                'created_at': r.created_at.isoformat() if r.created_at else None,
                'reviewed_at': r.reviewed_at.isoformat() if r.reviewed_at else None
            } for r in reports]
        })
    except Exception as e:
        print(f"获取所有报告失败: {e}")
        return jsonify({'success': False, 'message': '获取报告失败'}), 500


@awd_bp.route('/api/reports/download_all', methods=['GET'])
def download_all_reports():
    """打包下载所有报告"""
    user_id, error = judge_required()
    if error:
        return error

    try:
        import zipfile
        import io
        
        reports = Report.query.all()
        
        # 创建临时zip文件
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for report in reports:
                if report.file_path and os.path.exists(report.file_path):
                    # 确定文件夹名称
                    team_type = '红队' if report.report_type == 'attack' else '蓝队'
                    if report.status == 'approved':
                        folder = f"已通过/{team_type}"
                    elif report.status == 'rejected':
                        folder = f"已驳回/{team_type}"
                    else:
                        folder = f"待审核/{team_type}"
                    
                    # 添加文件到zip
                    zip_file.write(report.file_path, f"{folder}/{report.file_name}")
        
        zip_buffer.seek(0)
        
        log_operation('system', f'评委下载了所有报告打包', 'low', user_id)
        
        return send_file(
            zip_buffer,
            mimetype='application/zip',
            as_attachment=True,
            download_name='所有报告.zip'
        )
    except Exception as e:
        print(f"打包下载报告失败: {e}")
        return jsonify({'success': False, 'message': '下载失败'}), 500


@awd_bp.route('/api/reports/<int:report_id>', methods=['GET'])
def get_report_detail(report_id):
    """获取报告详情"""
    user_id, error = login_required()
    if error:
        return error

    try:
        report = Report.query.get(report_id)
        if not report:
            return jsonify({'success': False, 'message': '报告不存在'}), 404

        user = User.query.get(user_id)
        if user.role not in ('admin', 'judge') and report.reporter_id != user_id:
            return jsonify({'success': False, 'message': '无权查看该报告'}), 403

        return jsonify({
            'success': True,
            'report': {
                'id': report.id,
                'report_type': report.report_type,
                'target_id': report.target_id,
                'target_name': report.target.asset_name if report.target else None,
                'target_info': report.target.target_info if report.target else None,
                'report_title': report.report_title,
                'file_name': report.file_name,
                'reporter_id': report.reporter_id,
                'reporter_name': report.reporter.nickname if report.reporter else None,
                'reporter_team': report.reporter.team.team_name if report.reporter and report.reporter.team else None,
                'status': report.status,
                'score': report.score,
                'review_reason': report.review_reason,
                'reviewer_id': report.reviewer_id,
                'reviewer_name': report.reviewer.nickname if report.reviewer else None,
                'created_at': report.created_at.isoformat() if report.created_at else None,
                'reviewed_at': report.reviewed_at.isoformat() if report.reviewed_at else None
            }
        })
    except Exception as e:
        print(f"获取报告详情失败: {e}")
        return jsonify({'success': False, 'message': '获取报告详情失败'}), 500


@awd_bp.route('/api/reports/<int:report_id>/review', methods=['POST'])
def review_report(report_id):
    """评委审核报告"""
    user_id, error = judge_required()
    if error:
        return error

    data = request.json
    action = data.get('action', '')
    score = data.get('score', 0)
    reason = data.get('reason', '')

    if action not in ('approve', 'reject'):
        return jsonify({'success': False, 'message': '无效的审核操作'}), 400

    if action == 'approve':
        if not isinstance(score, int) or score <= 0:
            return jsonify({'success': False, 'message': '分数必须是正整数'}), 400

    try:
        report = Report.query.get(report_id)
        if not report:
            return jsonify({'success': False, 'message': '报告不存在'}), 404

        if report.status != 'pending':
            return jsonify({'success': False, 'message': '该报告已被审核，无法再次审核'}), 400

        report.status = 'approved' if action == 'approve' else 'rejected'
        report.score = score if action == 'approve' else 0
        report.review_reason = reason
        report.reviewer_id = user_id
        report.reviewed_at = datetime.now()

        if action == 'approve' and score > 0:
            reporter = User.query.get(report.reporter_id)
            if reporter:
                reporter.total_score += score
                if reporter.team_id:
                    team = Team.query.get(reporter.team_id)
                    if team:
                        team.total_score += score

        db.session.commit()

        log_operation('system',
                      f'评委审核了报告: {report.report_title} - {report.status}',
                      'low', user_id)

        # 通过WebSocket广播报告审核事件
        try:
            from app import socketio
            socketio.emit('report_reviewed', {
                'report_id': report.id,
                'report_type': report.report_type,
                'report_title': report.report_title,
                'reporter_team': report.reporter.team.team_name if report.reporter and report.reporter.team else None,
                'status': report.status,
                'score': report.score
            })
        except Exception as e:
            print(f"广播审核事件失败: {e}")

        return jsonify({
            'success': True,
            'message': f'报告已{("通过" if action == "approve" else "驳回")}',
            'status': report.status,
            'score': report.score
        })
    except Exception as e:
        print(f"审核报告失败: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': '审核报告失败'}), 500


@awd_bp.route('/api/reports/<int:report_id>/download', methods=['GET'])
def download_report(report_id):
    """下载报告PDF"""
    user_id, error = login_required()
    if error:
        return error

    try:
        report = Report.query.get(report_id)
        if not report:
            return jsonify({'success': False, 'message': '报告不存在'}), 404

        user = User.query.get(user_id)
        if user.role not in ('admin', 'judge') and report.reporter_id != user_id:
            return jsonify({'success': False, 'message': '无权下载该报告'}), 403

        if not report.file_name or not os.path.exists(report.file_path):
            return jsonify({'success': False, 'message': '报告文件不存在'}), 404

        return send_from_directory(
            UPLOAD_DIR,
            report.file_name,
            as_attachment=True,
            download_name=report.file_name
        )
    except Exception as e:
        print(f"下载报告失败: {e}")
        return jsonify({'success': False, 'message': '下载报告失败'}), 500


# =============================================================================
# 5. AWD排行榜
# =============================================================================

@awd_bp.route('/api/awd/rankings', methods=['GET'])
def get_awd_rankings():
    """获取AWD双排行榜（攻击队和防守队）"""
    user_id, error = login_required()
    if error:
        return error

    try:
        # 根据用户角色确定哪些队伍是攻击队，哪些是防守队
        attacker_team_ids = [r[0] for r in db.session.query(User.team_id).filter_by(role='attacker').distinct().all() if r[0]]
        defender_team_ids = [r[0] for r in db.session.query(User.team_id).filter_by(role='defender').distinct().all() if r[0]]
        
        # 获取队伍详情
        all_teams = Team.query.order_by(Team.total_score.desc()).all()
        
        attack_teams = []
        defense_teams = []
        
        for team in all_teams:
            team_data = {
                'id': team.id,
                'team_name': team.team_name,
                'team_icon': team.team_icon,
                'total_score': team.total_score or 0,
                'member_count': team.member_count or 0
            }
            
            if team.id in attacker_team_ids:
                attack_teams.append(team_data)
            elif team.id in defender_team_ids:
                defense_teams.append(team_data)

        return jsonify({
            'success': True,
            'attack_rankings': attack_teams,
            'defense_rankings': defense_teams
        })
    except Exception as e:
        print(f"获取AWD排行榜失败: {e}")
        return jsonify({'success': False, 'message': '获取排行榜失败'}), 500


@awd_bp.route('/api/awd/rankings/public', methods=['GET'])
def get_awd_rankings_public():
    """获取AWD双排行榜（公开接口，无需登录）"""
    try:
        attacker_team_ids = [r[0] for r in db.session.query(User.team_id).filter_by(role='attacker').distinct().all() if r[0]]
        defender_team_ids = [r[0] for r in db.session.query(User.team_id).filter_by(role='defender').distinct().all() if r[0]]
        
        all_teams = Team.query.order_by(Team.total_score.desc()).all()
        
        attack_teams = []
        defense_teams = []
        
        for team in all_teams:
            team_data = {
                'id': team.id,
                'team_name': team.team_name,
                'team_icon': team.team_icon,
                'total_score': team.total_score or 0,
                'member_count': team.member_count or 0
            }
            
            if team.id in attacker_team_ids:
                attack_teams.append(team_data)
            elif team.id in defender_team_ids:
                defense_teams.append(team_data)

        return jsonify({
            'success': True,
            'attack_rankings': attack_teams,
            'defense_rankings': defense_teams
        })
    except Exception as e:
        print(f"获取AWD排行榜失败: {e}")
        return jsonify({'success': True, 'attack_rankings': [], 'defense_rankings': []})


# =============================================================================
# 6. 用户删除管理
# =============================================================================

@awd_bp.route('/api/admin/delete_all_defenders', methods=['DELETE'])
def delete_all_defenders():
    """删除所有蓝队（防守方）用户"""
    user_id, error = admin_required()
    if error:
        return error

    try:
        deleted_count = User.query.filter_by(role='defender').delete()
        db.session.commit()
        log_operation('system', f'管理员删除了 {deleted_count} 个蓝队用户', 'medium', user_id)
        return jsonify({'success': True, 'message': f'已删除 {deleted_count} 个蓝队用户'})
    except Exception as e:
        print(f"删除蓝队用户失败: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': '删除失败'}), 500


@awd_bp.route('/api/admin/delete_all_judges', methods=['DELETE'])
def delete_all_judges():
    """删除所有裁判用户"""
    user_id, error = admin_required()
    if error:
        return error

    try:
        deleted_count = User.query.filter_by(role='judge').delete()
        db.session.commit()
        log_operation('system', f'管理员删除了 {deleted_count} 个裁判用户', 'medium', user_id)
        return jsonify({'success': True, 'message': f'已删除 {deleted_count} 个裁判用户'})
    except Exception as e:
        print(f"删除裁判用户失败: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': '删除失败'}), 500


@awd_bp.route('/api/admin/delete_user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    """删除单个用户"""
    user_id_req, error = admin_required()
    if error:
        return error

    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'message': '用户不存在'}), 404
        
        username = user.username
        db.session.delete(user)
        db.session.commit()
        log_operation('system', f'管理员删除了用户: {username}', 'low', user_id_req)
        return jsonify({'success': True, 'message': f'用户 {username} 已删除'})
    except Exception as e:
        print(f"删除用户失败: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': '删除失败'}), 500


@awd_bp.route('/api/admin/export_accounts', methods=['GET'])
def export_all_accounts():
    """导出所有账号信息为xlsx"""
    user_id, error = admin_required()
    if error:
        return error

    try:
        import openpyxl

        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = '账号信息'

        headers = ['用户名', '密码', '角色', '昵称', '积分', '状态']
        ws.append(headers)

        role_names = {
            'admin': '管理员',
            'red_team': '红队',
            'judge': '裁判',
            'attacker': '攻击方',
            'defender': '防守方'
        }

        users = User.query.all()
        for user in users:
            ws.append([
                user.username,
                user.password,
                role_names.get(user.role, user.role),
                user.nickname or '',
                user.total_score or 0,
                '活跃' if user.is_active else '禁用'
            ])

        for col in ws.columns:
            max_length = 0
            column_letter = col[0].column_letter
            for cell in col:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(str(cell.value))
                except:
                    pass
            ws.column_dimensions[column_letter].width = min(max_length + 2, 50)

        output = BytesIO()
        wb.save(output)
        output.seek(0)

        log_operation('system', f'管理员导出了 {len(users)} 个账号信息', 'low', user_id)

        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name='账号信息.xlsx'
        )
    except Exception as e:
        print(f"导出账号失败: {e}")
        return jsonify({'success': False, 'message': '导出失败'}), 500


# =============================================================================
# 注册蓝图的函数（在app.py中调用）
# =============================================================================

def register_awd_routes(app):
    """注册AWD路由蓝图"""
    app.register_blueprint(awd_bp)
    print("AWD模式路由已注册")
