# 红色竞赛实时攻防平台 (Red_Game)
"蓝的世界于凌晨两点沉入梦境，红的天地在此刻悄然迎来黎明。"

## 平台介绍

红色竞赛实时攻防平台，一个为网络安全竞赛打造的、具备实时攻防态势感知能力的红蓝对抗平台。支持**ATK模式**（传统Flag提交）和**AWD模式**（攻击/防守/裁判三方平台）两种比赛模式。

## 📸 平台功能展示

### 🎯 AWD模式

<div align="center">

| 比赛模式设置 | 队伍管理 | 目标管理 |
|:---:|:---:|:---:|
| <img src="images/awd_mode.png" width="250" alt="比赛模式设置"> | <img src="images/awd_teams.png" width="250" alt="队伍管理"> | <img src="images/awd_targets.png" width="250" alt="目标管理"> |
| **选择ATK或AWD模式** | **批量创建红队/蓝队/裁判** | **资产导入与归属设置** |

</div>

<div align="center">

| 目标归属设置 | 攻击方/防守方面板 | 实时态势大屏 |
|:---:|:---:|:---:|
| <img src="images/awd_assignment.png" width="250" alt="目标归属设置"> | <img src="images/dashboard_awd.png" width="250" alt="用户面板"> | <img src="images/situation_awd.png" width="250" alt="实时态势大屏"> |
| **配置队伍可访问的目标** | **提交报告与查看记录** | **三节点拓扑图（红队-服务器-蓝队）** |

</div>

### ⚖️ 裁判工作台

<div align="center">

| 报告列表 | 报告评审 |
|:---:|:---:|
| <img src="images/judge_panel.png" width="250" alt="裁判工作台"> | <img src="images/judge_review.png" width="250" alt="报告评审"> |
| **待审核/已通过/已驳回** | **查看详情、评分、驳回** |

</div>

### 🏠 ATK模式

<div align="center">

| 登录页面 | 用户面板 | 实时态势大屏 |
|:---:|:---:|:---:|
| <img src="images/login.png" width="250" alt="登录页面"> | <img src="images/hongduishouye.png" width="250" alt="用户面板"> | <img src="images/taishidaping.png" width="250" alt="实时态势大屏"> |
| **统一身份认证** | **Flag提交与积分查看** | **攻击流量可视化** |

</div>

### 🎯 管理面板

<div align="center">

| 比赛管理 | 队伍管理 | 靶标管理 |
|:---:|:---:|:---:|
| <img src="images/bisaiguanli.png" width="250" alt="比赛管理"> | <img src="images/duiwuguanli1.png" width="250" alt="队伍管理"> | <img src="images/babiaoguanli.png" width="250" alt="靶标管理"> |
| **创建比赛、时间控制** | **批量创建、成员管理** | **靶标部署与配置** |

</div>

## 🎯 功能特性

### 双模式支持

| 模式 | 说明 | 适用场景 |
|------|------|----------|
| **ATK模式** | 红队提交Flag获取积分 | 基础CTF竞赛 |
| **AWD模式** | 攻击/防守/裁判三方对抗，提交报告评审得分 | 攻防演练竞赛 |

### 核心功能

- **实时态势感知** - 动态显示攻击流量、队伍排名、系统日志
- **队伍管理** - 批量创建攻击队、防守队、裁判组
- **目标管理** - 导入xlsx、手动添加、归属设置
- **比赛管理** - 创建比赛、设置时间、自动结束
- **报告提交** - 攻击方/防守方提交PDF报告
- **裁判评审** - 审阅报告、通过/驳回、评分
- **日志收集** - 被动式日志收集Agent

### AWD模式特色

- **三方平台** - 攻击方、防守方、裁判组独立管理
- **报告评审** - 提交PDF报告，裁判审阅评分
- **目标归属** - 一个目标可归属多个攻击队和防守队
- **实时大屏** - 三节点拓扑图（红队-服务器-蓝队）
- **打包下载** - 一键导出所有报告

## 🛠️ 技术栈

| 层面 | 技术选型 |
| :--- | :--- |
| **后端** | Python 3.9+, Flask, SQLAlchemy, MySQL |
| **前端** | HTML/CSS/JS, Tailwind CSS, Socket.IO |
| **监控** | Python Agent, Watchdog |

## 📁 项目结构

```
Red_Game/
├── app.py                  # 主应用（ATK模式路由）
├── awd_routes.py           # AWD模式路由
├── database.py             # 数据库实例
├── models_all.py           # 所有数据库模型
├── database_schema.sql     # 数据库结构
├── requirements.txt        # Python依赖
├── templates/              # HTML模板
│   ├── base.html           # 基础模板
│   ├── login.html          # 登录页
│   ├── admin.html          # 管理面板
│   ├── dashboard.html      # 用户面板
│   ├── judge.html          # 裁判工作台
│   ├── situation.html      # 实时态势大屏
│   └── change_password.html
├── static/                 # 静态文件
│   ├── css/
│   ├── js/
│   └── uploads/
│       ├── reports/        # 报告PDF存储
│       └── avatars/        # 头像存储
├── 日志收集探针/             # Agent脚本
├── README.md
└── 更新日志.txt
```

## 🚀 快速开始

### 环境要求
- Python 3.9
- MySQL 5.7+

### 安装步骤

```bash
# 1. 克隆项目
git clone https://github.com/g0dxing/Red_Game.git
cd Red_Game

# 2. 安装依赖
pip install -r requirements.txt

# 3. 导入数据库
mysql -u root -p < database_schema.sql

# 4. 启动应用
python app.py
```

### 访问平台
- 主页: http://localhost:5000
- 默认管理员: admin / godxing

## 📊 功能模块

### 1. 管理面板

| 标签页 | 功能 |
|--------|------|
| **比赛模式** | 选择ATK或AWD模式 |
| **队伍管理** | 红队/蓝队/裁判组管理 |
| **目标管理** | 资产导入、归属设置 |
| **比赛管理** | 创建比赛、时间控制 |
| **系统日志** | 查看系统日志 |

### 2. AWD模式流程

```
1. 切换比赛模式为AWD
2. 批量创建红队、蓝队、裁判
3. 导入目标资产（xlsx或手动添加）
4. 设置目标归属（哪些队伍可攻击/防守）
5. 创建比赛并开始
6. 攻击方/防守方提交报告
7. 裁判审阅报告、评分
8. 排行榜实时更新
```

### 3. 裁判工作台

- 查看待审核/已通过/已驳回报告
- 审阅报告详情
- 通过并评分 / 驳回并填写原因
- 打包下载所有报告

### 4. 实时态势大屏

- **ATK模式**: 攻击方 → 靶标
- **AWD模式**: 攻击方 → 服务器 → 防守方
- 实时排行榜
- 日志流（含假数据模拟）
- 高危告警提示

### 5. 日志收集系统

- 被动收集: Agent定时发送日志
- 多类型监控: 登录、攻击、系统、错误日志
- 文件完整性: 监控文件篡改
- 网络监控: 检测异常连接

## 🔧 配置说明

### 数据库配置
在 `app.py` 中修改:
```python
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://username:password@localhost/Red_Game'
```

### Agent配置
```json
{
  "platform_url": "http://localhost:5000/api/logs/collect",
  "target_id": "target_web_001"
}
```

## 📝 账号命名规则

| 角色 | 前缀 | 示例 |
|------|------|------|
| 管理员 | - | admin |
| 红队 | rd | rd3847 |
| 蓝队 | bf | bf4821 |
| 裁判 | jd | jd0291 |

## 🎨 主题定制

```css
:root {
    --primary-red: #dc2626;
    --dark-red: #991b1b;
    --light-red: #ef4444;
    --primary-black: #0f0f0f;
    --secondary-black: #1a1a1a;
    --accent-gold: #f59e0b;
}
```

## 🔒 安全特性

- SQL注入防护: ORM框架自动防护
- XSS防护: 前端输入过滤和转义
- CSRF防护: Session-based认证
- 权限控制: 基于角色的访问控制

## 📈 性能优化

- 数据库索引: 关键字段建立索引
- 缓存机制: 实时数据缓存优化
- WebSocket: 减少HTTP轮询开销

## 📝 更新日志

### V4.0
- 新增AWD模式（攻击/防守/裁判三方平台）
- 新增报告提交与评审系统
- 新增目标资产管理和归属设置
- 新增裁判评审工作台
- 新增打包下载所有报告功能
- 大屏适配AWD模式（三节点拓扑图）
- 新增批量创建账号功能
- 优化实时日志流显示

### V3.3
- 实现完全本地化，可以断网使用

### V3.2
- 修复UTC时间问题
- 添加比赛自动结束功能

### V3.1
- 修改图标为保护伞公司图标
- 修改主页下划线为横线

## 🤝 贡献

欢迎提交Issue和Pull Request来改进项目。

## 📞 联系方式

- 项目维护者: [g0dxing]
- 邮箱: [1848210202@qq.com]
- 项目地址: [https://github.com/g0dxing/Red_Game.git]

---

**⚠️ 商用声明**: 商业活动请联系作者。

[![GitHub stars](https://img.shields.io/github/stars/g0dxing/Red_Game?style=for-the-badge)](https://github.com/g0dxing/Red_Game/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/g0dxing/Red_Game?style=for-the-badge)](https://github.com/g0dxing/Red_Game/network/members)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge)](https://www.python.org)
