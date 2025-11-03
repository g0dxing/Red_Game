# 红色竞赛实时攻防平台 (Red_Game)
"蓝的世界于凌晨两点沉入梦境，红的天地在此刻悄然迎来黎明。"

## 平台介绍

红色竞赛实时攻防平台平台,一个为网络安全竞赛打造的、具备实时攻防态势感知能力的红蓝对抗平台。一个功能完整的网络安全攻防演练平台，采用红黑色调主题设计，支持实时态势感知、队伍管理、靶标部署、成绩统计等完整功能。

## 🎯 功能特性

### 核心功能
- **实时态势感知** - 动态显示攻击流量、队伍排名、系统日志
- **队伍管理** - 批量创建账户、队伍重命名、成员管理
- **比赛管理** - 创建比赛、设置靶标、时间控制
- **Flag提交** - 支持多种Flag格式，实时积分更新
- **日志收集** - 被动式日志收集Agent，支持多种监控类型

### 技术特色
- **红黑色调主题** - 专业的网络安全视觉设计
- **实时数据更新** - WebSocket + Socket.IO 实现实时通信
- **响应式设计** - 支持桌面和移动设备
- **模块化架构** - 前后端分离，易于扩展

## 🛠️ 技术栈

| 层面     | 技术选型                                        |
| :------- | :---------------------------------------------- |
| **后端** | Python 3.8+, Flask, SQLAlchemy, MySQL           |
| **前端** | 原生HTML/CSS/JS, Tailwind CSS, Socket.IO Client |
| **监控** | 自定义Python Agent, Watchdog                    |



## 📁 项目结构

```
Red_Game/
├── app.py                    # 主应用程序
├── database_schema.sql       # 数据库结构
├── index.html                # 首页
├── templates/                # HTML模板
│   ├── base.html            # 基础模板
│   ├── index.html           # 首页
│   ├── login.html           # 登录页
│   ├── admin.html           # 管理面板
│   ├── dashboard.html       # 用户面板
│   └── situation.html       # 实时态势大屏
├── static/                   # 静态文件
│   ├── uploads/             # 头像存储目录（功能待开发）
├── 日志收集探针/             # 存放日志收集探针脚本及其配置文件
│   ├── log_agent.py         # 日志收集Agent
│   ├── agent_config.json    # Agent配置文件及其模板
│   ├── agent_config.json.example
│   ├── requirements.txt     # Agent脚本python依赖
├── README.md                 # 项目文档
└── requirements.txt          # python依赖项
```

## 📸 平台功能展示

### 🖥️ 系统功能
<div align="center">

| 实时态势大屏 | 首页功能 | 系统设置 |
|:---:|:---:|:---:|
| <img src="images/taishidaping.png" width="250" alt="实时态势大屏"> | <img src="images/index2.png" width="250" alt="首页功能"> | <img src="images/xitongshezhi.png" width="250" alt="系统设置"> |
| **攻防态势可视化** | **完整功能展示** | **系统参数配置** |

</div>


### 🏠 用户界面
<div align="center">

| 登录页面 | 红队首页 | 首页展示 |
|:---:|:---:|:---:|
| <img src="images/login.png" width="250" alt="登录页面"> | <img src="images/hongduishouye.png" width="250" alt="红队首页"> | <img src="images/index1.png" width="250" alt="首页展示"> |
| **统一身份认证** | **红队操作面板** | **平台首页概览** |

</div>

### 🎯 比赛管理
<div align="center">

| 比赛管理 | 比赛设置 | 比赛控制 |
|:---:|:---:|:---:|
| <img src="images/bisaiguanli.png" width="250" alt="比赛管理"> | <img src="images/bisaiguanli1.png" width="250" alt="比赛设置"> | <img src="images/bisaiguanli2.png" width="250" alt="比赛控制"> |
| **比赛信息管理** | **详细参数设置** | **比赛进程控制** |

</div>

### 👥 队伍管理
<div align="center">

| 队伍管理 | 成员管理 | 批量操作 |
|:---:|:---:|:---:|
| <img src="images/duiwuguanli1.png" width="250" alt="队伍管理"> | <img src="images/duiwuguanli2.png" width="250" alt="成员管理"> | <img src="images/babiaoguanli.png" width="250" alt="靶标管理"> |
| **队伍信息维护** | **成员信息管理** | **靶标部署管理** |

</div>




## 🚀 快速开始

### 环境要求
- Python 3.8+
- MySQL 5.7+
- Node.js 14+ (用于前端依赖)

### 安装步骤

1. **克隆或下载项目**
```bash
git clone https://github.com/g0dxing/Red_Game.git
cd Red_Game
```

2. **安装Python依赖**
```bash
pip install -r requirements.txt
```

3. **配置数据库**
```bash
# 创建数据库
mysql -u root -p < database_schema.sql
```

4. **启动应用**
```bash
python app.py
```

5. **访问平台**
- 主页: http://localhost:5000
- 默认管理员账户: admin / godxing

### 日志收集Agent使用

1. **配置Agent**
```bash
cp agent_config.json.example agent_config.json
# 编辑配置文件
vim agent_config.json
```

2. 将`日志收集探针`文件夹上传至已经部署好的靶机中。

3. **启动Agent**
```bash
pip install -r requirements.txt
python log_agent.py
```

## 📊 功能模块

### 1. 用户认证
- 支持管理员和红队成员两种角色
- Session-based认证机制

### 2. 管理员功能
- **批量创建队伍**: 一键生成多个队伍和账户、一键删除所有帐号功能。
- **比赛管理**: 创建比赛、设置靶标、自定义flag、控制时间
- **用户管理**: 查看、删除用户，查看、修改队伍名称
- **系统监控**: 查看系统状态和日志


### 3. 红队成员功能
- **Flag提交**: 支持标准Flag格式
- **积分查看**: 实时查看个人和队伍积分
- **个人信息管理**: 修改昵称、邮箱
- **队伍管理**: 重命名队伍

### 4. 实时态势大屏
- **攻击流量图**: 网络拓扑式攻击可视化
- **实时排行榜**: 队伍积分动态排名
- **日志流**: 实时系统日志显示
- **全屏模式**: 支持大屏展示

### 5. 日志收集系统
- **被动收集**: Agent定时发送日志数据
- **多类型监控**: 登录、攻击、系统、错误日志
- **文件完整性**: 监控文件篡改
- **网络监控**: 检测异常连接
- **简易安全监控** - 常见简单攻击可以识别，如：sql注入、目录爆破


## 🔧 配置说明

### 数据库配置
在 `app.py` 中修改数据库连接：
```python
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://username:password@localhost/Red_Game'
```

### Agent配置
在 `agent_config.json` 中配置监控项：
```json
{
  "platform_url": "http://localhost:5000/api/logs/collect", //平台地址
  "target_id": "target_web_001",                            //靶机id
  "log_sources": {
    "web_access": {
      "enabled": true,
      "log_file": "/var/log/apache2/access.log"
    }
  }
}
```

## 🎨 主题定制

平台采用红黑色调主题，可通过修改CSS变量自定义颜色：
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

- **SQL注入防护**: ORM框架自动防护
- **XSS防护**: 前端输入过滤和转义
- **CSRF防护**: Session-based认证
- **权限控制**: 基于角色的访问控制

## 📈 性能优化

- **数据库索引**: 关键字段建立索引
- **缓存机制**: 实时数据缓存优化
- **WebSocket**: 减少HTTP轮询开销
- **前端优化**: 最小化DOM操作

## 🤝 贡献指南
此项目由作者本人及两位学生共同开发测试，kimi OK Computer搭建雏形、deepseek进行修改优化。
欢迎提交Issue和Pull Request来改进项目。

## 📞 联系方式

如有问题或建议，欢迎联系：
- 项目维护者: [g0dxing]
- 邮箱: [1848210202@qq.com]
- 项目地址: [https://github.com/g0dxing/Red_Game.git]


---

# **⚠️ 商用声明**: 商业活动请联系作者，有点钱作者就能给你当牛马。10RMB为您打造定制化平台。



[![GitHub stars](https://img.shields.io/github/stars/g0dxing/Red_Game?style=for-the-badge)](https://github.com/g0dxing/Red_Game/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/g0dxing/Red_Game?style=for-the-badge)](https://github.com/g0dxing/Red_Game/network/members)
[![GitHub issues](https://img.shields.io/github/issues/g0dxing/Red_Game?style=for-the-badge)](https://github.com/g0dxing/Red_Game/issues)
[![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge)](https://www.python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](https://opensource.org/licenses/MIT)

[![GitHub Stats](https://github-readme-stats.vercel.app/api?username=g0dxing&show_icons=true&theme=radical)](https://github.com/g0dxing/Red_Game)