# 实时攻防平台 (python攻防平台)

一个功能完整的网络安全攻防演练平台，采用红黑色调主题设计，支持实时态势感知、队伍管理、靶标部署、成绩统计等完整功能。

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

### 后端
- **Python 3.8+** - 后端开发语言
- **Flask** - Web框架
- **Flask-SocketIO** - 实时通信
- **SQLAlchemy** - ORM框架
- **MySQL** - 数据库

### 前端
- **原生HTML/CSS/JS** - 无框架依赖
- **Tailwind CSS** - 样式框架
- **Font Awesome** - 图标库
- **Socket.IO Client** - 实时通信
- **Axios** - HTTP客户端

### 监控组件
- **日志收集Agent** - Python编写的被动式日志收集
- **文件完整性监控** - 基于watchdog的文件监控
- **网络连接监控** - 实时网络流量分析
- **系统资源监控** - CPU、内存、磁盘使用率


## 📁 项目结构

```
python攻防平台/
├── app.py                # 主应用程序
├── log_agent.py          # 日志收集Agent
├── agent_config.json     # Agent配置文件
├── database_schema.sql   # 数据库结构
├── index.html            # 首页
├── templates/            # HTML模板
│   ├── base.html        # 基础模板
│   ├── index.html       # 首页
│   ├── login.html       # 登录页
│   ├── admin.html       # 管理面板
│   ├── dashboard.html   # 用户面板
│   └── situation.html   # 实时态势大屏
├── static/               # 静态文件
│   ├── uploads          # 头像存储目录（功能待开发）
├── README.md             # 项目文档
└── requirements.txt      # python依赖项
```

## 🚀 快速开始

### 环境要求
- Python 3.8+
- MySQL 5.7+
- Node.js 14+ (用于前端依赖)

### 安装步骤

1. **克隆或下载项目**
```bash
git clone <repository-url>
cd cyber-range-platform
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
- 管理员账户: admin / godxing

### 日志收集Agent使用

1. **配置Agent**
```bash
cp agent_config.json.example agent_config.json
# 编辑配置文件
vim agent_config.json
```

2. 将`log_agent.py`及其配置文件`agent_config.json`上传至已经部署好的靶机中

3. **启动Agent**
```bash
python log_agent.py
```

## 📊 功能模块

### 1. 用户认证
- 支持管理员和红队成员两种角色
- Session-based认证机制

### 2. 管理员功能
- **批量创建队伍**: 一键生成多个队伍和账户、一键删除所有帐号功能。
- **比赛管理**: 创建比赛、设置靶标、自定义flag、控制时间
- **用户管理**: 查看、删除用户账户
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
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://username:password@localhost/cyber_range_platform'
```

### Agent配置
在 `agent_config.json` 中配置监控项：
```json
{
  "platform_url": "http://localhost:5000/api/logs/collect",
  "target_id": "target_web_001",
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
- 项目维护者: [godxing]
- 邮箱: [1848210202@qq.com]
- 项目地址: [https://github.com/g0dxing/Offensive-and-defensive-platform]

---

**⚠️ 安全声明**: 本平台仅用于合法的网络安全教育和培训目的，请勿用于非法活动。
