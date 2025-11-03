-- 实时攻防平台数据库设计
-- 主题：红黑色调攻防平台

-- 创建数据库
CREATE DATABASE IF NOT EXISTS Red_Game CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE Red_Game;

-- 首先创建不依赖其他表的队伍表
CREATE TABLE teams (
    id INT PRIMARY KEY AUTO_INCREMENT,
    team_name VARCHAR(100) UNIQUE NOT NULL,
    team_icon VARCHAR(255),
    total_score INT DEFAULT 0,
    member_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- 然后创建用户表（引用队伍表）
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role ENUM('admin', 'red_team') DEFAULT 'red_team',
    team_id INT,
    nickname VARCHAR(100),
    avatar VARCHAR(255),
    total_score INT DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE SET NULL
);

-- 比赛表（引用用户表）
CREATE TABLE competitions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    background_story TEXT,
    theme_image VARCHAR(255),
    start_time DATETIME,
    end_time DATETIME,
    is_active BOOLEAN DEFAULT FALSE,
    is_ended BOOLEAN DEFAULT FALSE,
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);

-- 靶标表（引用比赛表）
CREATE TABLE targets (
    id INT PRIMARY KEY AUTO_INCREMENT,
    competition_id INT NOT NULL,
    name VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    flag VARCHAR(255) NOT NULL,
    points INT NOT NULL DEFAULT 100,
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (competition_id) REFERENCES competitions(id) ON DELETE CASCADE
);

-- Flag提交记录表（引用用户表和靶标表）
-- 修改Flag提交记录表，确保target_id不为NULL
CREATE TABLE flag_submissions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    target_id INT NOT NULL,  -- 改为 NOT NULL
    submitted_flag VARCHAR(255) NOT NULL,
    is_correct BOOLEAN DEFAULT FALSE,
    points_earned INT DEFAULT 0,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);

-- 积分记录表（引用用户表和队伍表）
CREATE TABLE score_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    team_id INT,
    action_type ENUM('flag_submission', 'bonus', 'penalty') DEFAULT 'flag_submission',
    points INT NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE SET NULL
);

-- 系统日志表（引用队伍表和用户表）
CREATE TABLE system_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    log_type ENUM('login', 'attack', 'system', 'error', 'success', 'warning', 'network', 'file_integrity', 'malware_detection') DEFAULT 'system',    
    source_ip VARCHAR(45),
    target_ip VARCHAR(45),
    message TEXT NOT NULL,
    severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    team_id INT,
    user_id INT,
    raw_data JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE SET NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- 攻击流量日志表（引用队伍表）
CREATE TABLE attack_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    team_id INT NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    target_ip VARCHAR(45) NOT NULL,
    attack_type VARCHAR(50),
    traffic_volume INT DEFAULT 0,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE
);

-- 靶标状态表（引用靶标表）
CREATE TABLE target_status (
    id INT PRIMARY KEY AUTO_INCREMENT,
    target_id INT,
    is_online BOOLEAN DEFAULT TRUE,
    is_compromised BOOLEAN DEFAULT FALSE,
    last_check TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);

-- 创建索引
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_team_id ON users(team_id);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_flag_submissions_user_id ON flag_submissions(user_id);
CREATE INDEX idx_flag_submissions_target_id ON flag_submissions(target_id);
CREATE INDEX idx_score_logs_user_id ON score_logs(user_id);
CREATE INDEX idx_score_logs_team_id ON score_logs(team_id);
CREATE INDEX idx_system_logs_created_at ON system_logs(created_at);
CREATE INDEX idx_system_logs_log_type ON system_logs(log_type);
CREATE INDEX idx_attack_logs_team_id ON attack_logs(team_id);
CREATE INDEX idx_attack_logs_timestamp ON attack_logs(timestamp);

-- 插入默认管理员账户（密码：godxing）
INSERT INTO users (username, password, email, role, nickname) VALUES 
('admin', 'godxing', '1848210202@qq.com', 'admin', '系统管理员');

-- 创建视图：实时积分榜
CREATE VIEW real_time_rankings AS
SELECT 
    t.id,
    t.team_name,
    t.team_icon,
    t.total_score,
    COUNT(DISTINCT u.id) as member_count,
    MAX(fs.submitted_at) as last_submission,
    RANK() OVER (ORDER BY t.total_score DESC) as rank_position
FROM teams t
LEFT JOIN users u ON t.id = u.team_id AND u.role = 'red_team'
LEFT JOIN flag_submissions fs ON fs.user_id IN (SELECT id FROM users WHERE team_id = t.id)
WHERE t.member_count > 0
GROUP BY t.id, t.team_name, t.team_icon, t.total_score
ORDER BY t.total_score DESC;

-- 创建视图：用户积分详情
CREATE VIEW user_score_details AS
SELECT 
    u.id,
    u.username,
    u.nickname,
    u.avatar,
    u.total_score,
    t.team_name,
    t.team_icon,
    COUNT(DISTINCT fs.target_id) as targets_completed,
    MAX(fs.submitted_at) as last_submission
FROM users u
LEFT JOIN teams t ON u.team_id = t.id
LEFT JOIN flag_submissions fs ON u.id = fs.user_id AND fs.is_correct = TRUE
WHERE u.role = 'red_team' AND u.is_active = TRUE
GROUP BY u.id, u.username, u.nickname, u.avatar, u.total_score, t.team_name, t.team_icon
ORDER BY u.total_score DESC;