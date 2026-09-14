// 全局变量
let socket = null;

// 工具函数
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `fixed top-4 right-4 p-4 rounded-lg shadow-lg z-50 ${type === 'success' ? 'bg-green-600' :
        type === 'error' ? 'bg-red-600' : type === 'warning' ? 'bg-yellow-600' : 'bg-blue-600'} text-white`;
    notification.innerHTML = `
        <div class="flex items-center">
            <i class="fas ${type === 'success' ? 'fa-check-circle' :
            type === 'error' ? 'fa-exclamation-circle' :
                type === 'warning' ? 'fa-exclamation-triangle' : 'fa-info-circle'} mr-2"></i>
            <span>${message}</span>
        </div>
    `;
    document.body.appendChild(notification);
    setTimeout(() => notification.remove(), 3000);
}

function formatTime(timestamp) {
    return new Date(timestamp).toLocaleString('zh-CN');
}

// 认证相关函数
async function logout() {
    try {
        await axios.post('/api/logout');
        window.location.href = '/';
    } catch (error) {
        console.error('Logout error:', error);
        window.location.href = '/';
    }
}

async function checkAuth() {
    try {
        const response = await axios.get('/api/check_auth');
        if (response.data.authenticated && socket) {
            socket.emit('associate_user');
            console.log('User authenticated, sending associate event');
        }
        return response.data;
    } catch (error) {
        return { authenticated: false };
    }
}

// WebSocket连接
function connectWebSocket() {
    try {
        socket = io({
            transports: ['websocket', 'polling'],
            upgrade: true,
            timeout: 10000
        });

        socket.on('connect', () => {
            console.log('WebSocket connected');
            updateWebSocketStatus(true);
            sendUserInfo();
        });

        socket.on('disconnect', (reason) => {
            console.log('WebSocket disconnected:', reason);
            updateWebSocketStatus(false);
            setTimeout(connectWebSocket, 3000);
        });

        socket.on('connect_error', (error) => {
            console.log('WebSocket connection error:', error);
            updateWebSocketStatus(false);
        });

        socket.on('score_update', (data) => {
            console.log('Score update received:', data);
            window.dispatchEvent(new CustomEvent('scoreUpdate', { detail: data }));
        });

        socket.on('log_update', (data) => {
            console.log('Log update received:', data);
            window.dispatchEvent(new CustomEvent('logUpdate', { detail: data }));
        });

        socket.on('report_reviewed', (data) => {
            console.log('Report reviewed:', data);
            window.dispatchEvent(new CustomEvent('reportReviewed', { detail: data }));
        });

    } catch (error) {
        console.error('WebSocket initialization error:', error);
        updateWebSocketStatus(false);
    }
}

// 发送用户信息到WebSocket
function sendUserInfo() {
    checkAuth().then(authData => {
        if (authData.authenticated && socket) {
            socket.emit('associate_user', {});
            console.log('Associate user event sent:', authData.user.id);
        }
    });
}

function updateWebSocketStatus(connected) {
    const statusElement = document.getElementById('websocketStatus');
    if (statusElement) {
        if (connected) {
            statusElement.innerHTML = '<i class="fas fa-circle mr-1"></i>已连接';
            statusElement.className = 'text-green-400';
        } else {
            statusElement.innerHTML = '<i class="fas fa-circle mr-1"></i>断开';
            statusElement.className = 'text-red-400';
        }
    }
}

// 头像上传功能
async function uploadAvatar(file) {
    if (!file) return;

    const allowedTypes = ['image/png', 'image/jpeg', 'image/gif'];
    if (!allowedTypes.includes(file.type)) {
        showNotification('只支持PNG、JPG、JPEG、GIF格式的图片', 'error');
        return;
    }

    if (file.size > 2 * 1024 * 1024) {
        showNotification('头像文件大小不能超过2MB', 'error');
        return;
    }

    const formData = new FormData();
    formData.append('avatar', file);

    try {
        const response = await axios.post('/api/user/avatar', formData, {
            headers: {
                'Content-Type': 'multipart/form-data'
            }
        });

        if (response.data.success) {
            showNotification('头像上传成功', 'success');
            updateAvatarDisplay(response.data.avatar_url);
        } else {
            showNotification(response.data.message || '头像上传失败', 'error');
        }
    } catch (error) {
        console.error('头像上传失败:', error);
        showNotification('头像上传失败', 'error');
    }
}

function updateAvatarDisplay(avatarUrl) {
    const avatarImage = document.getElementById('avatarImage');
    const avatarIcon = document.getElementById('avatarIcon');
    const avatarContainer = document.getElementById('avatarContainer');

    if (avatarImage) {
        avatarImage.src = avatarUrl + '?t=' + new Date().getTime();
    } else {
        const newAvatarImage = document.createElement('img');
        newAvatarImage.src = avatarUrl + '?t=' + new Date().getTime();
        newAvatarImage.alt = '头像';
        newAvatarImage.className = 'w-full h-full object-cover';
        newAvatarImage.id = 'avatarImage';

        if (avatarIcon) {
            avatarIcon.remove();
        }
        avatarContainer.appendChild(newAvatarImage);
    }
}

// 工具函数
function getLogTypeIcon(logType) {
    const iconMap = {
        'login': 'fa-sign-in-alt',
        'attack': 'fa-bolt',
        'system': 'fa-cog',
        'error': 'fa-exclamation-triangle',
        'success': 'fa-check-circle',
        'warning': 'fa-exclamation-circle',
        'network': 'fa-network-wired',
        'file_integrity': 'fa-file-shield',
        'malware_detection': 'fa-virus'
    };
    return iconMap[logType] || 'fa-file-alt';
}

function getSeverityColor(severity) {
    const colorMap = {
        'low': 'text-green-400',
        'medium': 'text-yellow-400',
        'high': 'text-red-400',
        'critical': 'text-red-600'
    };
    return colorMap[severity] || 'text-gray-400';
}

// 页面初始化
document.addEventListener('DOMContentLoaded', function () {
    connectWebSocket();

    // 每5秒检查一次并发送用户信息
    setInterval(sendUserInfo, 5000);

    // 监听全局事件
    window.addEventListener('scoreUpdate', function (event) {
        console.log('Score update event received');
    });

    window.addEventListener('logUpdate', function (event) {
        console.log('Log update event received');
    });
});