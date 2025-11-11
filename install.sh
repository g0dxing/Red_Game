#!/bin/bash

# 获取脚本所在目录的绝对路径
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "脚本所在目录: $SCRIPT_DIR"

# 检查是否为root用户
if [ "$(id -u)" != "0" ]; then
    echo "错误: 此脚本必须以root权限运行"
    echo "请使用 sudo ./install.sh 重新运行"
    exit 1
fi

echo "开始安装Python 3.9和MariaDB..."

# 安装Python 3.9依赖
echo "安装Python 3.9编译依赖..."
apt-get update
apt-get install -y make build-essential libssl-dev zlib1g-dev libbz2-dev \
libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev \
xz-utils tk-dev libffi-dev liblzma-dev zlib1g-dev

# 创建Python安装目录
mkdir -p /opt/python

# 下载Python 3.9源码
echo "下载Python 3.9源码..."
cd /tmp
if [ ! -f "Python-3.9.11.tgz" ]; then
    # 使用不检查证书的方式下载
    wget --no-check-certificate https://www.python.org/ftp/python/3.9.11/Python-3.9.11.tgz
    if [ $? -ne 0 ]; then
        echo "下载失败，尝试备用镜像..."
        wget --no-check-certificate https://mirrors.sohu.com/python/3.9.11/Python-3.9.11.tgz
    fi
fi

# 检查下载是否成功
if [ ! -f "Python-3.9.11.tgz" ]; then
    echo "错误: 无法下载Python源码包"
    exit 1
fi

# 解压源码
echo "解压Python源码..."
tar -xzf Python-3.9.11.tgz

# 检查解压是否成功
if [ ! -d "Python-3.9.11" ]; then
    echo "错误: 解压Python源码失败"
    exit 1
fi

# 编译安装Python
echo "编译安装Python 3.9..."
cd /tmp/Python-3.9.11
./configure --enable-optimizations --prefix=/opt/python/python3.9
make -j$(nproc)
make install

# 检查编译是否成功
if [ ! -f "/opt/python/python3.9/bin/python3.9" ]; then
    echo "错误: Python编译安装失败"
    exit 1
fi

# 创建符号链接
echo "创建Python符号链接..."
ln -sf /opt/python/python3.9/bin/python3.9 /usr/local/bin/python3.9
ln -sf /opt/python/python3.9/bin/pip3.9 /usr/local/bin/pip3.9

# 安装pip
echo "安装pip..."
/opt/python/python3.9/bin/python3.9 -m ensurepip --upgrade

echo "Python 3.9安装完成!"

# 安装MariaDB
echo "安装MariaDB..."
apt-get install -y mariadb-server

# 启动MariaDB服务
echo "启动MariaDB服务..."
systemctl start mysql
systemctl enable mysql

# 检查MariaDB服务状态
echo "检查MariaDB服务状态..."
if systemctl is-active --quiet mysql; then
    echo "MariaDB服务运行正常"
else
    echo "警告: MariaDB服务未正常运行"
    # 尝试使用service命令
    service mysql start
    service mysql enable
fi

# 等待MySQL服务完全启动
echo "等待MySQL服务启动..."
sleep 5

# 配置MariaDB root密码 - 使用多种方法确保成功
echo "配置MariaDB root密码..."

# 方法1: 直接尝试设置密码
mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED BY 'root';" 2>/dev/null

# 方法2: 如果方法1失败，使用mysql_native_password插件
mysql -u root -e "USE mysql; UPDATE user SET plugin='mysql_native_password' WHERE User='root'; FLUSH PRIVILEGES;" 2>/dev/null

# 方法3: 使用mysql_secure_installation的自动化版本
echo "运行MySQL安全安装..."
mysql -u root -e "DELETE FROM mysql.user WHERE User='';"
mysql -u root -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
mysql -u root -e "DROP DATABASE IF EXISTS test;"
mysql -u root -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"
mysql -u root -e "FLUSH PRIVILEGES;"

# 最终设置密码
mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED BY 'root';" 2>/dev/null || \
mysql -u root -e "SET PASSWORD FOR 'root'@'localhost' = PASSWORD('root');" 2>/dev/null

mysql -u root -e "GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost';"
mysql -u root -e "FLUSH PRIVILEGES;"

echo "MariaDB安装配置完成!"

# 返回到脚本所在目录进行后续操作
echo "返回到脚本目录: $SCRIPT_DIR"
cd "$SCRIPT_DIR"

# 安装Python依赖包
echo "安装Python依赖包..."
if [ -f "requirements.txt" ]; then
    echo "使用pip安装依赖包..."
    /opt/python/python3.9/bin/python3.9 -m pip install --upgrade pip
    /opt/python/python3.9/bin/python3.9 -m pip install -r requirements.txt
    
    if [ $? -eq 0 ]; then
        echo "Python依赖包安装完成!"
    else
        echo "警告: Python依赖包安装失败，尝试使用国内镜像..."
        /opt/python/python3.9/bin/python3.9 -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
    fi
else
    echo "未找到requirements.txt文件，跳过Python依赖包安装"
    echo "当前目录内容:"
    ls -la
fi

# 导入数据库schema
echo "导入数据库schema..."
if [ -f "database_schema.sql" ]; then
    echo "找到database_schema.sql文件，开始导入..."
    mysql -u root -proot < database_schema.sql
    
    if [ $? -eq 0 ]; then
        echo "数据库schema导入成功!"
    else
        echo "错误: 数据库schema导入失败"
        echo "请手动运行: mysql -u root -proot < database_schema.sql"
    fi
else
    echo "未找到database_schema.sql文件，跳过数据库导入"
    echo "当前目录内容:"
    ls -la
fi

# 输出完成提示
echo "==========================================="
echo "安装完成!"
echo "Python 3.9安装位置: /opt/python/python3.9/"
echo "MariaDB root密码: root"
echo "数据库schema已导入"
echo "现在你可以使用以下命令运行你的应用:"
echo "python3.9 app.py"
echo "==========================================="
