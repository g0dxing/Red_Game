#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据库初始化模块
避免循环导入问题
"""
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
