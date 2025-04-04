from flask import Flask
from flask_login import LoginManager, UserMixin

# 配置 MySQL 数据库连接
db_config = {
    'host': 'localhost',
    'user': 'root',
    'port': '3406',
    'password': '123456789',
    'database': 'ch_test_not_safe'
}

app = Flask(__name__)
# 初始化 LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'index'

# 用户类
class User(UserMixin):
    def __init__(self, user_id, username,ty):
        self.id = user_id
        self.username = username
        self.type = ty

from datetime import datetime

def calcu_age(birth_date):
    """
    计算年龄
    :param birth_date: 出生日期 (格式: YYYY-MM-DD)
    :return: 年龄
    """
    today = datetime.today()
    #birth_date = datetime.strptime(birth_date, "%Y-%m-%d")
    age = today.year - birth_date.year
    # 检查是否已经过了生日
    if (today.month, today.day) < (birth_date.month, birth_date.day):
        age -= 1
    return age
'''
# 示例用法
birth_date = "1990-05-15"
age = calcu_age(birth_date)
print(f"年龄: {age}")
'''






