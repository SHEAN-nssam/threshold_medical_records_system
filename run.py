from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import mysql.connector
from mysql.connector import Error
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # 设置密钥

# 配置 MySQL 数据库连接
db_config = {
    'host': 'localhost',
    'user': 'root',
    'port': '3406',
    'password': '123456789',
    'database': 'ch_test_not_safe'
}

# 初始化 LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# 用户类
class User(UserMixin):
    def __init__(self, user_id, username):
        self.id = user_id
        self.username = username


# 用户加载函数
@login_manager.user_loader
def load_user(user_id):
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        cursor.execute("SELECT id, username FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        if user:
            return User(user[0], user[1])
        return None
    except Error as e:
        print(f"Error: {e}")
        return None
    finally:
        if connection and connection.is_connected():
            if cursor:
                cursor.close()
            connection.close()


# 检查并创建数据库和表格
def initialize_database():
    connection = None
    cursor = None
    try:
        # 创建数据库连接（不指定数据库）
        connection = mysql.connector.connect(
            host=db_config['host'],
            user=db_config['user'],
            port=db_config['port'],
            password=db_config['password'],
            database=db_config['database']
        )
        print("mysql正常连接")
        cursor = connection.cursor()
        '''
        # 检查数据库是否存在，不存在则创建
        # code = "CREATE DATABASE IF NOT EXISTS '%s'" % ("ch_test_not_safe")
        cursor.execute("CREATE DATABASE IF NOT EXISTS '%s'", db_config['database'])
        print("Database created or already exists.")
        '''
        # 选择数据库
        cursor.execute("USE `%s`" % db_config['database'])
        #print("USE `%s`" % db_config['database'])
        # 检查表格是否存在，不存在则创建
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(80) UNIQUE NOT NULL,
            password TINYBLOB NOT NULL
        )
        """)
        print("Table 'users' created or already exists.")

    except Error as e:
        print(f"initialize_database-Error: {e}")
    finally:
        if connection and connection.is_connected():
            if cursor:
                cursor.close()
            connection.close()


# 注册功能
@app.route('/register', methods=['GET', 'POST'])
def register():
    connection = None
    cursor = None
    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("password")
        hashed_password = generate_password_hash(password)

        try:
            connection = mysql.connector.connect(**db_config)
            cursor = connection.cursor()

            # 检查用户名是否已存在
            cursor.execute("SELECT id FROM users WHERE username = %s",  (username,))
            existing_user = cursor.fetchone()

            if existing_user:
                return 'Username already exists. Please choose a different one.<a href = "/register">back</a>'

            # 插入新用户
            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
            connection.commit()

            # 获取新用户的 ID
            user_id = cursor.lastrowid
            return f'Registration successful! Your user ID is: {user_id}. Please login.<a href = "/login">login</a>'

        except Error as e:
            print(f"register-Error: {e}")
            return 'Registration failed. Please try again.'
        finally:
            if connection and connection.is_connected():
                if cursor:
                    cursor.close()
                connection.close()

    return render_template('register.html')


# 登录功能
@app.route('/login', methods=['GET', 'POST'])
def login():
    connection = None
    cursor = None
    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("password")
        # password = request.form['password']

        try:
            connection = mysql.connector.connect(**db_config)
            cursor = connection.cursor()
            cursor.execute("SELECT id, username, password FROM users WHERE username = %s",  (username,))
            user_data = cursor.fetchone()

            if user_data:
                # 确保 user_data[2] 是字符串类型
                stored_password = user_data[2].decode('utf-8') if isinstance(user_data[2], bytes) else user_data[2]
                if check_password_hash(stored_password, password):
                    user = User(user_data[0], user_data[1])
                    login_user(user)
                    return redirect(url_for('home'))
                else:
                    return 'Invalid username or password. Please try again.<a href = "/login">back</a>'
            else:
                return 'Invalid username or password. Please try again.<a href = "/login">back</a>'

        except Error as e:
            print(f"login-Error: {e}")
            return 'Login failed. Please try again.<a href = "/login">back</a>'
        finally:
            if connection and connection.is_connected():
                if cursor:
                    cursor.close()
                connection.close()

    return render_template('login.html')


# 主页（登录后访问）
@app.route('/')
@login_required
def home():
    return render_template('home.html', username=current_user.username)


# 注销功能
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/input_page')
def index():
    return render_template('input_page.html')


# 在应用启动时初始化数据库
if __name__ == '__main__':
    initialize_database()
    app.run(debug=True)
