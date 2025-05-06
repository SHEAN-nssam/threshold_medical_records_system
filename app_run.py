from flask import Flask, render_template, jsonify, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import json
import mysql.connector
from mysql.connector import Error
from flask_socketio import SocketIO
from crypto import *
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'qwertyuiopasdfghjklzxcvbnm--qazwsxedcrfvtgbyhnujmikolp'  # 设置密钥
#os.urandom(24)

# 初始化 SocketIO 并存储在 app.extensions 中
socketio = SocketIO(app)
app.extensions['socketio'] = socketio

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
login_manager.login_view = 'index'


# 用户类
class User(UserMixin):
    def __init__(self, user_id, username, ty):
        self.id = user_id
        self.username = username
        self.type = ty


# 主页
@app.route('/')
def index():
    return render_template('index.html')


# 用户加载函数
@login_manager.user_loader
def load_user(user_id):
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # 尝试从 admins 表加载
        cursor.execute("SELECT id, username FROM admins WHERE id = %s", (user_id,))
        admin_user = cursor.fetchone()
        if admin_user:
            return User(admin_user[0], admin_user[1], 'admin')

        # 尝试从 doctors 表加载
        cursor.execute("SELECT id, username FROM doctors WHERE id = %s", (user_id,))
        doctor_user = cursor.fetchone()
        if doctor_user:
            return User(doctor_user[0], doctor_user[1], 'doctor')

        # 尝试从 patients 表加载
        cursor.execute("SELECT id, username FROM patients WHERE id = %s", (user_id,))
        patient_user = cursor.fetchone()
        if patient_user:
            return User(patient_user[0], patient_user[1], 'patient')

        return None
    except Error as e:
        print(f"Error: {e}")
        return None
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


def initialize_database():
    connection = None
    cursor = None
    try:
        # 创建数据库连接（不指定数据库）
        connection = mysql.connector.connect(
            host=db_config['host'],
            user=db_config['user'],
            port= db_config['port'],
            password=db_config['password']
        )
        cursor = connection.cursor()

        # 读取数据库表结构定义文件
        with open('database_schema.json', 'r') as file:
            schema = json.load(file)

        # 选择数据库
        cursor.execute("USE `%s`" % (db_config['database'],))

        # 创建表
        for table in schema['tables']:
            table_name = table['name']
            columns = table['columns']
            foreign_keys = table.get('foreign_keys', [])

            # 构建 CREATE TABLE 语句
            create_table_sql = f"CREATE TABLE IF NOT EXISTS {table_name} (\n"
            for column in columns:
                create_table_sql += f"  {column['name']} {column['type']} {column.get('constraints', '')},\n"

            # 添加外键约束
            for foreign_key in foreign_keys:
                create_table_sql += f"  FOREIGN KEY ({foreign_key['column']}) REFERENCES {foreign_key['references']},\n"

            # 去掉最后一个多余的逗号和换行符
            create_table_sql = create_table_sql.rstrip(',\n') + "\n"
            create_table_sql += ");"

            # 执行 CREATE TABLE 语句
            cursor.execute(create_table_sql)
            print(f"Table '{table_name}' created or already exists.")

        # 预先创建管理员用户
        # 判断表中是否已有管理员用户
        cursor.execute("SELECT COUNT(*) FROM admins")
        count = cursor.fetchone()[0]

        if count == 0:

            # 定义三个管理员用户的信息
            admin_users = [
                {
                    "id": 10000001,
                    "username": "admin1",
                    "password": "123456"
                },
                {
                    "id": 10000002,
                    "username": "admin2",
                    "password": "123456"
                },
                {
                    "id": 10000003,
                    "username": "admin3",
                    "password": "123456"
                }
            ]

            # 生成管理员共同公私钥对，并将私钥分为三片
            ad_key, public_key = generate_valid_sm2_key_pair()
            print("管理员共同私钥：", type(ad_key), ad_key)
            print("管理员共同公钥：", type(public_key), public_key)

            public_key = hexstr_bytes(public_key)
            ad_key = hexstr_bytes(ad_key)
            shares = split_secret(ad_key, 2, 3)
            print("共同私钥原始分片：", shares)
            del ad_key
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            # 存储公钥到 admin_public_keys 表
            cursor.execute(
                "INSERT INTO admin_public_keys (public_key,created_at) VALUES (%s,%s)",
                (public_key, current_time)
            )

            share_index = 0
            # 插入三个管理员用户
            for admin in admin_users:
                # 密码加密
                sa = generate_salt()
                hashed_password = generate_salt_sm3(admin["password"], sa)  # 生成加盐哈希
                akey, bkey = generate_sm2_key_pair()  # 生成个人的公私密钥对
                print(f"管理员{admin['username']}的个人私钥：{akey}")
                print(f"管理员{admin['username']}的个人公钥：{bkey}")
                tkey = generate_pbkdf2_key(admin["password"], sa)  # 由密码和盐值生成加密私钥的临时对称密钥
                akey = sm4_encrypt(akey, tkey)  # 加密私钥
                del tkey  # 销毁临时对称密钥
                sh_id, adksh = shares[share_index]  # 获取属于个人的共同私钥分片
                adksh = sm2_encrypt(adksh, bkey)  # 使用个人公钥加密共同私钥分片，使用时需要还原私钥解密分片
                print(f"管理员{admin['username']}的分片：{sh_id}号-{adksh}")
                cursor.execute(
                    "INSERT INTO admins (id, username, password, sa, a_key, b_key, adksh,sh_id) "
                    "VALUES (%s, %s, %s, %s, %s,%s,%s,%s)",
                    (admin["id"], admin["username"], hashed_password, sa, akey, bkey, adksh, sh_id)
                )
                share_index = share_index + 1
        print("admins inserted")
        # 提交事务
        connection.commit()
        print("sheets are ready")
    except Error as e:
        print(f"initialize_database_Error: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


# 导入蓝prints
from patient.routes import patient_bp
from doctor.routes import doctor_bp
from admin.routes import admin_bp

# 注册蓝prints
app.register_blueprint(patient_bp, url_prefix='/patient')
app.register_blueprint(doctor_bp, url_prefix='/doctor')
app.register_blueprint(admin_bp, url_prefix='/admin')


if __name__ == '__main__':
    initialize_database()
    #app.run(host='0.0.0.0', port=5000, debug=True)
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)



'''
def initialize_database():
    connection = None
    cursor = None
    try:
        # 创建数据库连接（不指定数据库）
        connection = mysql.connector.connect(
            host=db_config['host'],
            user=db_config['user'],
            port= db_config['port'],
            password=db_config['password']
        )
        cursor = connection.cursor()
        # 数据库名需修改，同步检查三端函数
        ''''''
        # 检查数据库是否存在，不存在则创建
        cursor.execute("CREATE DATABASE IF NOT EXISTS your_database")
        print("Database created or already exists.")
        ''''''
        # 选择数据库
        print("USE `%s`" % (db_config['database'],))
        cursor.execute("USE `%s`" % (db_config['database'],))


        # 检查并创建 admins 表
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INT PRIMARY KEY,
            username VARCHAR(80) UNIQUE NOT NULL,
            password TINYBLOB NOT NULL
        )
        """)
        print("Table 'admins' created or already exists.")

        # 检查并创建 doctors 表
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS doctors (
            id INT PRIMARY KEY,
            username VARCHAR(80) UNIQUE NOT NULL,
            password TINYBLOB NOT NULL,
            is_online TINYINT(1) DEFAULT 0
        )
        """)
        print("Table 'doctors' created or already exists.")

        # 检查并创建 patients 表
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            id INT PRIMARY KEY,
            username VARCHAR(80) UNIQUE NOT NULL,
            password TINYBLOB NOT NULL
        )
        """)
        print("Table 'patients' created or already exists.")

        # 患者个人信息表检查
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS patient_profiles (
            id INT PRIMARY KEY,
            full_name VARCHAR(100) NOT NULL,
            gender VARCHAR(10) NOT NULL,
            birth_date DATE NOT NULL,
            FOREIGN KEY (id) REFERENCES patients (id)
        );
        """)
        print("Table 'patient_profiles' created or already exists.")

        # 医生个人信息表检查
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS doctor_profiles (
            id INT PRIMARY KEY,
            full_name VARCHAR(100) NOT NULL,
            gender VARCHAR(10) NOT NULL,
            birth_date DATE NOT NULL,
            department VARCHAR(50) NOT NULL,
            title VARCHAR(50) NOT NULL,
            FOREIGN KEY (id) REFERENCES doctors (id)
        ); 
        """)
        print("Table 'doctor_profiles' created or already exists.")

        # 病历表初始化
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS medical_records (
            id INT PRIMARY KEY AUTO_INCREMENT, -- 病历编号
            patient_id INT NOT NULL, -- 患者ID，外键关联患者表
            doctor_id INT NOT NULL, -- 医生ID，外键关联医生表
            visit_date DATETIME NOT NULL, -- 就诊时间
            department VARCHAR(50) NOT NULL, -- 就诊科别
            patient_complaint TEXT NOT NULL, -- 病人主诉
            medical_history TEXT, -- 病人病史
            physical_examination TEXT, -- 体格检查
            auxiliary_examination TEXT, -- 辅助检查结果
            diagnosis TEXT NOT NULL, -- 医生诊断
            treatment_advice TEXT NOT NULL, -- 处理意见
            doctor_signature VARCHAR(100) NOT NULL, -- 医生签名
            is_reviewed BOOLEAN DEFAULT FALSE NOT NULL, -- 是否已审核
            is_approved BOOLEAN DEFAULT FALSE NOT NULL, -- 是否通过审核
            review_by INT, -- 审核人ID，外键关联管理员表
            review_date DATETIME, -- 审核时间
            FOREIGN KEY (patient_id) REFERENCES patients(id),
            FOREIGN KEY (doctor_id) REFERENCES doctors(id),
            FOREIGN KEY (review_by) REFERENCES admins(id)
        );
                """)
        print("Table 'medical_records' created or already exists.")

    except Error as e:
        print(f"initialize_database_Error: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

'''

