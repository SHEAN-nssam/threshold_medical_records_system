from flask import Blueprint, render_template, request, redirect, url_for,jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from mysql.connector import Error
from config import db_config, User  # 假设 User 类在 app.py 中定义
from admin.models import *
from crypto import *
# 创建蓝prints
admin_bp = Blueprint('admin_bp', __name__, template_folder='templates')


# 管理员登录
@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    message = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # change
        try:
            results = get_admin_login(username)
            #print(results['id'], results['username'], results['password'])
            if results is None:
                message = 'Username not found. Please register first.'
            else:
                # stored_password = results['password'].decode('utf-8')
                stored_password = results['password']
                sa = results['sa']
                # if check_password_hash(stored_password, password):
                if check_salt_sm3(password, sa, stored_password):
                    user = User(results['id'], results['username'], 'patient')
                    login_user(user)
                    return redirect(url_for('admin_bp.ad_home'))
                else:
                    message = 'Invalid password. Please try again.'
        except Error as e:
            print(f"routes_admin_login_Error: {e}")
            message = 'Login failed. Please try again.'

    return render_template('admin_login.html', message=message)


# 管理员注册
@admin_bp.route('/register', methods=['GET', 'POST'])
def register():
    message = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # hashed_password = generate_password_hash(password).encode('utf-8')
        sa = generate_salt()
        hashed_password = generate_salt_sm3(password, sa)
        akey, bkey = generate_sm2_key_pair()
        tkey = generate_pbkdf2_key(password, sa)
        akey = sm4_encrypt(akey, tkey)
        del tkey
        try:
            results = get_admin_login(username)
            #print(results['id'], results['username'], results['password'])
            if results is not None:
                message = 'Username already exists. Please choose a different one.'
                return render_template('admin_register.html', message=message)

            if create_admin_login(generate_admin_id(), username, hashed_password, sa, akey, bkey):
                message = 'Registration successful! Please login.'
                return render_template('admin_register.html', message=message)
            else:
                message = 'Registration failed.'
                return render_template('admin_register.html', message=message)
        except Error as e:
            print(f"routes_admin_login_Error: {e}")
            message = 'Registration failed. Please try again.'

    return render_template('admin_register.html', message=message)


def generate_admin_id():
    connection = None
    cursor = None
    new_id = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        prefix = 10000000
        table_name = 'admins'
        cursor.execute(f"SELECT MAX(id) FROM {table_name}")
        result = cursor.fetchone()

        if result and result[0]:
            current_id = result[0]
        else:
            current_id = prefix
        new_id = current_id + 1

    except Error as e:
        print(f"generate_admin_id_Error: {e}")
        new_id = None
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return new_id


@admin_bp.route('/home', methods=['GET', 'POST'])
@login_required
def ad_home():
    return render_template('admin_dashboard.html', username=current_user.username)


@admin_bp.route('/review_list')
@login_required
def review_list():
    me_records = get_medical_records_waiting_review()
    print(me_records)
    return render_template('admin_review_list.html', records=me_records)


@admin_bp.route('/review_record/<record_id>', methods=['GET','POST'])
@login_required
def review_record(record_id):
    message = None
    medical_record = get_medical_record(record_id)
    if request.method == 'POST':
        review_opinions = request.form['review_opinions']
        action = request.form['action']

        if action == 'pass':
            if create_review_record_pass(record_id,current_user.id) and approve_medical_record(record_id):
                message = '病历已归档'
            else:
                message = '病历未能归档'
        elif action == 'not_pass':
            if review_opinions is None:
                message = '不通过请填写审核意见'
            else:
                if create_review_record_not_pass(record_id,current_user.id,review_opinions) \
                        and reject_medical_record(record_id):
                    message = "病历已拒绝"
                else:
                    message = "病历未能拒绝"
    return render_template('admin_medical_record.html', medical_record=medical_record, message=message)

# 注销功能
@admin_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


'''
# 生成用户 ID
def generate_user_id(user_type):
    connection = None
    cursor = None
    new_id = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        if user_type == 'admin':
            prefix = 10000000
            table_name = 'admins'
        elif user_type == 'doctor':
            prefix = 20000000
            table_name = 'doctors'
        elif user_type == 'patient':
            prefix = 30000000
            table_name = 'patients'
        else:
            return None

        cursor.execute(f"SELECT MAX(id) FROM {table_name}")
        result = cursor.fetchone()

        if result and result[0]:
            current_id = result[0]
        else:
            current_id = prefix

        new_id = current_id + 1

    except Error as e:
        print(f"Error: {e}")
        new_id = None
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

    return new_id
'''