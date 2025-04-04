from flask import Blueprint, render_template, request, redirect, url_for, current_app
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from mysql.connector import Error
from config import db_config, User,calcu_age
from patient.models import *
from flask_socketio import SocketIO

#from app_run import socketio  # 从主应用导入 socketio 实例
# 创建蓝prints
patient_bp = Blueprint('patient_bp', __name__, template_folder='templates')

# 患者登录
@patient_bp.route('/login', methods=['GET', 'POST'])
def login():
    message = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # 如果使用models文件的函数，在此处插入
        try:
            results = get_patient_login(username)
            #print(results['id'], results['username'], results['password'])
            if results is None:
                message = 'Username not found. Please register first.'
            else:
                stored_password = results['password'].decode('utf-8')
                if check_password_hash(stored_password, password):
                    user = User(results['id'], results['username'], 'patient')
                    login_user(user)
                    return redirect(url_for('patient_bp.pt_home'))
                else:
                    message = 'Invalid password. Please try again.'
        except Error as e:
            print(f"routes_patient_login_Error: {e}")
            message = 'Login failed. Please try again.'
            # return redirect(url_for('patient_bp.login'))

    return render_template('patient_login.html', message=message)


# 患者注册
@patient_bp.route('/register', methods=['GET', 'POST'])
def register():
    message = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password).encode('utf-8')

        # 如果使用models文件的函数，在此处插入
        try:
            results = get_patient_login(username)
            #print(results['id'], results['username'], results['password'])
            if results is not None:
                message = 'Username already exists. Please choose a different one.'
                return render_template('patient_register.html', message=message)

            if create_patient_login(generate_patient_id(), username, hashed_password):
                message = 'Registration successful! Please login.'
                return render_template('patient_register.html', message=message)
            else:
                message = 'Registration failed.'
                return render_template('patient_register.html', message=message)
        except Error as e:
            print(f"routes_patient_login_Error: {e}")
            message = 'Registration failed. Please try again.'

    return render_template('patient_register.html', message=message)


def generate_patient_id():
    connection = None
    cursor = None
    new_id = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        prefix = 30000000
        table_name = 'patients'
        cursor.execute(f"SELECT MAX(id) FROM {table_name}")
        result = cursor.fetchone()

        if result and result[0]:
            current_id = result[0]
        else:
            current_id = prefix
        new_id = current_id + 1

    except Error as e:
        print(f"routes_generate_patient_id_Error: {e}")
        new_id = None
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return new_id


@patient_bp.route('/home', methods=['GET', 'POST'])
@login_required
def pt_home():
    profile_data = get_patient_profile(current_user.id)
    return render_template('patient_dashboard.html',
                           username=current_user.username,
                           user_id=current_user.id,
                           profile_completed=bool(profile_data))
    # return render_template('patient_dashboard.html', username=current_user.username)


# 患者个人信息展示
@patient_bp.route('/profile')
@login_required
def display_profile():
    profile_data = get_patient_profile(current_user.id)
    profile_complete = bool(profile_data)
    age = None
    if profile_complete is True:
        age = calcu_age(profile_data['birth_date'])
    else:
        pass
    return render_template('patient_profile_display.html',
                           profile_data=profile_data,
                           age=age,
                           profile_complete=profile_complete)


# 患者个人信息编辑
@patient_bp.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    message = None
    profile_data = get_patient_profile(current_user.id)

    if request.method == 'POST':
        full_name = request.form.get('full_name')
        gender = request.form.get('gender')
        birth_date = request.form.get('birth_date')

        if create_patient_profile(current_user.id, full_name, gender, birth_date):
            message = 'Profile updated successfully.'
            profile_data = get_patient_profile(current_user.id)
            # return redirect(url_for('patient_bp.display_profile'))
        else:
            message = 'Failed to save profile. Please try again.'

    return render_template('patient_profile_edit.html', message=message, profile_data=profile_data)


# 患者问诊
@patient_bp.route('/consultation')
@login_required
def consultation():
    online_doctors = get_online_doctors()
    #print(online_doctors)
    return render_template('patient_consultation.html', online_doctors=online_doctors)


# 患者发出问诊申请
@patient_bp.route('/send_request/<int:doctor_id>', methods=['POST'])
@login_required
def send_request(doctor_id):
    patient_id = current_user.id
    message = None
    if create_consultation_request(patient_id, doctor_id):

        # 通过 current_app 访问 socketio 实例
        socketio = current_app.extensions['socketio']
        socketio.emit('new_request', {'doctor_id': doctor_id}, room=f'doctor_{doctor_id}')
        message = 'Request sent successfully.'
    else:
        message = 'Failed to send request.'
    online_doctors = get_online_doctors()
    return render_template('patient_consultation.html', online_doctors=online_doctors, message=message)


# 患者查看通知
@patient_bp.route('/notifications')
@login_required
def notifications():
    notifications = get_patient_notifications(current_user.id)
    return render_template('patient_notifications.html', notifications=notifications)


# 患者病历查询
@patient_bp.route('/medical_records')
@login_required
def medical_records():
    records = get_medical_records(current_user.id)
    return render_template('patient_medical_records.html',records=records)


# 注销功能
@patient_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


