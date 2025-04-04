from flask import Blueprint, render_template, request, redirect, url_for, current_app
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from mysql.connector import Error
from config import db_config, User, calcu_age  # 假设 User 类在 app.py 中定义
from doctor.models import *
from flask_socketio import SocketIO, emit

# from app_run import socketio  # 从主应用导入 socketio 实例
# 创建蓝prints
doctor_bp = Blueprint('doctor_bp', __name__, template_folder='templates')


# 医生登录
@doctor_bp.route('/login', methods=['GET', 'POST'])
def login():
    message = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # change
        try:
            results = get_doctor_login(username)
            # print(results['id'], results['username'], results['password'])
            if results is None:
                message = 'Username not found. Please register first.'
            else:
                stored_password = results['password'].decode('utf-8')
                if check_password_hash(stored_password, password):
                    user = User(results['id'], results['username'], 'patient')
                    login_user(user)

                    if set_doctor_online(results['id']):
                        # print(f"doctor{results['username']} login successfully")
                        return redirect(url_for('doctor_bp.dc_home'))
                    else:
                        # print(f"doctor{results['username']} not login")
                        raise Error(f"医生{results['username']}登录但未能正常设置其在线状态")
                    # return redirect(url_for('doctor_bp.dc_home'))
                else:
                    message = 'Invalid password. Please try again.'
        except Error as e:
            print(f"routes_doctor_login_Error: {e}")
            message = 'Login failed. Please try again.'
            # return redirect(url_for('patient_bp.login'))
        '''   
        connection = None
        cursor = None
        try:
            connection = mysql.connector.connect(**db_config)
            cursor = connection.cursor()

            cursor.execute("SELECT id, username, password FROM doctors WHERE username = %s", (username,))
            doctor_user = cursor.fetchone()

            if doctor_user:
                stored_password = doctor_user[2].decode('utf-8')
                if check_password_hash(stored_password, password):
                    user = User(doctor_user[0], doctor_user[1], 'doctor')
                    login_user(user)
                    return redirect(url_for('doctor_bp.dc_home'))
                else:
                    message = 'Invalid password. Please try again.'
            else:
                message = 'Username not found. Please register first.'
            #return redirect(url_for('doctor_bp.login'))

        except Error as e:
            print(f"doctor_login_Error: {e}")
            message = 'Login failed. Please try again.'
            #return redirect(url_for('doctor_bp.login'))
        finally:
            if connection and connection.is_connected():
                cursor.close()
                connection.close()
    '''
    return render_template('doctor_login.html', message=message)


# 医生注册
@doctor_bp.route('/register', methods=['GET', 'POST'])
def register():
    message = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password).encode('utf-8')

        # change
        try:
            results = get_doctor_login(username)
            # print(results['id'], results['username'], results['password'])
            if results is not None:
                message = 'Username already exists. Please choose a different one.'
                return render_template('doctor_register.html', message=message)

            if create_doctor_login(generate_doctor_id(), username, hashed_password):
                message = 'Registration successful! Please login.'
                return render_template('doctor_register.html', message=message)
            else:
                message = 'Registration failed.'
                return render_template('doctor_register.html', message=message)
        except Error as e:
            print(f"routes_doctor_login_Error: {e}")
            message = 'Registration failed. Please try again.'
        '''
        connection = None
        cursor = None
        try:
            connection = mysql.connector.connect(**db_config)
            cursor = connection.cursor()

            cursor.execute("SELECT id FROM doctors WHERE username = %s", (username,))
            existing_user = cursor.fetchone()

            if existing_user:
                message = 'Username already exists. Please choose a different one.'
                return render_template('patient_register.html', message=message)

            cursor.execute("INSERT INTO doctors (id, username, password) VALUES (%s, %s, %s)",
                           (generate_doctor_id(), username, hashed_password))
                           # (generate_user_id('doctor'), username, hashed_password, department))
            connection.commit()

            message = 'Registration successful! Please login.'
            return render_template('patient_register.html', message=message)

        except Error as e:
            print(f"doctor_register_Error: {e}")
            message = 'Registration failed. Please try again.'
        finally:
            if connection and connection.is_connected():
                cursor.close()
                connection.close()
    '''
    return render_template('doctor_register.html', message=message)


def generate_doctor_id():
    connection = None
    cursor = None
    new_id = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        prefix = 20000000
        table_name = 'doctors'
        cursor.execute(f"SELECT MAX(id) FROM {table_name}")
        result = cursor.fetchone()

        if result and result[0]:
            current_id = result[0]
        else:
            current_id = prefix
        new_id = current_id + 1

    except Error as e:
        print(f"generate_doctor_id_Error: {e}")
        new_id = None
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return new_id


@doctor_bp.route('/home', methods=['GET', 'POST'])
@login_required
def dc_home():
    profile_data = get_doctor_profile(current_user.id)

    # return render_template('doctor_dashboard.html', username=current_user.username)
    return render_template('doctor_dashboard.html', username=current_user.username, user_id=current_user.id,
                           profile_completed=bool(profile_data))


# 医生个人信息
@doctor_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def display_profile():
    profile_data = get_doctor_profile(current_user.id)
    profile_complete = bool(profile_data)
    age = None
    if profile_complete is True:
        age = calcu_age(profile_data['birth_date'])
    else:
        pass
    return render_template('doctor_profile_display.html',
                           profile_data=profile_data,
                           age=age,
                           profile_complete=profile_complete)


# 个人信息编辑
@doctor_bp.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    message = None
    profile_data = get_doctor_profile(current_user.id)

    if request.method == 'POST':
        full_name = request.form['full_name']
        gender = request.form['gender']
        birth_date = request.form['birth_date']
        department = request.form['department']
        title = request.form['title']

        if create_doctor_profile(current_user.id, full_name, gender, birth_date, department, title):
            message = 'Profile updated successfully.'
            profile_data = get_doctor_profile(current_user.id)
        else:
            message = 'Failed to save profile. Please try again.'

    return render_template('doctor_profile_edit.html', message=message, profile_data=profile_data)


'''
# 医生接诊
@doctor_bp.route('/appointments')
@login_required
def appointments():
    return render_template('doctor_appointments.html')
'''


# 医生查看问诊申请
@doctor_bp.route('/appointments')
@login_required
def view_appointments():
    requests = get_consultation_requests(current_user.id)
    if requests:
        print(requests)
    else:
        print("no request")
    return render_template('doctor_appointments.html', requests=requests)


# 医生接受或拒绝问诊申请
@doctor_bp.route('/respond_request/<int:request_id>/<action>', methods=['POST'])
@login_required
def respond_request(request_id, action):
    status = 'accepted' if action == 'accept' else 'rejected'
    # print(f"{request_id}号通知，有患者呼叫医生")
    message = None
    if update_consultation_request(request_id, status):
        message = 'Request updated successfully.'
        # 发送通知给患者
        patient_id = get_patient_id(request_id)
        add_notification(patient_id, request_id, status)
        socketio = current_app.extensions['socketio']
        # 通过 WebSocket 通知患者
        socketio.emit('request_response', {'request_id': request_id, 'status': status},
                      room=f'patient_{get_patient_id(request_id)}')
    else:
        message = 'Failed to update request.'
    requests = get_consultation_requests(current_user.id)
    return render_template('doctor_appointments.html', requests=requests, message=message)


# 医生结束问诊
@doctor_bp.route('/end_consultation/<int:request_id>', methods=['POST'])
@login_required
def end_consultation(request_id):
    message = None

    if update_consultation_request(request_id, 'completed'):
        message = 'Consultation ended successfully.'
        # 发送通知给患者
        patient_id = get_patient_id(request_id)
        add_notification(patient_id, request_id, 'completed')
        socketio = current_app.extensions['socketio']
        # 通过 WebSocket 通知患者
        socketio.emit('consultation_ended', {'request_id': request_id}, room=f'patient_{get_patient_id(request_id)}')
    else:
        message = 'Failed to end consultation.'
    requests = get_consultation_requests(current_user.id)
    return render_template('doctor_appointments.html', requests=requests, message=message)


'''
# 医生书写病历
@doctor_bp.route('/write_medical_record')
@login_required
def write_medical_record():
    return render_template('doctor_write_medical_record.html')
'''


@doctor_bp.route('/medical_records')
@login_required
def request_list():
    requests = get_active_consultation_requests(current_user.id)
    rejected_records = get_records_correct(current_user.id)
    return render_template('doctor_request_list.html', requests=requests, rejected_records=rejected_records)


@doctor_bp.route('/medical_record/<int:request_id>', methods=['GET', 'POST'])
@login_required
def medical_record(request_id):
    message = None
    medical_record_data = None
    # 检查病历是否存在
    medical_record_data = get_medical_records_by_request(request_id)
    #print(medical_record_data)
    exist = bool(medical_record_data)
    #print(exist)
    if exist is False:
        # 如果病历不存在，创建新病历
        #print(f"{request_id}号申请对应的病历不存在")
        if create_medical_record(request_id):
            medical_record_data = get_medical_records_by_request(request_id)
            message = 'New medical record created.'
        else:
            message = 'Failed to create medical record.'
    else:
        print(medical_record_data)
        pass

    if request.method == 'POST':
        patient_complaint = request.form['patient_complaint']
        medical_history = request.form['medical_history']
        physical_examination = request.form['physical_examination']
        auxiliary_examination = request.form['auxiliary_examination']
        diagnosis = request.form['diagnosis']
        treatment_advice = request.form['treatment_advice']
        action = request.form['action']

        if action == 'save':
            # 保存草稿
            if update_medical_record_by_request(request_id, patient_complaint, medical_history, physical_examination,
                                                auxiliary_examination, diagnosis, treatment_advice):
                message = 'Draft saved successfully.'
            else:
                message = 'Failed to save draft.'
        elif action == 'submit':
            # 提交病历
            if update_medical_record_by_request(request_id, patient_complaint, medical_history, physical_examination,
                                                auxiliary_examination, diagnosis, treatment_advice):
                if submit_medical_record_by_request(request_id):
                    message = 'Medical record submitted successfully.'
                else:
                    message = 'Failed to submit medical record.'
            else:
                message = 'Failed to save draft before submission.'

    return render_template('doctor_medical_record.html', medical_record=medical_record_data, message=message)


# 修改病历功能
@doctor_bp.route('/medical_records_revise/<int:mr_id>/<int:review_record_id>', methods=['GET', 'POST'])
def revise_medical_record(mr_id, review_record_id):
    message = None
    medical_record_data = None
    review_record_data = get_review_record(review_record_id)
    # 检查病历是否存在
    medical_record_data = get_medical_record(mr_id)
    if medical_record_data is None:
        # 如果病历不存在，则返回错误
        message = "该病历不存在，请联系管理员"
        return render_template("doctor_revise_medical_record.html", message=message)

    if request.method == 'POST':
        patient_complaint = request.form['patient_complaint']
        medical_history = request.form['medical_history']
        physical_examination = request.form['physical_examination']
        auxiliary_examination = request.form['auxiliary_examination']
        diagnosis = request.form['diagnosis']
        treatment_advice = request.form['treatment_advice']
        action = request.form['action']

        if action == 'save':
            # 保存草稿
            if update_medical_record(mr_id, patient_complaint, medical_history, physical_examination,
                                     auxiliary_examination, diagnosis, treatment_advice):
                message = 'Draft saved successfully.'
            else:
                message = 'Failed to save draft.'
        elif action == 'submit':
            # 提交病历
            if update_medical_record(mr_id, patient_complaint, medical_history, physical_examination,
                                     auxiliary_examination, diagnosis, treatment_advice):
                if submit_medical_record(mr_id):
                    message = 'Medical record submitted successfully.'
                else:
                    message = 'Failed to submit medical record.'
            else:
                message = 'Failed to save draft before submission.'
    return render_template("doctor_revise_medical_record.html", message=message, review_record=review_record_data, medical_record=medical_record_data)


# 注销功能
@doctor_bp.route('/logout')
@login_required
def logout():
    set_doctor_offline(current_user.id)
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
