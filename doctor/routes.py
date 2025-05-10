# doctor\routes.py
from flask import Blueprint, render_template, request, redirect, url_for, current_app, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
# from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from mysql.connector import Error
from config import db_config, User, calcu_age  # 假设 User 类在 app.py 中定义
from doctor.models import *
from flask_socketio import SocketIO, emit
from crypto import *
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
                message = '用户名不存在，请先注册'
            else:
                stored_password = results['password']
                sa = results['sa']
                if check_salt_sm3(password,sa,stored_password):
                    user = User(results['id'], results['username'], 'doctor')
                    login_user(user)

                    # 将医生的登录信息存储到 session 中
                    session['doctor_id'] = results['id']
                    session['doctor_username'] = results['username']
                    session['pw'] = password

                    if set_doctor_online(results['id']):
                        # print(f"doctor{results['username']} login successfully")
                        return redirect(url_for('doctor_bp.dc_home'))
                    else:
                        # print(f"doctor{results['username']} not login")
                        raise Error(f"医生{results['username']}登录但未能正常设置其在线状态")
                    # return redirect(url_for('doctor_bp.dc_home'))
                else:
                    message = '密码错误，请重试'
        except Error as e:
            print(f"routes_doctor_login_Error: {e}")
            message = '登录失败，请重试'
            # return redirect(url_for('patient_bp.login'))

    return render_template('doctor_login.html', message=message)


# 医生注册
@doctor_bp.route('/register', methods=['GET', 'POST'])
def register():
    message = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # hashed_password = generate_password_hash(password).encode('utf-8')
        sa = generate_salt()
        hashed_password = generate_salt_sm3(password, sa)
        akey, bkey = generate_sm2_key_pair()  # 此处密钥对是十六进制字符串]
        print(f"医生{username}初始生成的私钥：", akey)
        print(f"医生{username}初始生成的公钥：", bkey)
        tkey = generate_pbkdf2_key(password, sa)
        akey = sm4_encrypt(akey, tkey)  # 此处加密后的私钥是bytes
        del tkey
        # change
        try:
            results = get_doctor_login(username)
            # print(results['id'], results['username'], results['password'])
            if results is not None:
                message = '用户名已存在，请重试'
                return render_template('doctor_register.html', message=message)

            if create_doctor_login(generate_doctor_id(), username, hashed_password, sa, akey, bkey):
                message = '注册成功，请登录'
                return render_template('doctor_register.html', message=message)
            else:
                message = '注册失败'
                return render_template('doctor_register.html', message=message)
        except Error as e:
            print(f"routes_doctor_login_Error: {e}")
            message = '注册失败请重试'

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
    # 从 session 中获取医生的登录信息
    doctor_id = session.get('doctor_id')
    doctor_username = session.get('doctor_username')
    password = session.get('pw')
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
            message = '个人信息已更新'
            profile_data = get_doctor_profile(current_user.id)
        else:
            message = '个人信息未能更新'

    return render_template('doctor_profile_edit.html', message=message, profile_data=profile_data)


# 医生查看问诊申请
@doctor_bp.route('/appointments')
@login_required
def view_appointments():
    requests = get_consultation_requests(current_user.id)
    password = session.get('pw')
    dc_akey = get_doctor_akey(current_user.id, password)  # bytes
    dc_akey = dc_akey.decode()
    print("医生解密用的私钥", type(dc_akey), dc_akey)
    viewed_requests = []
    for request in requests:
        # 获取患者id
        print("sm2解密前：", type(request['patient_id']), request['patient_id'])
        patient_id = sm2_decrypt(request['patient_id'], dc_akey)
        print("sm2解密后：", type(patient_id), patient_id)
        patient_id = patient_id.decode('utf-8')
        patient_id = int(patient_id)

        # 通过患者id获取公钥并校验签名
        pt_bkey = get_patient_key(patient_id)['b_key']
        #pt_bkey = pt_bkey.encode() # 会触发错误报告
        to_sign = str(patient_id + current_user.id)
        sign = sm2_decrypt(request['sign'], dc_akey)
        sign = bytes_hexstr(sign)
        # print(sign)
        print("医生获取的解密签名：", type(sign), sign)
        print("医生校验签名使用的患者公钥：", type(pt_bkey), pt_bkey)
        print("医生校验签名使用的消息：", type(to_sign), to_sign)
        sign_result = sm2_verify(sign, to_sign, pt_bkey)
        print(sign_result)
        if sign_result is True:
            request['patient_id'] = patient_id
            viewed_requests.append(request)
        else:
            print(f"{sign_result}，{request['id']}申请，签名未通过")
    if viewed_requests:
        print(viewed_requests)
    else:
        print("无合法申请")
    del dc_akey

    return render_template('doctor_appointments.html', requests=viewed_requests)


# 医生接受或拒绝问诊申请
@doctor_bp.route('/respond_request/<int:request_id>/<action>', methods=['POST'])
@login_required
def respond_request(request_id, action):
    status = 'accepted' if action == 'accept' else 'rejected'
    # print(f"{request_id}号通知，有患者呼叫医生")

    message = None
    if update_consultation_request(request_id, status):
        message = '问诊申请已接受'
        # 发送通知给患者
        patient_id = get_patient_id(request_id)
        add_notification(patient_id, request_id, status)
        socketio = current_app.extensions['socketio']
        # 通过 WebSocket 通知患者
        socketio.emit('request_response', {'request_id': request_id, 'status': status},
                      room=f'patient_{get_patient_id(request_id)}')
    else:
        message = '医生端问诊申请接受失败'

    requests = get_consultation_requests(current_user.id)
    return render_template('doctor_appointments.html', requests=requests, message=message)


@doctor_bp.route('/medical_records')
@login_required
def request_list():
    requests = get_active_consultation_requests(current_user.id)
    rejected_records = get_records_correct(current_user.id)
    password = session.get('pw')
    dc_akey = get_doctor_akey(current_user.id, password)  # bytes
    dc_akey = dc_akey.decode()
    for c_request in requests:
        encrypted_patient_id = c_request['patient_id']
        patient_id_bytes = sm2_decrypt(encrypted_patient_id, dc_akey)
        patient_id = int(patient_id_bytes.decode('utf-8'))
        c_request['patient_id'] = patient_id

    print(requests)
    return render_template('doctor_request_list.html', requests=requests, rejected_records=rejected_records)


@doctor_bp.route('/medical_record/<int:request_id>', methods=['GET', 'POST'])
@login_required
def medical_record(request_id):
    message = None
    requests = get_active_consultation_requests(current_user.id)
    password = session.get('pw')
    dc_akey = get_doctor_akey(current_user.id, password)  # bytes
    dc_akey = dc_akey.decode()
    for c_request in requests:
        encrypted_patient_id = c_request['patient_id']
        patient_id_bytes = sm2_decrypt(encrypted_patient_id, dc_akey)
        patient_id = int(patient_id_bytes.decode('utf-8'))
        c_request['patient_id'] = patient_id

    print(requests)

    # 检查病历是否存在
    medical_record_data = None
    medical_record_data = get_medical_records_by_request(request_id)
    print(medical_record_data)
    exist = bool(medical_record_data)
    # print(exist)
    del dc_akey
    if exist is False:
        patient_id = None
        # 如果病历不存在，创建新病历
        #print(f"{request_id}号申请对应的病历不存在")
        for c_request in requests:
            if c_request['id'] == request_id:
                patient_id = c_request['patient_id']
        if create_medical_record(request_id, patient_id):
            medical_record_data = get_medical_records_by_request(request_id)
            message = '病历已创建'
        else:
            message = '病历创建失败'
    else:
        print(medical_record_data)
        # medical_record_data['patient_id'] = int(sm2_decrypt(medical_record_data['patient_id'], dc_akey).decode('utf-8'))
        # 可能用不上这条
        pass
    # 如果存在病历则解密现有病历

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
                message = '病历已保存'
            else:
                message = '病历保存失败'
            # 加密病历已经写好的部分（以未提交状态加密）
        elif action == 'submit':
            # 提交病历
            if update_medical_record_by_request(request_id, patient_complaint, medical_history, physical_examination,
                                                auxiliary_examination, diagnosis, treatment_advice):
                to_cal = f"{request_id}-{patient_complaint}-{medical_history}-{physical_examination}-" \
                         f"{auxiliary_examination}-{diagnosis}-{treatment_advice}"

                to_sign = generate_sm3_hash(to_cal)
                dc_akey = get_doctor_akey(current_user.id, password)  # bytes
                dc_akey = dc_akey.decode()
                dc_sign = sm2_sign(to_sign, dc_akey)
                del dc_akey
                if submit_medical_record_by_request(request_id, dc_sign):
                    message = '病历已提交'
                else:
                    message = '病历提交失败'
            else:
                message = '病历提交前未能保存，提交失败'
            if end_consultation(request_id):
                message = message + "  "+"问诊已完成"
            else:
                message = message + "  "+"问诊关系未能正常结束"
            # 以提交状态加密

    return render_template('doctor_medical_record.html', requests=requests,
                           medical_record=medical_record_data, message=message)


def end_consultation(request_id):
    success = False
    if update_consultation_request(request_id, 'completed'):
        # 发送通知给患者
        password = session.get('pw')
        dc_akey = get_doctor_akey(current_user.id, password)  # bytes
        dc_akey = dc_akey.decode()
        encrypted_patient_id = get_patient_id(request_id)
        patient_id_bytes = sm2_decrypt(encrypted_patient_id, dc_akey)
        patient_id = int(patient_id_bytes.decode('utf-8'))
        add_notification(patient_id, request_id, 'completed')
        socketio = current_app.extensions['socketio']
        # 通过 WebSocket 通知患者
        socketio.emit('consultation_ended', {'request_id': request_id}, room=f'patient_{get_patient_id(request_id)}')
        success = True
    else:
        pass
    return success

# 修改病历功能
@doctor_bp.route('/medical_records_revise/<int:mr_id>/<int:review_record_id>', methods=['GET', 'POST'])
def revise_medical_record(mr_id, review_record_id):
    message = None
    medical_record_data = None
    rejected_records = get_records_correct(current_user.id)
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
                message = '草稿已保存'
            else:
                message = '草稿保存失败'
        elif action == 'submit':
            # 提交病历
            if update_medical_record(mr_id, patient_complaint, medical_history, physical_examination,
                                     auxiliary_examination, diagnosis, treatment_advice):
                to_cal = f"{medical_record_data['request_id']}-{patient_complaint}-{medical_history}-{physical_examination}-" \
                         f"{auxiliary_examination}-{diagnosis}-{treatment_advice}"

                to_sign = generate_sm3_hash(to_cal)
                password = session.get('pw')
                dc_akey = get_doctor_akey(current_user.id, password)  # bytes
                dc_akey = dc_akey.decode()
                dc_sign = sm2_sign(to_sign, dc_akey)
                del dc_akey
                if submit_medical_record(mr_id, dc_sign):
                    message = '病历已提交'
                else:
                    message = '病历提交失败'
            else:
                message = '提交前病历未能保存'
    return render_template("doctor_revise_medical_record.html", rejected_records=rejected_records, message=message, review_record=review_record_data, medical_record=medical_record_data)


# 注销功能
@doctor_bp.route('/logout')
@login_required
def logout():
    set_doctor_offline(current_user.id)
    logout_user()
    return redirect(url_for('index'))

