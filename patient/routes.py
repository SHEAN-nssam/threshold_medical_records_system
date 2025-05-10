# patient\routes.py
from flask import Blueprint, render_template, request, redirect, url_for, current_app
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import mysql.connector
from mysql.connector import Error
from config import User, calcu_age
from patient.models import *
from flask_socketio import SocketIO
from crypto import *

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
                message = '用户名不存在，请重试'
            else:
                #stored_password = results['password'].decode('utf-8')
                stored_password = results['password']
                sa = results['sa']
                # if check_password_hash(stored_password, password):
                if check_salt_sm3(password,sa,stored_password):
                    user = User(results['id'], results['username'], 'patient')
                    login_user(user)
                    return redirect(url_for('patient_bp.pt_home'))
                else:
                    message = '密码错误，请重试'
        except Error as e:
            print(f"routes_patient_login_Error: {e}")
            message = '登录失败，请重试'
            # return redirect(url_for('patient_bp.login'))

    return render_template('patient_login.html', message=message)


# 患者注册
@patient_bp.route('/register', methods=['GET', 'POST'])
def register():
    message = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        #hashed_password = generate_password_hash(password).encode('utf-8')
        sa = generate_salt()
        hashed_password = generate_salt_sm3(password, sa)
        akey, bkey = generate_sm2_key_pair()
        print(f"患者{username}初始生成的私钥：", akey)
        print(f"患者{username}初始生成的公钥：", bkey)
        tkey = generate_pbkdf2_key(password, sa)
        akey = sm4_encrypt(akey, tkey)
        del tkey
        # generate_patient_id(), username, hashed_password, sa, akey, bkey
        try:
            results = get_patient_login(username)
            #print(results['id'], results['username'], results['password'])
            if results is not None:
                message = '用户名已存在，请重试'
                return render_template('patient_register.html', message=message)
            if create_patient_login(generate_patient_id(), username, hashed_password, sa, akey, bkey):

                message = '注册成功，请登录'
                return render_template('patient_register.html', message=message)
            else:
                message = '注册成功'
                return render_template('patient_register.html', message=message)
        except Error as e:
            print(f"routes_patient_login_Error: {e}")
            message = '注册失败，请重试'

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
            message = '个人信息已更新'
            profile_data = get_patient_profile(current_user.id)
            # return redirect(url_for('patient_bp.display_profile'))
        else:
            message = '个人信息更新失败，请重试'

    return render_template('patient_profile_edit.html', message=message, profile_data=profile_data)


# 患者问诊列表
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
    # print(f"Received Content-Type: {request.content_type}")
    online_doctors = get_online_doctors()
    patient_id = current_user.id
    message = None
    # 问诊申请中患者id由医生公钥加密，患者id与医生id之和由患者私钥产生签名，再由医生公钥进行加密

    # get_patient_akey(patient_id,password)
    # 患者私钥签名,内容为患者id与医生id联合
    pwd = request.json.get('input')
    # print(pwd)
    # 此处添加密码验证逻辑
    username = current_user.username
    results = get_patient_login(username)
    stored_password = results['password']
    sa = results['sa']
    if not check_salt_sm3(pwd, sa, stored_password):
        message = '密码错误'
        # return redirect(url_for('patient_bp.consultation'))
        return render_template('patient_consultation.html', online_doctors=online_doctors, message=message)

    to_sign = str(patient_id+doctor_id)
    print("患者端待签名内容：", type(to_sign), to_sign)
    akey = get_patient_akey(patient_id, pwd)  # 因为加密时会将字符串encode，所以解密时使用decode恢复字符串，但注意此处本质是hexstr
    akey = akey.decode()
    print("患者端签名用的私钥：", type(akey), akey)
    sign = sm2_sign(to_sign, akey)
    del akey

    print("患者端生成的签名：", sign)
    # 添加获取医生公钥，加密的流程
    d_bkey = get_doctor_key(doctor_id)['b_key']
    print("患者端获取的医生公钥：", type(d_bkey), d_bkey)  # hexstr
    patient_id = str(patient_id).encode('utf-8')
    pt_id = sm2_encrypt(patient_id, d_bkey)
    print("患者id加密后：", pt_id)
    sign = hexstr_bytes(sign)
    sign = sm2_encrypt(sign, d_bkey)
    print("患者端加密签名：", type(sign), sign)

    if create_consultation_request(pt_id, doctor_id, sign):
        # 通过 current_app 访问 socketio 实例
        socketio = current_app.extensions['socketio']
        socketio.emit('new_request', {'doctor_id': doctor_id}, room=f'doctor_{doctor_id}')

        message = '问诊申请已发送'
    else:
        message = '问诊申请发送失败'

    return render_template('patient_consultation.html', online_doctors=online_doctors, message=message)



# 患者查看通知
@patient_bp.route('/notifications')
@login_required
def notifications():
    notifications = get_patient_notifications(current_user.id)
    return render_template('patient_notifications.html', notifications=notifications)


# 患者病历查询
@patient_bp.route('/medical_records', methods=['POST', 'GET'])
@login_required
def medical_records():
    records = None
    # records = get_medical_records(current_user.id)

    if request.method == 'POST':
        pwd = request.form.get('input')
    # print(pwd)
        username = current_user.username
        results = get_patient_login(username)
        stored_password = results['password']
        sa = results['sa']
        if not check_salt_sm3(pwd, sa, stored_password):
            message = 'Invalid password.'
            # return redirect(url_for('patient_bp.consultation'))
            return render_template('patient_medical_records.html',records=records)
        print(pwd)
        akey = get_patient_akey(current_user.id, pwd)  # 因为加密时会将字符串encode，所以解密时使用decode恢复字符串，但注意此处本质是hexstr
        akey = akey.decode()

        records = get_medical_records(current_user.id)
        print(records)
        for record in records:
            mr_pt_sh = get_pt_sh_by_medical_record(record['id'])['sh']
            print("en mr_pt_sh:", mr_pt_sh)
            mr_pt_sh = sm2_decrypt(mr_pt_sh, akey)
            print("mr_pt_sh:", mr_pt_sh)
            mr_pt_sh = (2, mr_pt_sh)
            mr_sv_sh = (1, record['server_share'])
            to_combine = [mr_sv_sh, mr_pt_sh]
            mr_tkey = combine_secret(to_combine, 2)
            mr_tkey = bytes_hexstr(mr_tkey)
            print("患者端获得的病历对称密钥：", mr_tkey)

            cr_id = sm4_decrypt(record["consultation_request_id"], mr_tkey)
            cr_id = int(cr_id.decode('utf-8'))
            print("cr_id:", cr_id)
            record["consultation_request_id"] = cr_id

            dc_id = sm4_decrypt(record["doctor_id"], mr_tkey)
            dc_id = int(dc_id.decode('utf-8'))
            print("dc_id:", dc_id)
            record["doctor_id"] = dc_id

            vi_da = sm4_decrypt(record["visit_date"], mr_tkey)
            vi_da = vi_da.decode()
            vi_da = str_to_datetime(vi_da)
            print("vi_da:", vi_da)
            record["visit_date"] = vi_da

            department = sm4_decrypt(record["department"], mr_tkey)
            department = department.decode()
            print("department:", department)
            record["department"]=department
            patient_complaint = sm4_decrypt(record["patient_complaint"], mr_tkey)
            patient_complaint = patient_complaint.decode()
            print("patient_complaint:", patient_complaint)
            record["patient_complaint"]=patient_complaint
            medical_history = sm4_decrypt(record["medical_history"], mr_tkey)
            medical_history = medical_history.decode()
            print("medical_history:", medical_history)
            record["medical_history"]=medical_history
            physical_examination = sm4_decrypt(record["physical_examination"], mr_tkey)
            physical_examination = physical_examination.decode()
            print("physical_examination:", physical_examination)
            record["physical_examination"]=physical_examination
            auxiliary_examination = sm4_decrypt(record["auxiliary_examination"], mr_tkey)
            auxiliary_examination = auxiliary_examination.decode()
            print("auxiliary_examination:", auxiliary_examination)
            record["auxiliary_examination"]=auxiliary_examination
            diagnosis = sm4_decrypt(record["diagnosis"], mr_tkey)
            diagnosis = diagnosis.decode()
            print("diagnosis:", diagnosis)
            record["diagnosis"]=diagnosis
            treatment_advice = sm4_decrypt(record["treatment_advice"], mr_tkey)
            treatment_advice = treatment_advice.decode()
            print("treatment_advice:", treatment_advice)
            record["treatment_advice"] = treatment_advice
        del akey
    return render_template('patient_medical_records.html', records=records)


'''
            cr_id = str(medical_record["consultation_request_id"]).encode('utf-8')
            medical_record["consultation_request_id"] = sm4_encrypt(cr_id, mr_key)

            dc_id = str(medical_record["doctor_id"]).encode('utf-8')
            medical_record["doctor_id"] = sm4_encrypt(dc_id, mr_key)

            vi_da=datetime_to_str(medical_record["visit_date"])
            medical_record["visit_date"] = sm4_encrypt(vi_da, mr_key)

            medical_record["department"] = sm4_encrypt(medical_record["department"], mr_key)
            medical_record["patient_complaint"] = sm4_encrypt(medical_record["patient_complaint"], mr_key)
            medical_record["medical_history"] = sm4_encrypt(medical_record["medical_history"], mr_key)
            medical_record["physical_examination"] = sm4_encrypt(medical_record["physical_examination"], mr_key)
            medical_record["auxiliary_examination"] = sm4_encrypt(medical_record["auxiliary_examination"], mr_key)
            medical_record["diagnosis"] = sm4_encrypt(medical_record["diagnosis"], mr_key)
            medical_record["treatment_advice"] = sm4_encrypt(medical_record["treatment_advice"], mr_key)
            '''

# 注销功能
@patient_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


