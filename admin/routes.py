import json
import tempfile

# from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from flask import Blueprint, render_template, request, redirect, url_for, session, send_file
from flask_login import login_user, login_required, logout_user, current_user

from admin.models import *
from config import User  # 假设 User 类在 app.py 中定义
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
            # print(results['id'], results['username'], results['password'])
            if results is None:
                message = '用户名不存在，请重试'
            else:
                # stored_password = results['password'].decode('utf-8')
                stored_password = results['password']
                sa = results['sa']
                # if check_password_hash(stored_password, password):
                if check_salt_sm3(password, sa, stored_password):
                    user = User(results['id'], results['username'], 'patient')
                    login_user(user)
                    # 将管理员的登录信息存储到 session 中
                    session['admin_id'] = results['id']
                    session['admin_username'] = results['username']
                    session['pw'] = password

                    return redirect(url_for('admin_bp.ad_home'))
                else:
                    message = '密码错误，请重试'
        except Error as e:
            print(f"routes_admin_login_Error: {e}")
            message = '登录失败，请重试'

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
        akey, bkey = generate_valid_sm2_key_pair()
        tkey = generate_pbkdf2_key(password, sa)
        akey = sm4_encrypt(akey, tkey)
        del tkey
        try:
            results = get_admin_login(username)
            # print(results['id'], results['username'], results['password'])
            if results is not None:
                message = '用户名存在，请重试'
                return render_template('admin_register.html', message=message)

            if create_admin_login(generate_admin_id(), username, hashed_password, sa, akey, bkey):
                message = '注册成功，请登录'
                return render_template('admin_register.html', message=message)
            else:
                message = '注册失败'
                return render_template('admin_register.html', message=message)
        except Error as e:
            print(f"routes_admin_login_Error: {e}")
            message = '注册失败，请重试'

    return render_template('admin_register.html', message=message)


# 增加修改个人用户名和密码的功能
@admin_bp.route('/login_info_change', methods=['GET', 'POST'])
@login_required
def login_info_change():
    message = None
    results = get_admin_login(current_user.username)
    if request.method == 'POST':
        old_password = request.form['old_password']
        stored_password = results['password']
        sa = results['sa']
        if check_salt_sm3(old_password, sa, stored_password):
            pass
        else:
            return render_template("admin_login_info_change.html", message="原密码输入错误")
        new_password = request.form['new_password']
        new_username = request.form['new_username']
        if new_password is not None:
            # 先解密旧有分片
            # 解密原密钥
            ad_akey = get_admin_akey(current_user.id, old_password)  # bytes
            ad_akey = ad_akey.decode()
            # 解密原分片
            my_share = get_admin_login(current_user.username)['adksh']  # 获取个人分片
            my_share = sm2_decrypt(my_share, ad_akey)
            # 生成新哈希值及新密钥
            hashed_password = generate_salt_sm3(new_password, sa)
            akey, bkey = generate_valid_sm2_key_pair()
            # 重新加密分片
            en_share = sm2_encrypt(my_share, akey)
            # 迭代对称密钥加密私钥
            tkey = generate_pbkdf2_key(new_password, sa)
            akey = sm4_encrypt(akey, tkey)
            del tkey
            if update_admin_login_password(current_user.id, hashed_password, akey, bkey, en_share):
                message = "密码已更新"
        if new_username is not None:
            if update_admin_login_username(current_user.id, new_username):
                message = "用户名已更新"

    return render_template("admin_login_info_change.html", message=message)


# 管理员的用户管理功能
# 包括管理员用户新加入时自动重新生成共同密钥对
# 导入医生用户的权限


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
    # print(me_records)
    return render_template('admin_review_list.html', records=me_records)


@admin_bp.route('/review_record/<record_id>', methods=['GET', 'POST'])
@login_required
def review_record(record_id):
    message = None
    medical_record = get_medical_record(record_id)
    ori_cr_id = medical_record["consultation_request_id"]
    print("原本的medical_record:", medical_record)
    if request.method == 'POST':
        review_opinions = request.form['review_opinions']
        action = request.form['action']

        if action == 'pass':
            mr_key = generate_sm4_key()
            # 加密环节，对medical_record操作
            cr_id = str(medical_record["consultation_request_id"]).encode('utf-8')
            medical_record["consultation_request_id"] = sm4_encrypt(cr_id, mr_key)
            dc_id = str(medical_record["doctor_id"]).encode('utf-8')
            medical_record["doctor_id"] = sm4_encrypt(dc_id, mr_key)
            vi_da = datetime_to_str(medical_record["visit_date"])
            medical_record["visit_date"] = sm4_encrypt(vi_da, mr_key)
            medical_record["department"] = sm4_encrypt(medical_record["department"], mr_key)
            medical_record["patient_complaint"] = sm4_encrypt(medical_record["patient_complaint"], mr_key)
            medical_record["medical_history"] = sm4_encrypt(medical_record["medical_history"], mr_key)
            medical_record["physical_examination"] = sm4_encrypt(medical_record["physical_examination"], mr_key)
            medical_record["auxiliary_examination"] = sm4_encrypt(medical_record["auxiliary_examination"], mr_key)
            medical_record["diagnosis"] = sm4_encrypt(medical_record["diagnosis"], mr_key)
            medical_record["treatment_advice"] = sm4_encrypt(medical_record["treatment_advice"], mr_key)
            # 密钥分片 分片均为字节串格式
            mr_key = hexstr_bytes(mr_key)
            print("加密病历用的sm4对称密钥", mr_key)
            shares = split_secret(mr_key, 2, 3)
            del mr_key
            _, sv_share = shares[0]
            _, pt_share = shares[1]
            _, ad_share = shares[2]
            print("服务器分片明文：", sv_share)
            print("患者分片明文：", pt_share)
            print("管理员分片明文", ad_share)
            # 服务器分片传入approve_medical_record函数一同参与函数归档，加密后的病历作为字典参与传参
            # 患者分片和管理员分片也需要进行公钥加密
            # 查找患者公钥
            pt_bkey = get_patient_key(medical_record["patient_id"])['b_key']
            pt_share = sm2_encrypt(pt_share, pt_bkey)
            print("患者分片密文：", pt_share)
            # 设置管理员共同公钥
            ad_bkey = get_admin_public_key()

            ad_share = sm2_encrypt(ad_share, ad_bkey)
            print("管理员分片密文：", ad_share)
            print("medical_record:", medical_record)
            if approve_medical_record(record_id, medical_record, sv_share) \
                    and create_review_record_pass(record_id, current_user.id):
                insert_patient_share(record_id, pt_share)
                insert_admin_share(record_id, ad_share)
                message = '病历已归档'
            else:
                message = '病历归档时产生错误'
        elif action == 'not_pass':
            if review_opinions is None:
                message = '不通过请填写审核意见'
            else:
                if create_review_record_not_pass(record_id, current_user.id, review_opinions) \
                        and reject_medical_record(record_id):
                    message = "病历已拒绝"
                else:
                    message = "病历未能拒绝"
    return render_template('admin_medical_record.html', medical_record=medical_record, message=message)


# 查看已有分片的功能
# 管理员的分片共同通过解密机制

@admin_bp.route('/retrieve_medical_records', methods=['GET', 'POST'])
@login_required
def retrieve_medical_records():
    message = ""
    if request.method == 'POST':
        patient_id = request.form['pt_id']
        start_date = datetime.strptime(request.form['start_date'], "%Y-%m-%d")
        end_date = datetime.strptime(request.form['end_date'], "%Y-%m-%d")
        admin_id = current_user.id  # 假设 current_user 是登录的管理员

        # 增加功能对比processing_medical_records表中的created_at，获取某指定时间段内的病历
        # 获取时间段内的病历记录
        pt_records = get_medical_records_by_patient_and_date(patient_id, start_date, end_date)
        if not pt_records:
            message = "在指定时间段内没有病历记录"
        else:
            # 调用函数创建调取提议
            success = create_retrieve_proposal(admin_id, patient_id, start_date, end_date)
            if success:
                message = "提议创建成功"
            else:
                message = "提议创建失败"
    return render_template('admin_retrieve_medical_records.html', message=message)


# 编写两个新的路由函数，一个用于查看自己之前提出的提议，如果提议被通过了，可以通过此页面进行后续调度
# 一个用于查看其他人提出的提议，选择是否同意其他人的提议

@admin_bp.route('/review_proposals', methods=['GET'])
@login_required
def review_proposals():
    admin_id = current_user.id  # 假设 current_user 是登录的管理员
    proposals = get_other_proposals(admin_id)

    return render_template('admin_review_proposals.html', proposals=proposals)


@admin_bp.route('/pass_proposal/<int:proposal_id>', methods=['POST'])
@login_required
def pass_proposal(proposal_id):
    message = ""
    admin_id = current_user.id  # 假设 current_user 是登录的管理员
    share = get_admin_login(current_user.username)['adksh']  # 获取个人分片
    admin_bkey = get_propose_admin_bkey(proposal_id)
    # 个人分片解密
    password = session.get('pw')
    ad_akey = get_admin_akey(current_user.id, password)  # bytes
    ad_akey = ad_akey.decode()
    share = sm2_decrypt(share, ad_akey)
    del ad_akey

    en_share = sm2_encrypt(share, admin_bkey)
    del share
    # 调用函数更新提议状态
    success = pass_retrieve_proposal(proposal_id, admin_id, en_share)

    if success:
        message = "提议已同意"
    else:
        message = "同意提议失败"
    return render_template('admin_review_proposals.html', message=message)


@admin_bp.route('/my_proposals', methods=['GET'])
@login_required
def my_proposals():
    admin_id = current_user.id  # 假设 current_user 是登录的管理员
    proposals = get_own_proposals(admin_id)
    return render_template('admin_my_proposals.html', proposals=proposals)


@admin_bp.route('/perform_action/<int:proposal_id>', methods=['GET'])
@login_required
def perform_action(proposal_id):
    # 获取提议的时间范围
    start_date, end_date = get_proposal_date_range(proposal_id)

    pt_id = get_propose_patient(proposal_id)
    # pt_records = get_medical_records_by_patient(pt_id)
    pt_records = get_medical_records_by_patient_and_date(pt_id, start_date, end_date)

    if not pt_records:
        return render_template('admin_perform_action.html', proposal_id=proposal_id,
                               message="在指定时间段内没有病历记录")

    # 获取个人私钥
    password = session.get('pw')
    ad_akey = get_admin_akey(current_user.id, password)  # bytes
    ad_akey = ad_akey.decode()
    to_combine = []

    # 需要解密自己的分片
    my_share = get_admin_login(current_user.username)['adksh']  # 获取个人分片
    my_share = sm2_decrypt(my_share, ad_akey)
    mysh_id = get_share_id(current_user.id)
    to_combine.append((mysh_id, my_share))
    # 调取数据库中retrieve_shares中所有提议号对应的分片
    pro_shares = get_proposal_shares(proposal_id)
    # 分片号到admins表中查找
    for share in pro_shares:
        sh_id = get_share_id(share['admin'])
        de_share = sm2_decrypt(share['share'], ad_akey)
        to_combine.append((sh_id, de_share))

    # print(to_combine)
    # 获取最低的门限数量（从proposal表中
    min = get_proposal_min(proposal_id)
    # 还原共同私钥
    mr_ad_akey = combine_secret(to_combine, min)
    mr_ad_akey = bytes_hexstr(mr_ad_akey)
    print("共同密钥-私钥：", mr_ad_akey)
    print("共同密钥-公钥：", get_admin_public_key())
    del ad_akey
    # mr_ad_akey = bytes_hexstr(mr_ad_akey)
    # 解密患者病历
    # 暂时先显示在页面上，如果可以实现再考虑以什么格式导出
    # print(pt_records)
    for record in pt_records:
        mr_ad_sh = get_ad_sh_by_medical_record(record['id'])['sh']
        print("en mr_ad_sh:", mr_ad_sh)
        mr_ad_sh = sm2_decrypt(mr_ad_sh, mr_ad_akey)
        print("mr_ad_sh:", mr_ad_sh)

        mr_ad_sh = (3, mr_ad_sh)
        mr_sv_sh = (1, record['server_share'])
        to_combine = [mr_sv_sh, mr_ad_sh]
        print("还原病历对称密钥时使用的分片列表：", to_combine)
        mr_tkey = combine_secret(to_combine, 2)
        mr_tkey = bytes_hexstr(mr_tkey)
        print("mr_teky:", mr_tkey)

        print("record-consultation_request_id:", record["consultation_request_id"])
        cr_id = sm4_decrypt(record["consultation_request_id"], mr_tkey)
        print("cr_id:", cr_id)
        cr_id = int(cr_id.decode('utf-8'))
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
        record["department"] = department
        patient_complaint = sm4_decrypt(record["patient_complaint"], mr_tkey)
        patient_complaint = patient_complaint.decode()
        print("patient_complaint:", patient_complaint)
        record["patient_complaint"] = patient_complaint
        medical_history = sm4_decrypt(record["medical_history"], mr_tkey)
        medical_history = medical_history.decode()
        print("medical_history:", medical_history)
        record["medical_history"] = medical_history
        physical_examination = sm4_decrypt(record["physical_examination"], mr_tkey)
        physical_examination = physical_examination.decode()
        print("physical_examination:", physical_examination)
        record["physical_examination"] = physical_examination
        auxiliary_examination = sm4_decrypt(record["auxiliary_examination"], mr_tkey)
        auxiliary_examination = auxiliary_examination.decode()
        print("auxiliary_examination:", auxiliary_examination)
        record["auxiliary_examination"] = auxiliary_examination
        diagnosis = sm4_decrypt(record["diagnosis"], mr_tkey)
        diagnosis = diagnosis.decode()
        print("diagnosis:", diagnosis)
        record["diagnosis"] = diagnosis
        treatment_advice = sm4_decrypt(record["treatment_advice"], mr_tkey)
        treatment_advice = treatment_advice.decode()
        print("treatment_advice:", treatment_advice)
        record["treatment_advice"] = treatment_advice
        record["doctor_signature"] = record["doctor_signature"].decode()
    del mr_ad_akey

    # 创建用于存储病历的字典列表
    medical_records_list = []
    for record in pt_records:
        to_cal = f"{record['consultation_request_id']}-{record['patient_complaint']}-{record['medical_history']}-" \
                 f"{record['physical_examination']}-{record['auxiliary_examination']}-{record['diagnosis']}-{record['treatment_advice']}"
        # 将记录转换为字典
        record_dict = {
            "medical_record_id": record["id"],
            "patient_id": record["patient_id"],
            "doctor_id": record["doctor_id"],
            "consultation_request_id": record["consultation_request_id"],
            "visit_date": record["visit_date"].strftime('%Y-%m-%d %H:%M:%S')
            if isinstance(record["visit_date"], datetime) else record["visit_date"],
            "department": record["department"],
            "patient_complaint": record["patient_complaint"],
            "medical_history": record["medical_history"],
            "physical_examination": record["physical_examination"],
            "auxiliary_examination": record["auxiliary_examination"],
            "diagnosis": record["diagnosis"],
            "treatment_advice": record["treatment_advice"],
            "doctor_signature": record["doctor_signature"],
            "created_at": record["created_at"].strftime('%Y-%m-%d %H:%M:%S')
            if isinstance(record["created_at"], datetime) else record["created_at"],
            "doctor_public_key": get_doctor_key(record["doctor_id"])['b_key'],
            "to_cal": to_cal,
            "to_verify_signature": generate_sm3_hash(to_cal)
        }
        medical_records_list.append(record_dict)
    '''
    # 定义 JSON 文件的路径和名称
    json_file_path = f"medical_records_proposal_{proposal_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    # 将字典列表写入 JSON 文件
    with open(json_file_path, 'w', encoding='utf-8') as json_file:
        json.dump(medical_records_list, json_file, ensure_ascii=False, indent=4)
    '''
    from medical_record_editor import json_to_word, json_to_pdf
    # 检查请求中是否包含下载参数
    if request.args.get('download') == 'true':
        format = request.args.get('format', 'json')  # 默认为 json
        if format == 'word':
            with tempfile.NamedTemporaryFile(delete=False, suffix='.docx') as temp_file:
                word_file_path = temp_file.name
                json_to_word(medical_records_list, word_file_path)
            return send_file(word_file_path, as_attachment=True,
                             download_name=f'medical_records_proposal_{proposal_id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.docx')
        elif format == 'pdf':
            with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as temp_file:
                pdf_file_path = temp_file.name
                json_to_pdf(medical_records_list, pdf_file_path)
            return send_file(pdf_file_path, as_attachment=True,
                             download_name=f'medical_records_proposal_{proposal_id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf')
        elif format == 'json':

            # 创建一个临时文件
            with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as temp_file:
                json_file_path = temp_file.name
                # 将字典列表写入临时 JSON 文件
                with open(json_file_path, 'w', encoding='utf-8') as json_file:
                    json.dump(medical_records_list, json_file, ensure_ascii=False, indent=4)
            # 发送文件给用户
            return send_file(json_file_path, as_attachment=True,
                         download_name=f'medical_records_proposal_{proposal_id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
        else:
            return "不支持的文件格式", 400
    else:
        # 渲染页面
        return render_template('admin_perform_action.html', proposal_id=proposal_id, records=pt_records)
    # return render_template('admin_perform_action.html', proposal_id=proposal_id, records=pt_records)


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
