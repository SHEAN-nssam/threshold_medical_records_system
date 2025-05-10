import mysql.connector
from mysql.connector import Error
from config import db_config
from datetime import datetime
from crypto import *

# 获取登录信息
def get_doctor_login(username):
    connection = None;cursor = None
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        # 查询登录信息
        cursor.execute("SELECT * FROM doctors WHERE username = %s ", (username,))
        # 返回查询结果
        return cursor.fetchone()
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        # 打印错误信息
        print(f"models_get_doctor_login_Error: {e}")
        return None
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


def get_doctor_login_id(user_id):
    connection = None;cursor = None
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        # 查询登录信息
        cursor.execute("SELECT * FROM doctors WHERE id = %s ", (user_id,))
        # 返回查询结果
        return cursor.fetchone()
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        # 打印错误信息
        print(f"models_get_doctor_login_Error: {e}")
        return None
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


# 创建医生登录信息
def create_doctor_login(user_id, username, password_hash, salt, akey, bkey):
    connection = None; cursor = None
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        # 插入患者登录信息
        cursor.execute("INSERT INTO doctors (id, username, password, sa, a_key, b_key) VALUES (%s, %s, %s, %s, %s, %s)",
                       (user_id, username, password_hash, salt, akey, bkey))
        # 提交事务
        connection.commit()
        return True
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        # 打印错误信息
        print(f"models_create_doctor_login_Error: {e}")
        return False
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


# 创建医生个人信息（待改
def create_doctor_profile(user_id, full_name, gender, birth_date, department, title):
    connection = None;cursor = None
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        # 插入医生个人信息
        cursor.execute("INSERT INTO doctor_profiles (id, full_name, gender, birth_date, department, title) VALUES (%s, %s, %s, %s,%s,%s)",
                       (user_id, full_name, gender, birth_date, department, title))
        # 提交事务
        connection.commit()
        return True
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        # 打印错误信息
        print(f"models_create_doctor_profile_Error: {e}")
        return False
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


def get_doctor_profile(user_id):
    connection = None; cursor = None
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        # 查询登录信息
        cursor.execute("SELECT * FROM doctor_profiles WHERE id = %s ", (user_id,))
        # 返回查询结果
        return cursor.fetchone()
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        # 打印错误信息
        print(f"models_get_doctor_login_Error: {e}")
        return None
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


def set_doctor_online(user_id):
    if get_doctor_login_id(user_id) is None:
        print(f"{user_id} this doctor don't exist")
        return False
    connection = None
    cursor = None
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        # 插入医生个人信息
        cursor.execute("UPDATE doctors SET is_online = 1 WHERE id = %s", (user_id,))
        # 提交事务
        connection.commit()
        return True
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        # 打印错误信息
        print(f"set_doctor_online_Error: {e}")
        return False
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


def set_doctor_offline(user_id):
    if get_doctor_login_id(user_id) is None:
        return False
    connection = None
    cursor = None
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        # 插入医生个人信息
        cursor.execute("UPDATE doctors SET is_online = 0 WHERE id = %s", (user_id,))
        # 提交事务
        connection.commit()
        return True
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        # 打印错误信息
        print(f"set_doctor_offline_Error: {e}")
        return False
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


def get_doctor_akey(doctor_id, password):
    connection = None
    cursor = None
    akey = None
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        # 查询登录信息
        cursor.execute("SELECT id,sa,a_key FROM doctors WHERE id = %s ", (doctor_id,))
        result = cursor.fetchone()
        salt = result['sa']
        tkey = generate_pbkdf2_key(password, salt)
        akey = sm4_decrypt(result['a_key'], tkey)
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        # 打印错误信息
        print(f"models_get_doctor_akey_Error: {e}")
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return akey


def get_patient_key(pt_id):
    '''
    获取患者公钥
    :param pt_id:患者id，int型
    :return: 患者公钥，字典型['b_key']:str
    '''
    connection = None
    cursor = None
    pt_key = []
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT b_key FROM patients WHERE id = %s",
            (pt_id,)
        )
        pt_key = cursor.fetchone()
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        print(f"Error in get_patient_key: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return pt_key

def get_consultation_requests(doctor_id):
    connection = None
    cursor = None
    requests = []
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT * FROM consultation_requests WHERE doctor_id = %s AND status IN ('pending', 'accepted')",
            (doctor_id,)
        )
        requests = cursor.fetchall()
        '''
        if requests:
            print(requests)
        else:
            print("no request")
            '''

    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        print(f"Error in get_consultation_requests: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return requests


def update_consultation_request(request_id, status):
    connection = None
    cursor = None
    success = False
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        cursor.execute(
            "UPDATE consultation_requests SET status = %s WHERE id = %s",
            (status, request_id)
        )
        connection.commit()
        success = True
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        print(f"Error in update_consultation_request: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return success

# 从问诊申请号获得患者的id
def get_patient_id(request_id):
    connection = None
    cursor = None
    patient_id = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        cursor.execute("SELECT patient_id FROM consultation_requests WHERE id = %s", (request_id,))
        result = cursor.fetchone()
        if result:
            patient_id = result[0]
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        print(f"Error in get_patient_id: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return patient_id

'''
def get_notification_message(status):
    if status == 'accepted':
        return 'Your consultation request has been accepted by the doctor.'
    elif status == 'rejected':
        return 'Your consultation request has been rejected by the doctor.'
    elif status == 'completed':
        return 'The doctor has ended your consultation.'
    return 'Unknown status'
'''
def get_notification_message(status, doctor_name):
    """
    根据状态生成通知消息
    :param status: 通知状态（accepted, rejected, completed）
    :param doctor_name: 医生姓名
    :return: 通知消息
    """
    if status == 'accepted':
        return f'Your consultation request has been accepted by Dr. {doctor_name}.'
    elif status == 'rejected':
        return f'Your consultation request has been rejected by Dr. {doctor_name}.'
    elif status == 'completed':
        return f'The consultation with Dr. {doctor_name} has been completed.'
    return 'Unknown status'

def add_notification(patient_id, consultation_request_id, status):
    connection = None
    cursor = None
    success = False
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # 获取医生ID
        cursor.execute("SELECT doctor_id FROM consultation_requests WHERE id = %s", (consultation_request_id,))
        consultation_request = cursor.fetchone()
        if not consultation_request:
            print("Consultation request not found.")
            return False
        doctor_id = consultation_request['doctor_id']

        # 获取医生姓名
        cursor.execute("SELECT full_name FROM doctor_profiles WHERE id = %s", (doctor_id,))
        doctor_profile = cursor.fetchone()
        if not doctor_profile:
            print("Doctor profile not found.")
            return False
        doctor_name = doctor_profile['full_name']

        message = get_notification_message(status,doctor_name)
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute(
            "INSERT INTO patient_notifications (patient_id, consultation_request_id, message, time) VALUES (%s, %s, %s, %s)",
            (patient_id, consultation_request_id, message, current_time)
        )
        connection.commit()
        success = True
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        print(f"Error in add_notification: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return success


def get_active_consultation_requests(doctor_id):
    connection = None
    cursor = None
    requests = []
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT * FROM consultation_requests WHERE doctor_id = %s AND status = 'accepted'",
            (doctor_id,)
        )
        requests = cursor.fetchall()
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        print(f"Error in get_active_consultation_requests: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return requests


def create_medical_record(consultation_request_id,patient_id):
    """
    创建新的病历记录，自动填写病历号、问诊申请号、患者号、医生号、问诊时间、科室和病历创建时间，并将病历状态设置为 'uc'（未完成）。
    :param consultation_request_id: 问诊申请ID
    :return: 创建成功返回 True，否则返回 False
    """
    connection = None
    cursor = None
    success = False
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # 获取问诊申请信息
        cursor.execute("SELECT * FROM consultation_requests WHERE id = %s", (consultation_request_id,))
        consultation_request = cursor.fetchone()
        if not consultation_request:
            print("Consultation request not found.")
            return False

        # patient_id = consultation_request['patient_id']
        doctor_id = consultation_request['doctor_id']
        visit_date = consultation_request['request_time']

        # 获取医生的科室信息
        cursor.execute("SELECT department FROM doctor_profiles WHERE id = %s", (doctor_id,))
        department_result = cursor.fetchone()
        if not department_result:
            print("Doctor department not found.")
            return False
        department = department_result['department']

        # 插入病历记录
        cursor.execute(
            """
            INSERT INTO processing_medical_records 
            (consultation_request_id, patient_id, doctor_id, visit_date, department, status, created_at)
            VALUES 
            (%s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
            """,
            (consultation_request_id, patient_id, doctor_id, visit_date, department, 'uc')
        )
        connection.commit()
        success = True
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        print(f"Error in create_medical_record: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return success


def update_medical_record(record_id, patient_complaint, medical_history, physical_examination, auxiliary_examination, diagnosis, treatment_advice):
    """
    更新病历记录中的详细信息。
    :param record_id: 病历记录ID
    :param patient_complaint: 患者主诉
    :param medical_history: 病史
    :param physical_examination: 体格检查
    :param auxiliary_examination: 辅助检查
    :param diagnosis: 诊断
    :param treatment_advice: 治疗建议
    :return: 更新成功返回 True，否则返回 False
    """
    connection = None
    cursor = None
    success = False
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # 更新病历记录
        cursor.execute(
            """
            UPDATE processing_medical_records
            SET
                patient_complaint = %s,
                medical_history = %s,
                physical_examination = %s,
                auxiliary_examination = %s,
                diagnosis = %s,
                treatment_advice = %s
            WHERE id = %s
            """,
            (patient_complaint, medical_history, physical_examination, auxiliary_examination, diagnosis, treatment_advice, record_id)
        )
        connection.commit()
        success = True
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        print(f"Error in update_medical_record: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return success


def submit_medical_record(record_id, doctor_signature):
    """
    提交病历，自动生成医生签名并更新病历状态为 'wr'（待审核）。
    :param record_id: 病历记录ID
    :return: 提交成功返回 True，否则返回 False
    """
    connection = None
    cursor = None
    success = False
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # 获取医生ID和当前时间
        cursor.execute("SELECT doctor_id FROM processing_medical_records WHERE id = %s", (record_id,))
        medical_record = cursor.fetchone()
        if not medical_record:
            print("Medical record not found.")
            return False

        doctor_id = medical_record['doctor_id']
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # 签名格式错误，待更改
        # doctor_signature = f"{doctor_id}-{doctor_id}-{current_time}"

        # 更新病历状态和签名
        cursor.execute(
            """
            UPDATE processing_medical_records
            SET
                doctor_signature = %s,
                status = 'wr'
            WHERE id = %s
            """,
            (doctor_signature, record_id)
        )
        connection.commit()
        success = True
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        print(f"Error in submit_medical_record: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return success


def update_medical_record_by_request(request_id, patient_complaint, medical_history, physical_examination, auxiliary_examination, diagnosis, treatment_advice):
    """
    更新病历记录中的详细信息。
    :param request_id: 问诊申请ID
    :param patient_complaint: 患者主诉
    :param medical_history: 病史
    :param physical_examination: 体格检查
    :param auxiliary_examination: 辅助检查
    :param diagnosis: 诊断
    :param treatment_advice: 治疗建议
    :return: 更新成功返回 True，否则返回 False
    """
    connection = None
    cursor = None
    success = False
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        # 更新病历记录
        cursor.execute(
            """
            UPDATE processing_medical_records
            SET
                patient_complaint = %s,
                medical_history = %s,
                physical_examination = %s,
                auxiliary_examination = %s,
                diagnosis = %s,
                treatment_advice = %s
            WHERE consultation_request_id = %s
            """,
            (patient_complaint, medical_history, physical_examination, auxiliary_examination, diagnosis, treatment_advice, request_id)
        )
        connection.commit()
        success = True
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        print(f"Error in update_medical_record_by_request: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return success


def submit_medical_record_by_request(request_id, doctor_signature):
    """
    提交病历，自动生成医生签名并更新病历状态为 'wr'（待审核）。
    :param request_id: 病历记录ID
    doctor_signature:医生电子签名
    :return: 提交成功返回 True，否则返回 False
    """
    connection = None
    cursor = None
    success = False
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # 获取医生ID和当前时间
        cursor.execute("SELECT doctor_id FROM processing_medical_records WHERE consultation_request_id = %s", (request_id,))
        medical_record = cursor.fetchone()
        if not medical_record:
            print("Medical record not found.")
            return False

        doctor_id = medical_record['doctor_id']
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # 签名格式错误，待更改
        # doctor_signature = f"{doctor_id}-{doctor_id}-{current_time}"

        # 更新病历状态和签名
        cursor.execute(
            """
            UPDATE processing_medical_records
            SET
                doctor_signature = %s,
                status = 'wr'
            WHERE consultation_request_id = %s
            """,
            (doctor_signature, request_id)
        )
        connection.commit()

        success = True
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        print(f"Error in submit_medical_record_by_request: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return success


def get_medical_record(record_id):
    '''
    从病历号获取病历
    :param record_id: 病历号
    :return: processing_medical_records格式的字典
    '''
    connection = None
    cursor = None
    medical_record = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT * FROM processing_medical_records WHERE id = %s",
            (record_id,)
        )
        medical_record = cursor.fetchone()
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        print(f"Error in get_medical_record: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return medical_record


def get_medical_records_by_request(request_id):
    '''
    从问诊申请号获取病历
    :param request_id:问诊申请号
    :return: processing_medical_records格式的字典
    '''
    connection = None
    cursor = None
    medical_records = []
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT * FROM processing_medical_records WHERE consultation_request_id = %s ORDER BY created_at DESC",
            (request_id,)
        )
        medical_records = cursor.fetchone()
        # print(f"{request_id}request-find-{medical_records}")
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        print(f"Error in get_medical_records_by_request: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return medical_records

# 自动获取医生id为指定id，并且状态为na的病历，并查询审核记录中对应的最新审核意见（时间降序），整合为特定格式后返回
# 需要：病历id，审核意见，审核时间，负责管理员
def get_records_correct(doctor_id):
    connection = None
    cursor = None
    review_records = []
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT id FROM processing_medical_records WHERE status = 'na' ORDER BY created_at DESC"
        )
        mrs = cursor.fetchall()
        # print(mrs)
        mr_id = [mr['id'] for mr in mrs]
        # print(len(mr_id))
        if len(mr_id) < 1:
            return None
        placeholders = ', '.join(['%s'] * len(mr_id))
        cursor.execute(f"SELECT * FROM review_records WHERE mr_id in ({placeholders})", mr_id)
        review_records = cursor.fetchall()
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        print(f"Error in get_medical_records_by_request: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return review_records


def get_review_record(review_record_id):
    '''
    从审核记录号获取审核记录
    :param review_record_id:
    :return: review_records格式的字典
    '''
    connection = None
    cursor = None
    review_record = []
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT * FROM review_records WHERE id = %s ORDER BY review_date DESC", (review_record_id,)
        )
        review_record = cursor.fetchone()
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        print(f"Error in get_review_record: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return review_record


if __name__ == '__main__':
    r = get_records_correct(20000001)
    if r:
        print(r)
    else:
        print("no record needs correct")
    '''
    r = get_doctor_login("李四")
    if r is None:
        print("not exist")
    else:
        print(r)
    '''