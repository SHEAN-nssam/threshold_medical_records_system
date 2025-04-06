import mysql.connector
from mysql.connector import Error
from config import db_config
from datetime import datetime

# 获取患者登录信息
def get_patient_login(username):
    connection = None
    cursor = None
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        # 查询患者登录信息
        cursor.execute("SELECT id, username, password FROM patients WHERE username = %s ", (username,))
        # 返回查询结果
        return cursor.fetchone()
    except Error as e:
        # 打印错误信息
        print(f"models_get_patient_login_Error: {e}")
        return None
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


# 创建患者登录信息
def create_patient_login(user_id, username, password_hash):
    connection = None;cursor = None
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        connection.start_transaction()

        # 插入患者登录信息
        cursor.execute("INSERT INTO patients (id, username, password) VALUES (%s, %s, %s)",
                       (user_id, username, password_hash))
        # 提交事务
        connection.commit()

        return True
    except Error as e:
        # 回滚事务
        if connection and connection.is_connected():
            connection.rollback()
        # 打印错误信息
        print(f"models_create_patient_login_Error: {e}")
        return False
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


def get_patient_profile(user_id):
    connection = None;cursor = None
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        # 查询登录信息
        cursor.execute("SELECT * FROM patient_profiles WHERE id = %s ", (user_id,))
        # 返回查询结果
        return cursor.fetchone()
    except Error as e:
        # 打印错误信息
        print(f"models_get_patient_profile_Error: {e}")
        return None
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


# 创建患者个人信息
def create_patient_profile(user_id, full_name, gender, birth_date):
    connection = None;cursor = None
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        connection.start_transaction()

        # 插入患者个人信息
        cursor.execute("INSERT INTO patient_profiles (id, full_name, gender, birth_date) VALUES (%s, %s, %s, %s)",
                       (user_id, full_name, gender, birth_date))
        # 提交事务
        connection.commit()

        return True
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        # 打印错误信息
        print(f"models_create_patient_profile_Error: {e}")
        return False
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

# 编写方法使患者可以获得在线的医生列表（进阶：最好可以按照科室划分
# 从doctors表（医生登录表）获取在线医生的id（is_online=1），再由id查阅doctor_profiles表，获取在线医生的信息
# 将在线医生的信息（字典数组）整合后，可以达成按照科室划分分别查看的效果


def get_online_doctors():
    """
    获取所有在线医生的信息
    :return: 在线医生的字典列表
    """
    connection = None
    cursor = None
    online_doctors = []

    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # 获取所有在线医生的ID
        cursor.execute("SELECT id FROM doctors WHERE is_online = 1")
        online_doctor_ids = cursor.fetchall()

        if not online_doctor_ids:
            return online_doctors  # 如果没有在线医生，返回空列表

        # 提取医生ID列表
        doctor_ids = [doc['id'] for doc in online_doctor_ids]

        # 根据医生ID列表获取医生的详细信息
        placeholders = ', '.join(['%s'] * len(doctor_ids))
        cursor.execute(
            f"SELECT id, full_name, gender, birth_date, department, title FROM doctor_profiles WHERE id IN ({placeholders})",
            doctor_ids
        )
        online_doctors = cursor.fetchall()

    except Error as e:
        print(f"Error in get_online_doctors: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

    return online_doctors


def create_consultation_request(patient_id, doctor_id):
    connection = None
    cursor = None
    success = False
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        connection.start_transaction()

        cursor.execute(
            "INSERT INTO consultation_requests (patient_id, doctor_id, status, request_time) VALUES (%s, %s, %s, %s)",
            (patient_id, doctor_id, 'pending', current_time)
        )
        connection.commit()
        success = True
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        print(f"Error in create_consultation_request: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return success


def get_patient_notifications(patient_id):
    connection = None
    cursor = None
    notifications = []
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT * FROM patient_notifications WHERE patient_id = %s ORDER BY time DESC",
            (patient_id,)
        )
        notifications = cursor.fetchall()
    except Error as e:
        print(f"Error in get_patient_notifications: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return notifications


def get_notification_message(status):
    if status == 'accepted':
        return 'Your consultation request has been accepted by the doctor.'
    elif status == 'rejected':
        return 'Your consultation request has been rejected by the doctor.'
    elif status == 'completed':
        return 'The doctor has finished your consultation.'
    return 'Unknown status'


def get_medical_records(user_id):
    connection = None
    cursor = None
    mr = []
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT * FROM medical_records WHERE patient_id = %s and status = 'ap' ORDER BY created_at DESC",
            (user_id,)
        )
        mr = cursor.fetchall()
    except Error as e:
        print(f"Error in get_patient_notifications: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return mr


if __name__ == '__main__':
    r=get_medical_records(30000001)
    if r:
        print(r)
    else:
        print("no records")
    '''
    print(get_online_doctors())
    print(bool(get_online_doctors()))
    
    r = get_patient_profile(30000001)
    if r is None:
        print("not exist")
    else:
        print(r)
    '''