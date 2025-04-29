import mysql.connector
from mysql.connector import Error
from config import db_config
from datetime import datetime


# 获取登录信息
def get_admin_login(username):
    connection = None
    cursor = None
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        # 查询患者登录信息
        cursor.execute("SELECT * FROM admins WHERE username = %s ", (username,))
        # 返回查询结果
        return cursor.fetchone()
    except Error as e:
        # 打印错误信息
        print(f"models_get_admin_login_Error: {e}")
        return None
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


# 创建登录信息
def create_admin_login(user_id, username, password_hash, salt, akey, bkey):
    connection = None
    cursor = None
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        # 插入患者登录信息
        cursor.execute("INSERT INTO admins (id, username, password, sa, a_key, b_key) VALUES (%s, %s, %s, %s, %s, %s)",
                       (user_id, username, password_hash, salt, akey, bkey))
        # 提交事务
        connection.commit()
        return True
    except Error as e:
        # 打印错误信息
        print(f"models_create_admin_login_Error: {e}")
        return False
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


def get_medical_record(record_id):
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
        print(f"Error in get_medical_record: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return medical_record


# 编写函数获取所有状态为待审核的病历，并通过网页显示
def get_medical_records_waiting_review():
    connection = None
    cursor = None
    me_records = []
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        cursor.execute("SELECT * FROM processing_medical_records WHERE status = 'wr' ")
        # 提交事务
        me_records = cursor.fetchall()
        if me_records:
            print(me_records)
        else:
            print("no record")
    except Error as e:
        # 打印错误信息
        print(f"get_medical_records_waiting_review_Error: {e}")
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return me_records

def get_admin_public_key():
    """
    获取管理员共用的公钥
    :return: 管理员共用的公钥（字节串）或 None（如果未找到）
    """
    connection = None
    cursor = None
    public_key = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # 查询 admin_public_keys 表中最新的公钥
        cursor.execute("SELECT public_key FROM admin_public_keys ORDER BY created_at DESC LIMIT 1")
        result = cursor.fetchone()
        if result:
            public_key = result["public_key"]
    except Error as e:
        print(f"Error: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return public_key



def approve_medical_record(record_id, mr, server_share):
    """
    将指定病历从进程中病历表中删除，加入归档病历表中
    record_id (int): 病历ID
    mr(dictionary): 与进程中病历表格式一致的字典，取其中和归档病历格式一致的部分插入归档病历表
    server_share(bytes): 服务器分片，作为归档病历一部分插入
    Returns:bool: 操作是否成功
    """
    connection = None
    cursor = None
    success = False
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # 使用 mr 中的字段值更新病历状态和内容
        update_query = (
            "UPDATE processing_medical_records "
            "SET status = 'ap' "
            "WHERE id = %s"
        )
        update_values = (record_id,)
        cursor.execute(update_query, update_values)

        # 获取更新后的病历数据
        cursor.execute("SELECT * FROM processing_medical_records WHERE id = %s", (record_id,))
        record = cursor.fetchone()


        # 插入归档病历表
        insert_query = (
                "INSERT INTO archived_medical_records "
                "(consultation_request_id, patient_id, doctor_id, visit_date, "
                "department, patient_complaint, medical_history, "
                "physical_examination, auxiliary_examination, diagnosis, "
                "treatment_advice, doctor_signature, created_at, server_share) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            )

        insert_values = (
                mr['consultation_request_id'], mr['patient_id'], mr['doctor_id'], mr['visit_date'],
                mr['department'], mr['patient_complaint'], mr['medical_history'],
                mr['physical_examination'], mr['auxiliary_examination'], mr['diagnosis'],
                mr['treatment_advice'], mr['doctor_signature'], mr['created_at'], server_share
        )
        cursor.execute(insert_query, insert_values)

        # 删除原病历
        cursor.execute("DELETE FROM processing_medical_records WHERE id = %s", (record_id,))


        connection.commit()
        success = True
    except Error as e:
        print(f"approve_medical_record_Error: {e}")
        if connection:
            connection.rollback()
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return success


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
        print(f"Error in get_patient_key: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return pt_key


# 分别插入患者分片和管理员分片
def insert_patient_share(mrid,pt_share):
    connection = None
    cursor = None
    success = False
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        # 插入患者分片
        cursor.execute("INSERT INTO pt_sh (mr_id, sh) VALUES (%s, %s)",
                       (mrid, pt_share))
        # 提交事务
        connection.commit()
        success=True
    except Error as e:
        # 打印错误信息
        print(f"insert_patient_share_Error: {e}")
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
        return success


def insert_admin_share(mrid,ad_share):
    connection = None
    cursor = None
    success = False
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        # 插入患者分片
        cursor.execute("INSERT INTO ad_sh (mr_id, sh) VALUES (%s, %s)",
                       (mrid, ad_share))
        # 提交事务
        connection.commit()
        success=True
    except Error as e:
        # 打印错误信息
        print(f"insert_patient_share_Error: {e}")
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
        return success


# 编写方法将审核的病历置为不通过status = 'na'
def reject_medical_record(record_id):
    """
    将指定病历的状态设置为不通过（'na'），并记录拒绝原因
    Args:record_id (int): 病历ID
    Returns:bool: 操作是否成功
    """
    connection = None
    cursor = None
    success = False
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        # 更新病历状态为不通过，并记录拒绝原因
        cursor.execute(
            "UPDATE processing_medical_records SET status = 'na' WHERE id = %s",
            (record_id,)
        )
        connection.commit()
        success = True
    except Error as e:
        print(f"reject_medical_record_Error: {e}")
        if connection:
            connection.rollback()
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return success

# 编写函数创建通过的的审核记录
def create_review_record_pass(mr_id,ad_id):
    '''
    :param mr_id: 被审核的病历号
    :param ad_id: 审核的管理员号
    :return: 创建成功与否
    '''
    connection = None
    cursor = None
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # 插入
        cursor.execute("INSERT INTO review_records_archived (mr_id, result, review_by, review_date) VALUES (%s, %s, %s, %s)",
                       (mr_id, True, ad_id, current_time))
        # 提交事务
        connection.commit()
        return True
    except Error as e:
        # 打印错误信息
        print(f"create_review_record_pass_Error: {e}")
        return False
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

# 编写函数创建带有审核意见的审核记录
def create_review_record_not_pass(mr_id,ad_id,opi):
    '''
    编写函数创建带有审核意见的审核记录（主要是未通过的记录）
    :param mr_id: 被审核的病历号
    :param ad_id: 审核的管理员号
    :param opi:审核意见
    :return: 创建成功与否
    '''
    connection = None
    cursor = None
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # 插入
        cursor.execute("INSERT INTO review_records_processing (mr_id, result, review_opinions, review_by, review_date) VALUES "
                       "(%s, %s, %s, %s, %s)",
                       (mr_id, False, opi, ad_id, current_time))
        # 提交事务
        connection.commit()
        return True
    except Error as e:
        # 打印错误信息
        print(f"create_review_record_not_pass_Error: {e}")
        return False
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

#管理员分片机制


if __name__ == '__main__':
    r = get_admin_login("张四")
    if r is None:
        print("not exist")
    else:
        print(r)

    get_medical_records_waiting_review()

