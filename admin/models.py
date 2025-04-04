import mysql.connector
from mysql.connector import Error
from config import db_config
from datetime import datetime
# 获取登录信息
def get_admin_login(username):
    connection = None;cursor = None
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        # 查询患者登录信息
        cursor.execute("SELECT id, username, password FROM admins WHERE username = %s ", (username,))
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
def create_admin_login(user_id, username, password_hash):
    connection = None;cursor = None
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        # 插入患者登录信息
        cursor.execute("INSERT INTO admins (id, username, password) VALUES (%s, %s, %s)",
                       (user_id, username, password_hash))
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
            "SELECT * FROM medical_records WHERE id = %s",
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

        cursor.execute("SELECT * FROM medical_records WHERE status = 'wr' ")
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

# 编写方法将审核的病历置为通过status = 'ap'
def approve_medical_record(record_id):
    """
    将指定病历的状态设置为通过（'ap'）
    Args: record_id (int): 病历ID
    Returns:bool: 操作是否成功
    """
    connection = None
    cursor = None
    success = False
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        # 更新病历状态为通过
        cursor.execute(
            "UPDATE medical_records SET status = 'ap' WHERE id = %s",
            (record_id,)
        )
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
            "UPDATE medical_records SET status = 'na' WHERE id = %s",
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
        cursor.execute("INSERT INTO review_records (mr_id, result, review_by, review_date) VALUES (%s, %s, %s, %s)",
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
        cursor.execute("INSERT INTO review_records (mr_id, result, review_opinions, review_by, review_date) VALUES "
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


if __name__ == '__main__':
    r = get_admin_login("张四")
    if r is None:
        print("not exist")
    else:
        print(r)

    get_medical_records_waiting_review()

