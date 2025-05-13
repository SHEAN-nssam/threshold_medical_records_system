import mysql.connector
from mysql.connector import Error

from config import db_config
from crypto import *


# 获取登录信息
def get_admin_login(username):
    connection = None
    cursor = None
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        # 查询登录信息
        cursor.execute("SELECT * FROM admins WHERE username = %s ", (username,))
        # 返回查询结果
        return cursor.fetchone()
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
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
        if connection and connection.is_connected():
            connection.rollback()
        # 打印错误信息
        print(f"models_create_admin_login_Error: {e}")
        return False
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


def update_admin_login_username(ad_id, username):
    connection = None
    cursor = None
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        # 插入患者登录信息
        cursor.execute("UPDATE admins SET username = %s WHERE id = %s",
                       (username, ad_id))
        # 提交事务
        connection.commit()
        return True
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        # 打印错误信息
        print(f"models_update_admin_login_username_Error: {e}")
        return False
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


def update_admin_login_password(ad_id, password, a_key, b_key, adksh):
    connection = None
    cursor = None
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        # 插入患者登录信息
        cursor.execute("UPDATE admins SET password = %s, a_key=%s, b_key=%s, adksh=%s WHERE id = %s",
                       (password, a_key, b_key, adksh, ad_id))
        # 提交事务
        connection.commit()
        return True
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        # 打印错误信息
        print(f"models_update_admin_login_password_Error: {e}")
        return False
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


def get_admin_akey(admin_id, password):
    connection = None
    cursor = None
    akey = None
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        # 查询登录信息
        cursor.execute("SELECT id,sa,a_key FROM admins WHERE id = %s ", (admin_id,))
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
        if connection and connection.is_connected():
            connection.rollback()
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
        '''
        if me_records:
            print(me_records)
        else:
            print("no record")
            '''
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
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
            public_key = bytes_hexstr(public_key)
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
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
        if connection and connection.is_connected():
            connection.rollback()
        print(f"approve_medical_record_Error: {e}")
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
        if connection and connection.is_connected():
            connection.rollback()
        print(f"Error in get_patient_key: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return pt_key


# 分别插入患者分片和管理员分片
def insert_patient_share(mrid, pt_share):
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
        success = True
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        # 打印错误信息
        print(f"insert_patient_share_Error: {e}")
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
        return success


def insert_admin_share(mrid, ad_share):
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
        success = True
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
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
        if connection and connection.is_connected():
            connection.rollback()
        print(f"reject_medical_record_Error: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return success


# 编写函数创建通过的的审核记录
def create_review_record_pass(mr_id, ad_id):
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
        cursor.execute(
            "INSERT INTO review_records_archived (mr_id, result, review_by, review_date) VALUES (%s, %s, %s, %s)",
            (mr_id, True, ad_id, current_time))
        # 提交事务
        connection.commit()
        return True
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        # 打印错误信息
        print(f"create_review_record_pass_Error: {e}")
        return False
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


# 编写函数创建带有审核意见的审核记录
def create_review_record_not_pass(mr_id, ad_id, opi):
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
        cursor.execute(
            "INSERT INTO review_records_processing (mr_id, result, review_opinions, review_by, review_date) VALUES "
            "(%s, %s, %s, %s, %s)",
            (mr_id, False, opi, ad_id, current_time))
        # 提交事务
        connection.commit()
        return True
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        # 打印错误信息
        print(f"create_review_record_not_pass_Error: {e}")
        return False
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


def get_medical_records_by_patient(pt_id):
    connection = None
    cursor = None
    pt_records = []
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM archived_medical_records WHERE patient_id = %s ", (pt_id,))
        # 提交事务
        pt_records = cursor.fetchall()

    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        # 打印错误信息
        print(f"get_medical_records_by_patient_Error: {e}")
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return pt_records


# 管理员发起调取提议
def create_retrieve_proposal(ad_id, pt_id):
    connection = None
    cursor = None
    success = False
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        # 获取管理员数量，计算管理员的最低门槛
        cursor.execute("SELECT COUNT(*) AS admin_count FROM admins")
        result = cursor.fetchone()
        if result:
            admin_count = result['admin_count']
            print("现有管理员总数：", admin_count)
            # 计算管理员的最低门槛（奇数取 ceil(admin_count / 2)，偶数取 admin_count / 2 + 1）
            required_approvals = int((admin_count / 2) + 1)
            print("计算得门槛数：", required_approvals)
            cursor.execute("INSERT INTO retrieve_proposals ("
                           "propose_admin, patient_id, status, approving_admins, "
                           "approval_count, created_at, required_approvals) "
                           "VALUES (%s, %s, %s, %s, %s, NOW(), %s)"
                           , (ad_id, pt_id, 0, f"{ad_id}",
                              1, required_approvals))

        # 提交事务
        connection.commit()
        success = True
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        # 打印错误信息
        print(f"models_create_admin_login_Error: {e}")
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

    return success


# 获取某提议对应的提出管理员的公钥
def get_propose_admin_bkey(proposal_id):
    '''
    获取该提议号下的提议管理员的公钥
    :param proposal_id:管理员id，int型
    :return:sm2公钥
    '''
    connection = None
    cursor = None
    admin_bkey = None
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        # 获取管理员数量，计算管理员的最低门槛
        cursor.execute("SELECT propose_admin FROM retrieve_proposals where id = %s", (proposal_id,))
        result = cursor.fetchone()
        admin_id = result['propose_admin']
        cursor.execute("SELECT b_key FROM admins where id = %s", (admin_id,))
        admin_bkey = cursor.fetchone()['b_key']

    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        # 打印错误信息
        print(f"get_propose_admin_bkey_Error: {e}")
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

    return admin_bkey


def get_propose_patient(proposal_id):
    '''
    获取该提议号下的被调取患者的id
    :param proposal_id:提议id，int型
    :return:患者id，int型
    '''
    connection = None
    cursor = None
    pt_id = None
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        # 获取管理员数量，计算管理员的最低门槛
        cursor.execute("SELECT patient_id FROM retrieve_proposals where id = %s", (proposal_id,))
        result = cursor.fetchone()
        pt_id = result['patient_id']

    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        # 打印错误信息
        print(f"get_propose_admin_bkey_Error: {e}")
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

    return pt_id


# 获取提议列表
def get_proposals():
    connection = None
    cursor = None
    proposals = None
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        cursor.execute("SELECT * FROM retrieve_proposals ")
        proposals = cursor.fetchall()

    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        # 打印错误信息
        print(f"get_proposals_Error: {e}")
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

    return proposals


def get_own_proposals(ad_id):
    connection = None
    cursor = None
    proposals = []
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        cursor.execute("SELECT * FROM retrieve_proposals WHERE propose_admin = %s ", (ad_id,))
        proposals = cursor.fetchall()

    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        # 打印错误信息
        print(f"get_proposals_Error: {e}")
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

    return proposals


def get_other_proposals(ad_id):
    connection = None
    cursor = None
    proposals = []
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        cursor.execute("SELECT * FROM retrieve_proposals WHERE propose_admin != %s ", (ad_id,))
        proposals = cursor.fetchall()

    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        # 打印错误信息
        print(f"get_proposals_Error: {e}")
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

    return proposals


# 管理员同意调取提议
# 不设置拒绝选项，管理员不同意即视为拒绝，不做特殊处理
def pass_retrieve_proposal(proposal_id, ad_id, en_share):
    connection = None
    cursor = None
    success = False
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        # 获取提议的信息
        cursor.execute("SELECT * "
                       "FROM retrieve_proposals WHERE id = %s"
                       , (proposal_id,))
        result = cursor.fetchone()
        print("其他管理员查询到的提议记录，", result)
        if not result:
            print("Proposal ID does not exist")
            return False

        current_status, approving_admins, approval_count = \
            result['status'], result['approving_admins'], result['approval_count']

        # 如果提议不是待处理状态，则不进行更新
        if current_status != 0:
            print("Proposal is not in pending status")
            return False

        # 将同意管理员列表从字符串转换为列表
        admins_list = list(map(int, approving_admins.split(','))) if approving_admins else []

        # 检查管理员是否已经同意过
        if ad_id in admins_list:
            print("The administrator has already agreed to this proposal")
            return False

        # 添加新的同意管理员ID到列表
        admins_list.append(ad_id)

        # 更新同意数量
        # new_approval_count = len(admins_list)
        new_approval_count = approval_count + 1

        # 判断是否达到所需的最小同意数量
        # new_status = 1 if new_approval_count >= result['required_approvals'] else 0  # 1表示已通过，0表示正在进程中
        new_status = 0
        if new_approval_count >= result['required_approvals']:
            new_status = 1
        else:
            new_status = 0

        # 将同意管理员列表转换回字符串
        new_admins_str = ','.join(map(str, admins_list))

        # 更新数据库记录
        cursor.execute('''
                    UPDATE retrieve_proposals
                    SET status = %s, approving_admins = %s, approval_count = %s, created_at = NOW()
                    WHERE id = %s
                ''', (new_status, new_admins_str, new_approval_count, proposal_id))

        # 将自己的分片加入调取分片表
        # 分片是该函数参数，在传入该函数前应当已完成加密
        cursor.execute("INSERT INTO retrieve_shares (proposal_id,admin,share) VALUES (%s, %s,%s)",
                       (proposal_id, ad_id, en_share))

        # 提交事务
        connection.commit()
        success = True
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        # 打印错误信息
        print(f"models_pass_retrieve_proposal_Error: {e}")
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

    return success


def get_proposal_shares(proposal_id):
    connection = None
    cursor = None
    shares = []
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        cursor.execute("SELECT * FROM retrieve_shares WHERE proposal_id = %s ", (proposal_id,))
        shares = cursor.fetchall()

    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        # 打印错误信息
        print(f"get_proposal_shares_Error: {e}")
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

    return shares


def get_share_id(ad_id):
    connection = None
    cursor = None
    share_id = []
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        cursor.execute("SELECT sh_id FROM admins WHERE id = %s ", (ad_id,))
        share_id = cursor.fetchone()['sh_id']

    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        # 打印错误信息
        print(f"get_proposal_shares_Error: {e}")
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

    return share_id


def get_proposal_min(proposal_id):
    connection = None
    cursor = None
    min = []
    try:
        # 连接数据库
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        cursor.execute("SELECT required_approvals FROM retrieve_proposals WHERE id = %s ", (proposal_id,))
        min = cursor.fetchone()['required_approvals']

    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        # 打印错误信息
        print(f"get_proposal_min_Error: {e}")
    finally:
        # 关闭数据库连接
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

    return min


def get_ad_sh_by_medical_record(mr_id):
    connection = None
    cursor = None
    sh = []
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT sh FROM ad_sh WHERE mr_id = %s",
            (mr_id,)
        )
        sh = cursor.fetchone()  # 此处的分片还是由公钥加密的状态
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        print(f"Error in get_ad_sh_by_medical_record: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return sh


def get_doctor_key(doc_id):
    connection = None
    cursor = None
    dkey = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # 获取所有在线医生的ID
        cursor.execute("SELECT b_key FROM doctors WHERE id = %s", (doc_id,))
        dkey = cursor.fetchone()
    except Error as e:
        if connection and connection.is_connected():
            connection.rollback()
        print(f"Error in get_online_doctors: {e}")
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()
    return dkey


# 创建医生登录信息
def create_doctor_login(user_id, username, password_hash, salt, akey, bkey):
    connection = None;
    cursor = None
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


if __name__ == '__main__':
    r = get_admin_login("张四")
    if r is None:
        print("not exist")
    else:
        print(r)

    get_medical_records_waiting_review()
