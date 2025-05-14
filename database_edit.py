import os
import subprocess
import mysql.connector
from mysql.connector import Error

# 数据库配置
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '123456789',
    'database': 'ch_test_not_safe',
    'port': 3406
}

# 备份文件夹路径
# F:\2025-1spring\database_backup
backup_folder = "F:/2025-1spring/database_backup"


def get_database_connection():
    """获取数据库连接"""
    try:
        connection = mysql.connector.connect(**db_config)
        return connection
    except Error as e:
        print(f"数据库连接错误: {e}")
        return None


def show_tables_and_data():
    """返回指定数据库的所有表格以及表格的内容"""
    connection = get_database_connection()
    if not connection:
        return

    try:
        cursor = connection.cursor()
        # 获取所有表名
        cursor.execute("SHOW TABLES")
        tables = cursor.fetchall()

        if not tables:
            print("数据库中没有表。")
            return

        for table in tables:
            table_name = table[0]
            print(f"\n表: {table_name}")
            # 获取表结构
            cursor.execute(f"DESCRIBE {table_name}")
            columns = cursor.fetchall()
            print("表结构:")
            for column in columns:
                print(f"  {column[0]}: {column[1]}")

            # 获取表数据
            cursor.execute(f"SELECT * FROM {table_name}")
            rows = cursor.fetchall()
            print("表数据:")
            for row in rows:
                print(row)

    except Error as e:
        print(f"操作数据库时出错: {e}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()


def backup_database():
    """将指定数据库备份为文件"""
    try:
        # 定义备份文件路径和名称
        backup_file = os.path.join(backup_folder, f"{db_config['database']}_backup.sql")

        # 构造 mysqldump 命令
        command = [
            "mysqldump",
            f"--host={db_config['host']}",
            f"--user={db_config['user']}",
            f"--password={db_config['password']}",
            f"--port={db_config['port']}",
            db_config['database']
        ]

        # 执行命令并保存备份
        with open(backup_file, 'w') as f:
            result = subprocess.run(command, stdout=f, check=True)

        print(f"数据库备份成功，备份文件: {backup_file}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"备份数据库时出错: {e}")
        return False


def restore_database():
    """选取指定文件还原数据库"""
    # 列出备份文件夹下的所有备份文件
    backup_files = [f for f in os.listdir(backup_folder) if f.endswith('_backup.sql')]

    if not backup_files:
        print("没有找到备份文件。")
        return False

    # 显示备份文件列表供用户选择
    print("可用的备份文件:")
    for i, file in enumerate(backup_files):
        print(f"{i + 1}. {file}")

    try:
        choice = int(input("请输入要还原的备份文件编号: "))
        if 1 <= choice <= len(backup_files):
            selected_file = backup_files[choice - 1]
            backup_file = os.path.join(backup_folder, selected_file)

            # 构造 mysql 命令
            command = [
                "mysql",
                f"--host={db_config['host']}",
                f"--user={db_config['user']}",
                f"--password={db_config['password']}",
                f"--port={db_config['port']}",
                db_config['database']
            ]

            # 执行命令并恢复备份
            with open(backup_file, 'r') as f:
                result = subprocess.run(command, stdin=f, check=True)

            print(f"数据库恢复成功，使用备份文件: {backup_file}")
            return True
        else:
            print("无效的选择。")
            return False
    except ValueError:
        print("请输入有效的数字。")
        return False
    except subprocess.CalledProcessError as e:
        print(f"恢复数据库时出错: {e}")
        return False


def clear_database():
    """清空指定数据库"""
    connection = get_database_connection()
    if not connection:
        return

    try:
        cursor = connection.cursor()
        # 获取所有表名
        cursor.execute("SHOW TABLES")
        tables = cursor.fetchall()

        if not tables:
            print("数据库中没有表。")
            return
        cursor.execute("SET FOREIGN_KEY_CHECKS=0")
        # 遍历每个表并清空
        for table in tables:
            table_name = table[0]
            cursor.execute(f"DROP TABLE {table_name}")
            print(f"已删除表: {table_name}")

        connection.commit()
        print("所有表已删除。")

    except Error as e:
        print(f"操作数据库时出错: {e}")
        connection.rollback()
    finally:
        cursor.execute("SET FOREIGN_KEY_CHECKS=1")
        if connection.is_connected():
            cursor.close()
            connection.close()


def main_menu():
    """显示数字菜单，让用户选择功能"""
    while True:
        print("\n请选择功能:")
        print("1. 查看数据库表及内容")
        print("2. 备份数据库")
        print("3. 还原数据库")
        print("4. 清空数据库")
        print("5. 退出")

        choice = input("请输入功能编号: ")

        if choice == '1':
            show_tables_and_data()
        elif choice == '2':
            backup_database()
        elif choice == '3':
            restore_database()
        elif choice == '4':
            clear_database()
        elif choice == '5':
            print("退出程序。")
            break
        else:
            print("无效的选择，请重新输入。")


if __name__ == "__main__":
    main_menu()
