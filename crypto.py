from gmssl import sm2, sm3, sm4, func
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Protocol.KDF import PBKDF2
#from Crypto.Hash import SHA256
import os

'''
格式规范：
传输时的密文以bytes格式传输
1.将格式进行统一规范
2.对对应接口上的格式进行对齐

bytes->hex_str
data=b'\x01\x02\xff'
msg = data.hex()  # 消息转化为16进制字符串
print(msg)

hex_str->bytes
hex_str = '0102ff'
byte_data = bytes.fromhex(hex_str)
print(byte_data)  # 输出: b'\x01\x02\xff'
'''



from datetime import datetime
def datetime_to_str(dt: datetime) -> str:
    """
    将 datetime 对象转换为字符串
    参数:dt: datetime 对象
    返回:格式化后的字符串 (格式: YYYY-MM-DD HH:MM:SS)
    """
    return dt.strftime('%Y-%m-%d %H:%M:%S')


def str_to_datetime(date_str: str) -> datetime:
    """
    将字符串转换为 datetime 对象
    参数:date_str: 表示日期和时间的字符串 (格式: YYYY-MM-DD HH:MM:SS)
    返回:转换后的 datetime 对象
    """
    return datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')


def hexstr_bytes(data):
    """
    :param data:hexstr
    :return:bytes
    """
    return bytes.fromhex(data)


def bytes_hexstr(data):
    """
    :param data:bytes
    :return: hexstr
    """
    return data.hex()


def generate_sm2_key_pair():  # 生成密钥为str格式
    '''

    :return: private_key, public_key_str
    '''
    private_key = func.random_hex(64)  # 生成64位十六进制的私钥
    sm2_crypt = sm2.CryptSM2(public_key='', private_key=private_key)
    public_key = sm2_crypt._kg(int(private_key, 16), sm2.default_ecc_table['g'])
    public_key_str = "04" + public_key
    return private_key, public_key_str


def generate_valid_sm2_key_pair():
    """
    生成并验证 SM2 密钥对是否匹配，直到找到匹配的密钥对。
    :return: private_key, public_key_str
    """
    while True:
        # 生成密钥对
        private_key, public_key_str = generate_sm2_key_pair()

        # 创建 SM2 加密对象
        sm2_crypt = sm2.CryptSM2(public_key=public_key_str, private_key=private_key)
        # 随机生成测试明文
        plaintext = func.random_hex(64)  # 生成随机明文
        plaintext = plaintext.encode('utf-8')
        try:
            # 加密
            ciphertext = sm2_crypt.encrypt(plaintext)
            # 解密
            decrypted_text = sm2_crypt.decrypt(ciphertext)
            # 验证解密后的明文是否与原始明文一致
            if decrypted_text == plaintext:
                print("找到匹配的密钥对！")
                return private_key, public_key_str
            else:
                print("密钥对不匹配，重新生成...")
        except Exception as e:
            print(f"验证失败，错误信息：{e}，重新生成...")
            continue


def sm2_encrypt(data, public_key):  # 生成加密数据为bytes格式
    '''
    :param data:str或者utf-8格式的bytes
    :param public_key:hexstr/bytes（以hexstr的格式参与运算）
    :return: 加密数据，bytes格式
    '''
    if isinstance(public_key, str):
        enc = sm2.CryptSM2(public_key=public_key, private_key="")
    else:
        enc = sm2.CryptSM2(public_key=bytes_hexstr(public_key), private_key="")
    if isinstance(data, str):
        encrypted_data = enc.encrypt(data.encode('utf-8'))
    else:
        encrypted_data = enc.encrypt(data)
    return encrypted_data


def sm2_decrypt(data, private_key):  # 生成解密数据为bytes格式
    '''
    sm2解密，需要使用私钥
    :param data: :str或者utf-8格式的bytes
    :param private_key: hexstr/bytes（以hexstr的格式参与运算）
    :return: 解密数据，bytes，解密正确的话应为utf-8解码
    '''
    if isinstance(private_key, str):
        dec = sm2.CryptSM2(public_key="", private_key=private_key)
    else:
        dec = sm2.CryptSM2(public_key="", private_key=bytes_hexstr(private_key))
    if isinstance(data, bytes):
        decrypted_data = dec.decrypt(data)
    else:
        decrypted_data = dec.decrypt(data.encode('utf-8'))
        #decrypted_data = dec.decrypt(bytes_hexstr(data))
    return decrypted_data


def sm2_sign(data, private_key):  # 生成签名格式为str格式
    # 被签名的data值统一转化为哈希值再签名
    random_hex_str = func.random_hex(32)
    if isinstance(private_key, str):
        sign = sm2.CryptSM2(public_key="", private_key=private_key)
    else:
        sign = sm2.CryptSM2(public_key="", private_key=bytes_hexstr(private_key))
    data_hash = generate_sm3_hash(data)
    #print("orhash:",data_hash)
    data_hash = hexstr_bytes(data_hash)
    print("用于本次签名生成的哈希值：", data_hash)
    # print("sm2signhash:",data_hash)
    signature = sign.sign(data_hash, random_hex_str)
    return signature


def sm2_verify(signature, message, public_key):  # 认证结果为布尔变量
    '''
    sm2签名校验
    :param signature:
    :param message: 原消息，为字符串
    :param public_key: 公钥，为十六进制字符串
    :return:
    '''
    verify_result = None
    try:
        # 用于认证的data一般为hash值
        veri = sm2.CryptSM2(public_key=public_key, private_key="")
        cal_hash = generate_sm3_hash(message)
        #print("sm2verihash:", cal_hash)
        cal_hash = hexstr_bytes(cal_hash)
        print("用于本次校验生成的哈希值：", cal_hash)
        # print("将要验证的签名：", signature)
        verify_result = veri.verify(signature, cal_hash)
    except Exception as e:
        print(f"crypto_sm2_verify_error: {e}")
    return verify_result


# 生成128位随机密钥
def generate_sm4_key():  # 生成密钥为str格式
    '''
    生成sm4算法所需的密钥
    :return: 32个字符长度的hexstr，对应128bit-16bytes
    '''
    key = func.random_hex(32)  # 生成32个字符的十六进制字符串，即128位
    return key


# 加密函数
def sm4_encrypt(plaintext, key):  # 生成加密数据为bytes格式
    '''
    sm4对称加密，若明文为字符串会将明文编码后用于运算
    :param plaintext: 可为bytes或字符串
    :param key: 可为bytes十六进制字符串
    :return:sm4加密数据，格式为bytes
    '''
    crypt_sm4 = sm4.CryptSM4(padding_mode=3)
    if isinstance(key, bytes):
        crypt_sm4.set_key(key, sm4.SM4_ENCRYPT)  # 设置密钥和加密模式
    else:
        crypt_sm4.set_key(hexstr_bytes(key), sm4.SM4_ENCRYPT)  # 设置密钥和加密模式
    if isinstance(plaintext, str):
        ciphertext = crypt_sm4.crypt_cbc(b'\x00' * 16, plaintext.encode('utf-8'))  # 使用CBC模式加密
    else:
        ciphertext = crypt_sm4.crypt_cbc(b'\x00' * 16, plaintext)
    # return ciphertext.hex()  # 返回密文
    return ciphertext


# 解密函数
def sm4_decrypt(ciphertext, key):#解密数据为bytes格式
    '''
    sm4对称解密，密文可为十六进制字符串或bytes
    :param ciphertext:密文，可为十六进制字符串或bytes
    :param key: 对称密钥，可为十六进制字符串或bytes
    :return: sm4解密数据，bytes明文
    '''
    crypt_sm4 = sm4.CryptSM4(padding_mode=3)
    '''
    if isinstance(key, bytes):
        crypt_sm4.set_key(key, sm4.SM4_DECRYPT)  # 设置密钥和加密模式
    else:
        crypt_sm4.set_key(hexstr_bytes(key), sm4.SM4_DECRYPT)
        '''
    if isinstance(key, bytes):
        pass
    else:
        key = hexstr_bytes(key)
    # print("sm4解密时的密钥", key)
    crypt_sm4.set_key(key, sm4.SM4_DECRYPT)  # 设置密钥和加密模式
    '''
    if isinstance(ciphertext, str):
        plaintext = crypt_sm4.crypt_cbc(b'\x00' * 16, bytes.fromhex(ciphertext))  # 使用CBC模式解密
    else:
        plaintext = crypt_sm4.crypt_cbc(b'\x00' * 16, ciphertext)
        '''
    if isinstance(ciphertext, str):
        ciphertext = bytes.fromhex(ciphertext)
    else:
        pass
    # print("sm4解密时的密文", ciphertext)
    plaintext = crypt_sm4.crypt_cbc(b'\x00' * 16, ciphertext)
    return plaintext  # 返回明文


def generate_sm3_hash(data):#哈希值数据为str格式
    """
    生成SM3摘要
    :param data: 要生成摘要的数据，可以是字符串或字节
    :return: SM3摘要的十六进制字符串
    """
    # 如果输入数据是字符串，则先将其转换为字节
    if isinstance(data, str):
        data = data.encode('utf-8')
    # 计算SM3摘要
    sm3_hash = sm3.sm3_hash(func.bytes_to_list(data))
    return sm3_hash

import hmac
def check_sm3_hash(data,get_hash):
    cal_hash = generate_sm3_hash(data)
    return hmac.compare_digest(cal_hash, get_hash)

def pack(receive_pubkey, data, send_prikey):
    '''
    数字信封打包
    :param receive_pubkey:
    :param data:只能传入utf-8格式的bytes
    :param send_prikey:
    :return:
    '''
    sm4_key = generate_sm4_key()  # hex_str
    # env = sm2_encrypt(sm4_key.encode(), receive_pubkey)
    env = sm2_encrypt(hexstr_bytes(sm4_key), receive_pubkey)  # bytes
    cip = sm4_encrypt(data, hexstr_bytes(sm4_key))  # bytes
    # sm3_hash = generate_sm3_hash(data)

    print("data:", data)
    sign = sm2_sign(data, send_prikey)
    sign = sign.encode('utf-8')
    print("戳：", env)
    #print("原明文：",data)
    print("加密明文：", cip)
    print("签名：", sign)
    #print("hash:",sm3_hash)
    #print("sm4key:",sm4_key)
    # return env+b"-*-"+hexstr_bytes(cip)+b"-*-"+sign
    print("解密前cip:", cip)
    return env + b"-*-" + cip + b"-*-" + sign


def unpack(send_pubkey, data, receive_prikey):
    env = data.split(b"-*-")[0]
    cip = data.split(b"-*-")[1]
    sign = data.split(b"-*-")[2]

    # cip = bytes_hexstr(cip)
    # sign = sign.decode()

    print("env:", env)
    sm4_key = sm2_decrypt(env, receive_prikey)
    print("decrypted_sm4_key:", sm4_key)
    # sm4_key = bytes_hexstr(sm4_key)
    # print("getkey:",sm4_key)

    print("解密端cip:", cip)
    message = sm4_decrypt(cip, sm4_key)
    print("message:", message)
    print("unpacksign:", sign)
    # sign = sign.encode('utf-8')


    veri_result=sm2_verify(sign, message, send_pubkey)
    print(veri_result)
    if veri_result:
        print("签名为真")
        return message.decode('utf-8')
    else:
        print("签名不符")
        return 0

#def pack_without_sign(receive_pubkey,data):

def split_secret(secret_bytes, min_shares, total_shares):
    """
    将长秘密分割成分片。
    :param secret_bytes: 待分割的秘密（字节串，长度 <= 128 字节）
    :param min_shares: 恢复秘密所需的最小分片数量
    :param total_shares: 总共生成的分片数量
    :return: 分片列表，每个分片是一个元组 (index, share)
    """
    if len(secret_bytes) > 128:
        raise ValueError("秘密长度超过 128 字节")

    # 将秘密分割成 16 字节的块
    blocks = [secret_bytes[i:i+16] for i in range(0, len(secret_bytes), 16)]

    # 为每个块生成分片
    shares_per_block = []
    for block in blocks:
        shares = Shamir.split(min_shares, total_shares, block)
        shares_per_block.append(shares)

    share_list = [b''] * total_shares
    for share_block in shares_per_block:
        print(share_block)
        for i in range(total_shares):
            share_list[i] = share_list[i] + share_block[i][1]
    for i in range(total_shares):
        share_list[i] = (i + 1, share_list[i])

    return share_list

def convert_share_list_to_shares_per_block(share_list):
    """
    将 share_list 格式转换回 shares_per_block 格式。
    :param share_list: 分片列表，每个分片是一个元组 (index, concatenated_share_data)
    :return: shares_per_block 列表，每个元素是一个块的分片列表 [(index, share_data), ...]
    """
    if not share_list:
        raise ValueError("share_list 为空")

    # 获取第一个分片的 concatenated_share_data 长度
    first_share = share_list[0]
    L = len(first_share[1])

    # 检查所有分片的 concatenated_share_data 长度是否一致
    for share in share_list:
        if len(share[1]) != L:
            raise ValueError("分片的连接数据长度不一致")

    # 计算块的数量
    num_blocks = (L + 15) // 16  # 向上取整

    # 初始化 shares_per_block
    shares_per_block = [[] for _ in range(num_blocks)]

    # 提取每个块的分片数据
    for index, concatenated_share_data in share_list:
        for b in range(num_blocks):
            start = b * 16
            end = min(start + 16, L)
            share_data_b = concatenated_share_data[start:end]
            shares_per_block[b].append((index, share_data_b))

    return shares_per_block


def combine_secret(shares_list, min_shares):
    """
    从分片中恢复长秘密。
    :param shares_per_block: 每个块的分片列表
    :param min_shares: 恢复秘密所需的最小分片数量
    :return: 恢复的秘密字节串
    """
    # print("原始分片列表：",shares_list)
    shares_per_block = convert_share_list_to_shares_per_block(shares_list)
    # print("复原的分块分片：", shares_per_block)
    recovered_blocks = []
    for block_shares in shares_per_block:
        if len(block_shares) < min_shares:
            #raise ValueError("提供的分片数量不足，至少需要 {}".format(min_shares))
            raise ValueError("提供的分片数量不足")
        # 恢复每个块
        recovered_block = Shamir.combine(block_shares[:min_shares])
        recovered_blocks.append(recovered_block)

    # 拼合所有块
    recovered_secret = b''.join(recovered_blocks)
    return recovered_secret

def generate_salt(salt_length=16):
    return os.urandom(salt_length)

def generate_salt_sm3(data,salt):
    """

    :param data:一般为口令字符串
    :param salt: 随机盐值，初始形式为字节
    :return: 加盐后哈希值，为十六进制字符串
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    if isinstance(salt,str):
        salt = hexstr_bytes(salt)
    cal = data+salt
    #print("salt:",salt.hex())
    sm3_hash = sm3.sm3_hash(func.bytes_to_list(cal))
    return sm3_hash


def check_salt_sm3(data, salt, get_hash):
    cal_hash = generate_salt_sm3(data, salt)
    return hmac.compare_digest(cal_hash, get_hash)


def generate_pbkdf2_key(password, salt, iterations=10000, key_length=16):
    """
    使用 PBKDF2 和 sm3 生成密钥
    :param password: 密码（字符串）
    :param salt: 盐值（字节串）
    :param iterations: 迭代次数
    :param key_length: 生成的密钥长度（字节）
    :return: 生成的密钥（字节串）
    """
    # 使用 PBKDF2 生成密钥
    #key = PBKDF2(password.encode('utf-8'), salt, dkLen=key_length, count=iterations,prf=lambda password, salt: SHA256.new(password + salt).digest())
    key = PBKDF2(password.encode('utf-8'), salt, dkLen=key_length, count=iterations,
                 prf=lambda password, salt: hexstr_bytes(generate_salt_sm3(password, salt)))

    return key


def pack_with_salt(receive_pubkey, data, send_prikey):
    # 生成随机盐值
    salt = generate_salt(64)
    if isinstance(data, str):
        data = data.encode('utf-8')
    else:
        pass
    print("data:", data)
    # 将盐值附加到明文前面
    data_with_salt = salt + data
    print("data_with_salt:", data_with_salt)
    # 使用SM4加密数据
    sm4_key = generate_sm4_key()  # hex_str
    cip = sm4_encrypt(data_with_salt, sm4_key)
    cip_hex = bytes_hexstr(cip)
    sm4_key = hexstr_bytes(sm4_key)
    print("sm4_key-bytes:", sm4_key)
    # 使用SM2加密SM4密钥
    env = sm2_encrypt(sm4_key, receive_pubkey)

    # 使用SM2对原始明文进行签名

    print("data:", data)
    sign = sm2_sign(data, send_prikey)

    # 返回加密后的密文、加密后的SM4密钥和签名
    return env + b"-*-" + hexstr_bytes(cip_hex) + b"-*-" + sign.encode('utf-8')


def unpack_with_salt(send_pubkey, data, receive_prikey, salt_length=64):
    # 分割数据
    parts = data.split(b"-*-")
    if len(parts) != 3:
        print("数据格式错误")
        return None

    env = parts[0]
    cip_hex = parts[1]
    sign = parts[2].decode('utf-8')

    # 解密SM4密钥
    sm4_key = sm2_decrypt(env, receive_prikey)
    if not sm4_key:
        print("SM2解密失败")
        return None
    print("sm4key:", sm4_key)
    sm4_key = bytes_hexstr(sm4_key)
    # 解密数据
    cip = bytes_hexstr(cip_hex)
    print("cip:", cip)
    decrypted_data = sm4_decrypt(cip, sm4_key)
    print("decrypted_data:", decrypted_data)

    # 分离盐值和明文
    salt = decrypted_data[:salt_length]
    plaintext = decrypted_data[salt_length:]
    print("plaintext:", plaintext)
    # 验证签名
    # plaintext_str = plaintext.decode('utf-8')
    # print("plaintext_str:", plaintext_str)
    veri_result = sm2_verify(sign, plaintext, send_pubkey)

    if veri_result:
        print("签名为真")
        return plaintext.decode('utf-8')
    else:
        print("签名不符")
        return None


def check_sm2_key_pair(akey,bkey):
    data = "asdfghjkl"
    en_data = sm2_encrypt(data, bkey)
    print("en_data:", en_data)
    de_data = sm2_decrypt(en_data, akey)
    print("de_data:", de_data)


if __name__ == "__main__":

    bkey = "048b674f701c1fd63e3aa0405df528c15b68697b0bbe52351eb2f3f0478f47f4424e746c3730dd252c053b0f3d8a023cd953d6d2017a98764dca8209f6ed1a985c"
    sign = "9a270edb05a6d1d4f4ddeb1c464487fcfb9cd58756350924696943df162f6306"
    message = "1-qqqq-aaaa-zzzz-wwww-ssss-xxxx"
    message = generate_sm3_hash(message)

    re = sm2_verify(sign, message, bkey)
    print(re)
    # 示例用法

    #salt = b"5209f6f54f0a74a45090e9e306c5d78e"
    data = "Hello,here is 120.你好这里是120"
    # akey = b'D\xfbT\xd1<\x1e\xc0\x13X\x94\xe2\xf9)\xa09j\x03D\xf8\xa1\x9b\x9b\xa32\x15%e\xac\xf0\xf9\xe8\x93'
    # bkey = b'0408dbc9b393f2a180eba26947df904ab56ddc6a3be02c3252cc66a3b3d67c9d9d4edf8d2b2b819399f6b2851b0e50cd54319fc715a9a3a8fedd821f52353ad3fb'
    # akey = "44fb54d13c1ec0135894e2f929a0396a0344f8a19b9ba332152565acf0f9e893"
    # bkey = "0408dbc9b393f2a180eba26947df904ab56ddc6a3be02c3252cc66a3b3d67c9d9d4edf8d2b2b819399f6b2851b0e50cd54319fc715a9a3a8fedd821f52353ad3fb"
    #akey, bkey = generate_sm2_key_pair()
    # akey = "22280514b66c04651b78ed120aef3560512fcdcde284a0eb695adda86fa77705"
    # bkey = "04067b06cb2a00a81c8cded509ddc1b9a2c7df073c3fd0ca0e3aad5dcccadb24cf1d887131df60900bec79468d6861816bc8869cc488e9a268d40e783994ed19f6"
    # akey = "b77aa521fcc00d90db6c5479a95b15b88f2d6a15ad1f799a23a12673475c40a8"
    # bkey = "04820136991596584c72fafbdcad5a6573943e556408920a1f2900b94d2901b9ad1bc22ff4132fcd754af09b5c0f324df3e9f9cbd6fa4b2ad1a20a979e4c64243d"
    # akey = "4874811c2035af5678d7713c92acf52e5746f9862cba5473e5a3a9ba7756bec1"
    # bkey = "041dca08e77232c6b42b88669aa692f51ae3aef1435df415bf9754d9ea469060260a10739cee4387f423c4d7582a8e9abb845fd6aef1511839e882b04c11a2a08d"
    '''
    管理员共同私钥： <class 'str'> 9949f08843fef734f721d873406bcf23432fc796928b833c6e4d4cd10a727888
    管理员共同公钥： <class 'str'> 0437e566c0e007f84775e84d5935f70ade0d6aac32acb658d10c634f289d778ef8bdd5742c9a095ad0df371ba00bbc32db93ea8263586d388839026a05e3d35bff
    '''
    # akey = '9949f08843fef734f721d873406bcf23432fc796928b833c6e4d4cd10a727888'
    # bkey = '0437e566c0e007f84775e84d5935f70ade0d6aac32acb658d10c634f289d778ef8bdd5742c9a095ad0df371ba00bbc32db93ea8263586d388839026a05e3d35bff'
    akey, bkey = generate_valid_sm2_key_pair()
    print("私钥：", type(akey), akey)
    print("公钥：", type(bkey), bkey)
    en_data = sm2_encrypt(data, bkey)
    print(en_data)
    de_data = sm2_decrypt(en_data, akey)
    print(de_data)

    sign = sm2_sign(data, akey)
    print(sign)
    print(len(sign))
    re = sm2_verify(sign, data, bkey)
    print(re)

    sign = "f891ec71c8428aca6668559f9d925363f67ea3487ae7dcaec484d76d9dc6164b56ba0401e2bea902483ce9963a8c6a0e15197874cdeba30e71935cc9fa2fd7fd"
    bkey = "04cc2cebd9fdd6ff8c182eca294b6d32663dd2693fbda6adcfe81df554e9788b6ffc346d02f8211229d85eeab5095b89a5e139c19be173894ecc28a4b12d9a4909"
    to_cal = "1-zzz-xxx-ccc-vvv-bbb-nnn"
    to_verify = generate_sm3_hash(to_cal)
    re = sm2_verify(sign, to_verify, bkey)
    print("正式验签结果：", re)

    print(data.encode() == de_data)
'''
    test = b'\xd6V\xf6\xff\xdd\x08\x7f{)xR\xbe\xbe,x\xf7(\x02V8\x06\xd4\xddR\x0eR?\x98\xcf`\xca<\xa7\x87\x02\x11\x04\x9aB\x18,\xee\xe3\xb1W7\xfb\x1a\xc8Yl\xd5\xe6<\xf3P\xf14\xf5M\xfd,\xf5"S\xd9\xa1\x97\x8e\xa7\xb3\xe67Y\x87;.-I\xae4\x01\r\x9a\x1a\x8c\xcf\xe4\x87\xb0Y\xf2\x1e\x10q\x8af\xa0\x05\xca\x85D\x05<'
    bkey = "0443537ec05ba2044d5e395e5cd14b5ff38e8dad6fb0eb047cc9eeb435486509c416a809346339a23eb836ea33e2cb98bb5d987fc1329024e07496314b686fb1a3"
    akey = "7310e3e744f518368aa4eb2a37393de9609c0bb7988796889805db475a3a22f9"
    result = sm2_decrypt(test, akey)
    print(result)
    # 钥匙有误

    en_data = sm2_encrypt(data, bkey)
    de_data = sm2_encrypt(en_data, akey)
    print(de_data)
'''

'''
    key = generate_sm4_key()
    print(key)
    key = hexstr_bytes(key)
    print(key)
    shares = split_secret(key, 2, 3)
    print(shares)
    print(shares[0][0])
    print(shares[0][1])
    print(shares[0][2])
    _, one_share = shares[0][0]
    _, two_share = shares[0][1]
    print(one_share)
    to_combine=[(1,one_share),(2,two_share)]
    # to_combine=[(2,one_share),(3,two_share)]  #分片序号也是重要因素，写错序号会导致恢复结果错误
    print(to_combine)
    re = combine_secret([to_combine], 2)
    print("re", re)
    print(bytes_hexstr(re))
'''
'''
    password = "qq123456"
    sa = generate_salt()

    # print("salt:",sa)
    # hashed_password = generate_salt_sm3(password, sa)
    # print(hashed_password)
    pswd = "123456"
    tkey = generate_pbkdf2_key(pswd,sa)
    pt = 30000001
    dc = 20000001
    to_sign = pt+dc
    to_sign = str(to_sign)

    ak = '976124366e8fe79461988e15c779adba55bd32bdf0f5f93364385abb7e764f74'
    bk = '0437d10fe076d915b7d14a1ee1f13f1c57b9f89a4122f8aed3f791dc52dd781dd81266e36439ece593e90470e945eec63ab30d1f6bcf4f50ca4b92a8c5c889044a'
    sign=sm2_sign(to_sign,ak)
    sign_result=sm2_verify(sign,to_sign,bk)
    print("ak-sign:",sign)
    print("bk-result:",sign_result)


    akey, bkey = generate_sm2_key_pair()
    print("akey:",akey)
    print("bkey:",bkey)

    print("hexstr_bytes(akey):",hexstr_bytes(akey))
    print("akey.encode():",akey.encode())
    hb_akey=hexstr_bytes(akey)
    enc_akey=akey.encode()
    hb_bkey =hexstr_bytes(bkey)
    enc_bkey=bkey.encode()

    stren_data=sm2_encrypt(data,bkey)
    strde_data=sm2_decrypt(stren_data,akey)
    print("strendata:",stren_data)
    print("strdedata:",strde_data)

    hben_data=sm2_encrypt(data,hb_bkey)
    hbde_data=sm2_decrypt(hben_data,hb_akey)
    print("hbendata:",hben_data)
    print("hbdedata:",hbde_data)
    encde_hben_data=sm2_decrypt(hben_data,enc_akey)
    print("encde_hben_data:",encde_hben_data)

    encen_data=sm2_encrypt(data,enc_bkey)
    encde_data=sm2_decrypt(encen_data,enc_akey)
    print("encen_data:", encen_data)
    print("encde_data:", encde_data)


    sign = sm2_sign(to_sign,akey)
    # 验签公钥不可为bytes格式
'''

'''
    print(sign)
    print(sm2_verify(sign,to_sign,bkey))
    sign = sm2_sign(to_sign,hb_akey)
    print(sign)
    print(sm2_verify(sign,to_sign,bkey))

    sign=sign.encode()
    print(sm2_verify(sign,to_sign,bkey))

    sign=bytes_hexstr(sign)
    print(sm2_verify(sign,to_sign,bkey))


    sign = sm2_sign(to_sign,akey)
    print(sign)
    sign = sm2_encrypt(sign,bkey)
    print(len(sign), sign)
    de_sign = sm2_decrypt(sign, akey)
    print(de_sign)
    sign_result = sm2_verify(de_sign, to_sign, bkey)

    print(sign_result)
    '''
'''
    pt_en = sm2_encrypt(str(pt), bkey)
    print(pt_en)

    en_akey = sm4_encrypt(akey, tkey)
    print("en_akey:",type(en_akey),en_akey)

    de_akey = sm4_decrypt(en_akey, tkey)
    print("de_akey:",type(de_akey),de_akey)

    de_akey=de_akey.decode()

    re_pt=sm2_decrypt(pt_en, de_akey)
    print(re_pt)
'''


