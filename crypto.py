from gmssl import sm2,sm3,sm4,func
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


def generate_sm2_key_pair(): # 生成密钥为str格式
    '''

    :return: private_key, public_key_str
    '''
    private_key = func.random_hex(64)  # 生成64位十六进制的私钥
    sm2_crypt = sm2.CryptSM2(public_key='', private_key=private_key)
    public_key = sm2_crypt._kg(int(private_key, 16), sm2.default_ecc_table['g'])
    public_key_str = "04" + public_key
    return private_key, public_key_str


def sm2_encrypt(data,public_key):#生成加密数据为bytes格式
    '''
    :param data:
    :param public_key:
    :return: 加密数据，bytes格式
    '''
    if isinstance(public_key, str):
        enc = sm2.CryptSM2(public_key=public_key, private_key="")
    else:
        enc = sm2.CryptSM2(public_key=bytes_hexstr(public_key), private_key="")
    if isinstance(data, str):
        encrypted_data = enc.encrypt(data.encode())
    else:
        encrypted_data = enc.encrypt(data)
    return encrypted_data


def sm2_decrypt(data,private_key):#生成解密数据为bytes格式
    if isinstance(private_key, str):
        dec = sm2.CryptSM2(public_key="", private_key=private_key)
    else:
        dec = sm2.CryptSM2(public_key="", private_key=bytes_hexstr(private_key))
    if isinstance(data, bytes):
        decrypted_data = dec.decrypt(data)
    else:
        decrypted_data = dec.decrypt(data.encode())
        #decrypted_data = dec.decrypt(bytes_hexstr(data))
    return decrypted_data


def sm2_sign(data, private_key):#生成签名格式为str格式
    # 被签名的data值统一转化为哈希值再签名
    random_hex_str = func.random_hex(32)
    if isinstance(private_key, str):
        sign = sm2.CryptSM2(public_key="", private_key=private_key)
    else:
        sign = sm2.CryptSM2(public_key="", private_key=bytes_hexstr(private_key))
    data_hash = generate_sm3_hash(data)
    #print("orhash:",data_hash)
    data_hash = hexstr_bytes(data_hash)
    print("用于本次签名生成的哈希值：",data_hash)
    #print("sm2signhash:",data_hash)
    signature = sign.sign(data_hash, random_hex_str)
    return signature


def sm2_verify(signature, message, public_key):#认证结果为布尔变量
    '''
    sm2签名校验
    :param signature:
    :param message: 原消息，大概率为字符串
    :param public_key: 公钥，大概率为字符串
    :return:
    '''
    # 用于认证的data一般为hash值
    veri = sm2.CryptSM2(public_key=public_key, private_key="")
    cal_hash = generate_sm3_hash(message)
    #print("sm2verihash:", cal_hash)
    cal_hash = hexstr_bytes(cal_hash)
    print("用于本次校验生成的哈希值：",cal_hash)
    verify_result = veri.verify(signature, cal_hash)

    return verify_result


# 生成128位随机密钥
def generate_sm4_key():#生成密钥为str格式
    key = func.random_hex(32)  # 生成32个字符的十六进制字符串，即128位
    return key


# 加密函数
def sm4_encrypt(plaintext, key):#生成加密数据为bytes格式
    '''
    sm4对称加密，若明文为字符串会将明文编码后用于运算
    :param plaintext: 可为bytes或字符串
    :param key: 可为bytes十六进制字符串
    :return:sm4加密数据，格式为bytes
    '''
    crypt_sm4 = sm4.CryptSM4()
    if isinstance(key, bytes):
        crypt_sm4.set_key(key, sm4.SM4_ENCRYPT)  # 设置密钥和加密模式
    else:
        crypt_sm4.set_key(key.encode(), sm4.SM4_ENCRYPT)  # 设置密钥和加密模式
    if isinstance(plaintext, str):
        ciphertext = crypt_sm4.crypt_cbc(b'\x00' * 16, plaintext.encode())  # 使用CBC模式加密
    else:
        ciphertext = crypt_sm4.crypt_cbc(b'\x00' * 16, plaintext)
    # return ciphertext.hex()  # 返回密文
    return ciphertext

# 解密函数
def sm4_decrypt(ciphertext, key):#解密数据为bytes格式
    '''
    sm4对称解密，密文可为十六进制字符串或bytes
    :param ciphertext:明文，可为十六进制字符串或bytes
    :param key: 对称密钥，可为十六进制字符串或bytes
    :return: sm4解密数据，bytes明文
    '''
    crypt_sm4 = sm4.CryptSM4()
    if isinstance(key, bytes):
        crypt_sm4.set_key(key, sm4.SM4_DECRYPT)  # 设置密钥和加密模式
    else:
        crypt_sm4.set_key(key.encode(), sm4.SM4_DECRYPT)
    if isinstance(ciphertext,str):
        plaintext = crypt_sm4.crypt_cbc(b'\x00' * 16, bytes.fromhex(ciphertext))  # 使用CBC模式解密
    else:
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
    cal_hash=generate_sm3_hash(data)
    return hmac.compare_digest(cal_hash,get_hash)

def pack(receive_pubkey, data, send_prikey):
    sm4_key = generate_sm4_key() # hex_str
    #env = sm2_encrypt(sm4_key.encode(), receive_pubkey)
    env = sm2_encrypt(sm4_key, receive_pubkey) #bytes
    cip = sm4_encrypt(data, sm4_key)#hex_str
    sm3_hash = generate_sm3_hash(data)

    sign = sm2_sign(data,send_prikey)
    sign = sign.encode()
    #print("戳：", env)
    #print("原明文：",data)
    #print("加密明文：", cip)
    #print("签名：", sign)
    #print("hash:",sm3_hash)
    #print("sm4key:",sm4_key)
    return env+b"-*-"+hexstr_bytes(cip)+b"-*-"+sign


def unpack(send_pubkey, data ,receive_prikey):
    env = data.split(b"-*-")[0]
    cip = data.split(b"-*-")[1]
    sign = data.split(b"-*-")[2]

    cip = bytes_hexstr(cip)
    sign = sign.decode()

    sm4_key = sm2_decrypt(env, receive_prikey)
    sm4_key = sm4_key.decode()
    #print("getkey:",sm4_key)

    message = sm4_decrypt(cip, sm4_key)
    #print("message:",message)
    print("unpacksign:",sign)
    cal_hash = generate_sm3_hash(message)
    print("unpackhash:",cal_hash)

    veri_result=sm2_verify(sign,message,send_pubkey)
    print(veri_result)
    if veri_result:
        print("签名为真")
        return message.decode()
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

    return shares_per_block


def combine_secret(shares_per_block, min_shares):
    """
    从分片中恢复长秘密。
    :param shares_per_block: 每个块的分片列表
    :param min_shares: 恢复秘密所需的最小分片数量
    :return: 恢复的秘密字节串
    """
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

def generate_salt():
    return os.urandom(16)

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


if __name__ == "__main__":

# 示例用法

    #salt = b"5209f6f54f0a74a45090e9e306c5d78e"
    data = "Hello,here is 120.你好这里是120"
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

    pt_en = sm2_encrypt(str(pt), bkey)
    print(pt_en)

    en_akey = sm4_encrypt(akey, tkey)
    print("en_akey:",type(en_akey),en_akey)

    de_akey = sm4_decrypt(en_akey, tkey)
    print("de_akey:",type(de_akey),de_akey)

    de_akey=de_akey.decode()

    re_pt=sm2_decrypt(pt_en, de_akey)
    print(re_pt)



