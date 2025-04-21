import re
import hmac
import hashlib
import math
import subprocess
import time
import sys
from bs4 import BeautifulSoup
import requests
import json
import os
from tqdm import tqdm
#由Tim-Conner制作
#time：2025/3/3 23：10
# 改进：改进密码位数为6时的溢出
#思路来自：huxiaofan1223
#思路文章地址：https://blog.csdn.net/qq_41797946/article/details/89417722
# 目标网址
username=""
password=""
init_url = ""
url = ""#登录网站网址
get_challenge_api = ""#
srun_portal_api = ""#
#其他配置
_PADCHAR = "="
_ALPHA = ""
n = '200'
type = '1'
ac_id = '1'
enc = "srun_bx1"


def read_config():
    config_path = "config.json"
    # 检查文件是否存在
    if not os.path.exists(config_path):
        # 如果文件不存在，创建文件
        create_config(config_path)
        return read_config()
    # 读取文件
    with open(config_path, "r", encoding="utf-8") as file:
        config = json.load(file)
    return config

def create_config(config_path):
    print("config.json 文件不存在，正在创建...")
    # 获取用户输入
    username = input("请输入用户名: ")
    password = input("请输入密码: ")

    # 获取IP地址
    ip_address = input("请输入IP地址（例如192.168.254.20）: ")
    if not ip_address:
        ip_address = "192.168.254.20"
    # 构造其他参数
    init_url = f"http://{ip_address}"
    url = f"http://{ip_address}/srun_portal_pc?ac_id=1&theme=basic3"
    get_challenge_api = f"http://{ip_address}/cgi-bin/get_challenge"
    srun_portal_api = f"http://{ip_address}/cgi-bin/srun_portal"
    _PADCHAR = "="
    _ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
    n = '200'
    type_ = '1'
    ac_id = '1'
    enc = "srun_bx1"
    role = chooseRole(url)
    # 将数据保存到文件中
    config = {
        "username": username,
        "password": password,
        "Role": role,
        "init_url": init_url,
        "url": url,
        "get_challenge_api": get_challenge_api,
        "srun_portal_api": srun_portal_api,
        "_PADCHAR": _PADCHAR,
        "_ALPHA": _ALPHA,
        "n": n,
        "type": type_,
        "ac_id": ac_id,
        "enc": enc
    }
    with open(config_path, "w", encoding="utf-8") as file:
        json.dump(config, file, ensure_ascii=False, indent=4)
    print("config.json 文件创建成功")


def parse_config(config):
    global username, password, init_url, url, get_challenge_api, srun_portal_api, _PADCHAR, _ALPHA, n, type, ac_id, enc
    # 解析 config.json 中的配置参数
    username = f"{config["username"]}@{config["Role"]}"
    password = config["password"]
    init_url = config["init_url"]
    url = config["url"]
    get_challenge_api = config["get_challenge_api"]
    srun_portal_api = config["srun_portal_api"]
    _PADCHAR = config["_PADCHAR"]
    _ALPHA = config["_ALPHA"]
    n = config["n"]
    type_ = config["type"]
    ac_id = config["ac_id"]
    enc = config["enc"]

    print("读取的配置文件内容：")
    print(f"username: {username}")
    print(f"password: {password}")
    print(f"init_url: {init_url}")
    print(f"url: {url}")
    print(f"get_challenge_api: {get_challenge_api}")
    print(f"srun_portal_api: {srun_portal_api}")
    print(f"_PADCHAR: {_PADCHAR}")
    print(f"_ALPHA: {_ALPHA}")
    print(f"n: {n}")
    print(f"type_: {type_}")
    print(f"ac_id: {ac_id}")
    print(f"enc: {enc}")



def getRole(url):
    try:
        # 发送 GET 请求
        response = requests.get(url)

        # 检查请求是否成功 (状态码 200 表示成功)
        if response.status_code == 200:
            # 将网页内容存储在变量中
            web_content = response.text
            print("网页代码已获取")
            soup = BeautifulSoup(web_content, 'html.parser')

            # 创建存储字典
            domain_dict = {}

            # 查找 select 元素
            select = soup.find('select', {'name': 'domain'})
            tex=list()
            valu=list()
            # 遍历所有 option 元素
            for option in select.find_all('option'):
                value = option.get('value')
                text = option.get_text(strip=True)

                # 跳过空值和默认提示
                if value and text != '请选择':
                    # 去除 value 的 @ 符号作为键
                    key = value.lstrip('@')
                    tex.append(text)
                    valu.append(key)
                    domain_dict[key] = text




            print(domain_dict)

            return domain_dict
            # 可以在这里打印或处理网页内容
        else:
            print(f"请求失败，状态码：{response.status_code}")

    except requests.exceptions.RequestException as e:
        print(f"请求过程中出现错误：{e}")



# 获取单个字符的 ASCII 值
def _getbyte(s, i):
    x = ord(s[i])
    if x > 255:
        print("INVALID_CHARACTER_ERR: DOM Exception 5")
        exit(0)
    return x

# 自定义 Base64 编码
def get_base64(s):
    i = 0
    b10 = 0
    x = []
    imax = len(s) - len(s) % 3
    if len(s) == 0:
        return s
    for i in range(0, imax, 3):
        b10 = (_getbyte(s, i) << 16) | (_getbyte(s, i + 1) << 8) | _getbyte(s, i + 2)
        x.append(_ALPHA[(b10 >> 18)])
        x.append(_ALPHA[(b10 >> 12) & 63])
        x.append(_ALPHA[(b10 >> 6) & 63])
        x.append(_ALPHA[b10 & 63])
    i = imax
    remaining = len(s) - imax
    if remaining == 1:
        # 处理剩余1个字符，使用 _getbyte 安全访问
        b10 = _getbyte(s, i) << 16
        x.append(_ALPHA[(b10 >> 18)] + _ALPHA[(b10 >> 12) & 63] + _PADCHAR + _PADCHAR)
    elif remaining == 2:
        # 处理剩余2个字符，确保 i+1 不越界
        b10 = (_getbyte(s, i) << 16) | (_getbyte(s, i + 1) << 8)
        x.append(_ALPHA[(b10 >> 18)] + _ALPHA[(b10 >> 12) & 63] + _ALPHA[(b10 >> 6) & 63] + _PADCHAR)
    return "".join(x)

# HMAC-MD5 加密
def get_md5(password, token):
    return hmac.new(token.encode(), password.encode(), hashlib.md5).hexdigest()

# SHA-1 加密
def get_sha1(value):
    return hashlib.sha1(value.encode()).hexdigest()

# 字符串转字符数组
def force(msg):
    ret = []
    for w in msg:
        ret.append(ord(w))
    return bytes(ret)

# 获取指定位置的字符 ASCII 值
def ordat(msg, idx):
    if len(msg) > idx:
        return ord(msg[idx])
    return 0

# 自定义分组编码
def sencode(msg, key):
    l = len(msg)
    pwd = []
    for i in range(0, l, 4):
        pwd.append(
            ordat(msg, i) |
            ordat(msg, i + 1) << 8 |
            ordat(msg, i + 2) << 16 |
            ordat(msg, i + 3) << 24
        )
    if key:
        pwd.append(l)
    return pwd

# 自定义分组解码
def lencode(msg, key):
    l = len(msg)
    ll = (l - 1) << 2
    if key:
        m = msg[l - 1]
        if m < ll - 3 or m > ll:
            return
        ll = m
    for i in range(l):
        msg[i] = (
            chr(msg[i] & 0xff) +
            chr((msg[i] >> 8) & 0xff) +
            chr((msg[i] >> 16) & 0xff) +
            chr((msg[i] >> 24) & 0xff)
        )
    if key:
        return "".join(msg)[:ll]
    return "".join(msg)

# 自定义加密算法
def get_xencode(msg, key):
    if not msg:
        return ""
    pwd = sencode(msg, True)
    pwdk = sencode(key, False)
    if len(pwdk) < 4:
        pwdk += [0] * (4 - len(pwdk))
    n = len(pwd) - 1
    z = pwd[n]
    y = pwd[0]
    c = 0x86014019 | 0x183639A0
    m = 0
    e = 0
    p = 0
    q = math.floor(6 + 52 / (n + 1))
    d = 0
    while q > 0:
        d = (d + c) & 0xFFFFFFFF
        e = (d >> 2) & 3
        p = 0
        while p < n:
            y = pwd[p + 1]
            m = (z >> 5) ^ (y << 2)
            m += ((y >> 3) ^ (z << 4)) ^ (d ^ y)
            m += (pwdk[(p & 3) ^ e] ^ z)
            pwd[p] = (pwd[p] + m) & 0xFFFFFFFF
            z = pwd[p]
            p += 1
        y = pwd[0]
        m = (z >> 5) ^ (y << 2)
        m += ((y >> 3) ^ (z << 4)) ^ (d ^ y)
        m += (pwdk[(p & 3) ^ e] ^ z)
        pwd[n] = (pwd[n] + m) & 0xFFFFFFFF
        z = pwd[n]
        q -= 1
    return lencode(pwd, False)

# 请求头
header = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.26 Safari/537.36'
}



# 初始化获取 IP 地址
def init_getip():
    global ip, header
    init_res = requests.get(init_url, headers=header)
    print("初始化获取 IP 地址")
    ip = re.search(r'id="user_ip" value="(.*?)"', init_res.text).group(1)
    print("IP 地址：", ip)

# 获取令牌
def get_token():
    global token
    print("获取令牌:")

    get_challenge_paramss = {
        "callback": f"jQuery112404953340710317169_{int(time.time() * 1000)}",
        "username": username,
        "ip": ip,
        "_": int(time.time() * 1000),
    }
    print(get_challenge_paramss)
    get_challenge_res = requests.get(get_challenge_api, params=get_challenge_paramss, headers=header)
    token = re.search(r'"challenge":"(.*?)"', get_challenge_res.text).group(1)
    print("获取到的令牌：", token)

# 处理加密信息
def do_complex_work():
    global i, hmd5, chksum
    i = get_info()
    i = "{SRBX1}" + get_base64(get_xencode(i, token))
    hmd5 = get_md5(password, token)
    chksum = get_sha1(get_chksum())
    print("所有加密工作已完成")

# 构建校验字符串
def get_chksum():
    chkstr = token + username
    chkstr += token + hmd5
    chkstr += token + ac_id
    chkstr += token + ip
    chkstr += token + n
    chkstr += token + type
    chkstr += token + i
    return chkstr

# 获取信息字符串
def get_info():
    info_temp = {
        "username": username,
        "password": password,
        "ip": ip,
        "acid": ac_id,
        "enc_ver": enc
    }
    i = str(info_temp).replace("'", '"').replace(" ", "")
    return i

# 发起登录请求
def login():
    global username, password
    srun_portal_params = {
        'callback': f'jQuery11240645308969735664_{int(time.time() * 1000)}',
        'action': 'login',
        'username': username,
        'password': '{MD5}' + hmd5,
        'ac_id': ac_id,
        'ip': ip,
        'chksum': chksum,
        'info': i,
        'n': n,
        'type': type,
        'os': 'windows+10',
        'name': 'windows',
        'double_stack': '0',
        '_': int(time.time() * 1000)
    }
    print("发起登录请求...")
    srun_portal_res = requests.get(srun_portal_api, params=srun_portal_params, headers=header)
    print("登录请求响应：", srun_portal_res.text)
    json_response = srun_portal_res.text
    start = json_response.find("(") + 1
    end = json_response.rfind(")")
    json_data = json_response[start:end].strip()

    # 解析 JSON
    data = json.loads(json_data)

    # 提取 ecode 和 error
    ecode = data.get("ecode")
    error = data.get("error")

    print(f"ecode: {ecode}, error: {error}")


def check_network_connection(host='baidu.com', timeout=3):
    try:
        print(f"提取目标url:{host}")
        match = re.search(r"http://([^/]+)", host)
        if match:
            host = match.group(1)
            print(f"提取：{host}")
        else:
            print("无法提取 host 直接运行")
        # 尝试 ping 主机
        ping_param = '-n' if sys.platform.startswith('win') else '-c'
        result = subprocess.run(
            ['ping', ping_param, '1', host],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=3  # 设置超时时间为 3 秒
        )

        # 检查 ping 的返回值
        if result.returncode == 0:
            print("网络连接正常")
            return True
        else:
            print("网络连接异常")
            return False
    except subprocess.TimeoutExpired:
        print("网络连接超时")
        return False
    except Exception as e:
        print(f"网络连接检查失败：{e}")
        return False



def chooseRole(url):
    r = getRole(url)
    # 输出选项供用户选择
    print("请选择网络运营商对应的编号：")
    options = list(enumerate(r.items(), 1))
    for index, (key, value) in options:
        print(f"{index}. {value}")

    # 获取用户选择的编号
    selected_index = int(input("请输入编号："))

    # 根据编号查找对应的键值
    selected_key = None
    selected_value = None
    if 1 <= selected_index <= len(options):
        selected_key, selected_value = options[selected_index - 1][1]
        print(f"对应的键是：{selected_key}")
        return selected_key
    else:
        print("无效的编号，请重新选择。")


if __name__ == '__main__':
    parse_config(read_config())

    if check_network_connection(init_url,10):
        print("连接到学校认证服务器")
        while True:
            if check_network_connection():
                total_seconds = 60  # 休眠 60 秒
                # 使用 tqdm 显示进度条
                for _ in tqdm(range(total_seconds), desc="等待", ncols=100, unit="s"):
                    time.sleep(1)  #
            else:
                print("网络异常.\n")
                init_getip()
                get_token()
                do_complex_work()
                login()

