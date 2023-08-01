#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import platform
from pathlib import Path
import re
import socket
import sys
from libs.IPy import IP
from libs.data import config

"""
def nook_get_masscan_file():
    os_type = platform.system()
    config.os_type = os_type
    masscan_path = config.BASE_DIR.joinpath("masscan")
    if os_type == 'Linux' or os_type == 'Darwin':
        if cmd_is_exist("masscan"):
            masscan_file = cmd_is_exist("masscan")
        else:
            masscan_file = str(masscan_path.joinpath("masscan"))
    if os_type == 'Windows':
        if cmd_is_exist("masscan.exe"):
            masscan_file = cmd_is_exist("masscan.exe")
        else:
            masscan_file = str(masscan_path.joinpath("masscan.exe"))
    return masscan_file
def nook_get_scanport_file():
    os_type = platform.system()
    config.os_type = os_type
    scanport_path = config.BASE_DIR.joinpath("scanport")
    if os_type == 'Linux' or os_type == 'Darwin':
        if cmd_is_exist("scanport"):
            scanport_file = cmd_is_exist("scanport")
        else:
            scanport_file = str(scanport_path.joinpath("scanport"))
    if os_type == 'Windows':
        if cmd_is_exist("scanport.exe"):
            scanport_file = cmd_is_exist("scanport.exe")
        else:
            scanport_file = str(scanport_path.joinpath("scanport.exe"))
    return scanport_file
def nook_cmd_is_exist(command):
    os_type = platform.system()
    env_path = os.getenv("PATH")

    if os_type == 'Linux' or os_type == 'Darwin':
        for cmdpath in env_path.split(":"):
            if os.path.isdir(cmdpath) and command in os.listdir(cmdpath):
                return cmdpath + "/" + command
    if os_type == 'Windows':
        for cmdpath in env_path.split(";"):
            if os.path.isdir(cmdpath) and command in os.listdir(cmdpath):
                return cmdpath + "\\" + command


def nook_handle_ports(ports):
    # 简单处理端口格式
    if isinstance(ports, list):
        ports = ','.join(ports)
    if isinstance(ports, str):
        ports = ports.replace(' ', '')
    # 端口列表去重,过滤
    if len(ports) > 0:
        # 计算所有扫描端口数量
        count_ports_all = 0
        if isinstance(ports, list):
            count_ports_all = len(ports)
        else:
            if '-' in ports and ',' in ports:
                portstrlist = ports.split(",")
                portlist = []
                for postStr in portstrlist:
                    if '-' in postStr:
                        port_start = int(postStr.split("-")[0].strip())
                        port_end = int(postStr.split("-")[1].strip())
                        portlist.extend([str(ports) for ports in range(port_start, port_end + 1)])
                    else:
                        portlist.append(postStr)
                ports = list(set(portlist))
            elif '-' in ports:
                port_start = int(ports.split("-")[0].strip())
                port_end = int(ports.split("-")[1].strip())
                portlist = [str(ports) for ports in range(port_start, port_end + 1)]
                ports = list(set(portlist))
            else:
                portlist = sorted(ports.split(","))
                ports = list(set(portlist))
            count_ports_all = len(ports)


def nook_open_ports_deduplication(config):
    open_port_list = config.open_ip_port_list
    count_ports_all = config.count_ports_all
    for ip in open_port_list.keys():
        # 开放端口去重
        open_port_list[ip] = list(set(open_port_list[ip]))
        # 通过比较IP对应的开放端口数量>=所有扫描ports数量来判断是否有拦截设备
        # 计算所有开放端口
        count_ports_open = len(open_port_list[ip])
        print('IP {} 本次扫描的所有端口 {} 个'.format(ip, count_ports_all))
        print('IP {} 本次扫描的所有开放端口 {} 个'.format(ip, count_ports_open))
        if (count_ports_all > 20) and (count_ports_open > count_ports_all * 0.5):
            formatStr = 'IP {} ,本次扫描端口共 {} 个,开放端口 {} 个, 开放率超过50%,可能有安全设备拦截, 置空模块端口扫描结果'.format(ip,
                                                                                               count_ports_all,
                                                                                               count_ports_open)
            print(formatStr)
            if config.ignore_ports_flag:
                open_port_list[ip] = []
            else:
                inputstr = input('即将置空扫描结果[确认Y|取消N]: ')
                if inputstr.lower() == 'n':
                    pass
                else:
                    open_port_list[ip] = []
        print(open_port_list)
"""


def ip_list_2_ip_segment(ip_host):
    # C段处理:ip列表转IP段 存在bug,按ip前三位数对应的后缀进行预测
    if len(ip_host) > 0:
        all_ip_list = []
        ip_prefix_list = [ip.rsplit('.', 1)[0] + '.' for ip in ip_host]
        ip_prefix_list = list(set(ip_prefix_list))
        # self.logger.debug('[*]tmp_ip_prefix_list',tmp_ip_prefix_list)
        # 从前缀列表生成一个'ip前缀':[]字典
        # fromkeys生成的数组的值id是相同的，不要用来指定数组
        # ip_prefix_dict = dict.fromkeys(ip_prefix_list , [])
        ip_prefix_dict = dict()
        for ip_prefix in ip_prefix_list:
            ip_prefix_dict[ip_prefix] = []
        # 将所有输入IP通过前缀进行区分
        # 生成一个'ip前缀':[ip后缀1,ip后缀1,...]字典
        for ip_prefix in ip_prefix_dict.keys():
            for ip in ip_host:
                if ip_prefix in ip:
                    ip_suffix = ip.rsplit('.', 1)[1].strip()
                    ip_prefix_dict[ip_prefix].append(ip_suffix)
        # print('ip_prefix_dict: {}'.format(ip_prefix_dict))
        # 根据ip前缀字典生成IP格式
        tmp_ip_suffix_list = []
        for ip_prefix in ip_prefix_dict.keys():
            tmp_ip_suffix_list = ip_prefix_dict[ip_prefix]
            tmp_ip_suffix_list = list(set(tmp_ip_suffix_list))  # 去重
            tmp_ip_suffix_list = [int(port) for port in tmp_ip_suffix_list]  # 排序之前需要改成数字类型
            tmp_ip_suffix_list.sort()  # 排序
            tmp_ip_suffix_list = [str(port) for port in tmp_ip_suffix_list]  # 排序之后需要改成字符串类型
            # 获得最大IP数量
            tmp_ip_count = int(tmp_ip_suffix_list[-1]) - int(tmp_ip_suffix_list[0]) + 1
            # 如果ip列表的长度==ip列表的数量,说明是连续格式，可以合并
            if (len(tmp_ip_suffix_list) >= tmp_ip_count) and (len(tmp_ip_suffix_list) != 1):
                # self.logger.debug('[*]输入的IP是连续的',tmp_ip_suffix_list)
                ip_prefix_suffix_str = ip_prefix + str(tmp_ip_suffix_list[0]) + '-' + str(tmp_ip_suffix_list[-1])
                all_ip_list.append(ip_prefix_suffix_str)
            # 如果ip列表的长度==ip列表的数量,说明不是连续格式，不进行合并
            else:
                # self.logger.debug('[*]输入的IP不是连续的',tmp_ip_suffix_list)
                ip_prefix_suffix_list = [ip_prefix + str(ip_prefix_suffix) for ip_prefix_suffix in
                                         tmp_ip_suffix_list]
                all_ip_list.extend(ip_prefix_suffix_list)
        ip_host = all_ip_list
    print('scan ip host: {}'.format(ip_host))
    return ip_host


def file_is_exist(filepath):
    '''判断文件是否存在'''
    if filepath:
        path = Path(filepath)
        if path.is_file():
            return True
        else:
            return False


def ip_is_invalid(ip):
    func = lambda _ip: all([int(x) < 256 for x in _ip.split('.')])
    return func(ip)


def get_portable_path(config, program_name):
    # 根据配置文件中程序的selection名称和程序命令行直接调用的名称获取到程序的命名路径,
    try:
        program_path = config[program_name + "_" + config.os_type.lower()]
        if program_path == "None":
            program_path = program_name
    except KeyError:
        program_path = program_name
    return program_path


def file_get_content(filename):
    """按行读取内容并组成列表"""
    with open(filename, 'r', encoding='utf-8') as f_obj:
        return [line.strip() for line in f_obj.readlines()]


def file_get_contents(file_name):
    """读取文件内容返回字符串"""
    data = ""
    try:
        f_obj = open(file_name, 'r', encoding='utf-8')
        data = f_obj.read()
    except Exception as e:
        return False
    else:
        return data
    finally:
        if f_obj:
            f_obj.close()


def config_key_with_prefix(config, prefix):
    # 输出字典内指定前缀的key:value字典
    tmp_dict = dict()
    for key, value in config.items():
        if key.startswith(prefix):
            tmp_dict[key] = value
    return tmp_dict


def config_key_with_suffix(config, suffix):
    # 返回字典内指定后缀的key:value字典
    tmp_dict = dict()
    for key, value in config.items():
        if key.endswith(suffix):
            tmp_dict[key] = value
    return tmp_dict


def config_a_value_with_prefix(config, prefix):
    # 返回字典内指定前缀的key的value,只返回第一个匹配,注意配置文件命名
    tmp_value = None
    for key, value in config.items():
        if key.startswith(prefix):
            tmp_value = value
            return tmp_value
    return tmp_value


def config_a_value_with_suffix(config, suffix):
    # 返回字典内指定后缀的key的value,只返回第一个,注意配置文件命名
    tmp_value = None
    for key, value in config.items():
        if key.endswith(suffix):
            tmp_value = value
            return tmp_value
    return tmp_value


def config_get_ports(config):
    # 解析扫描的端口
    config.logger.debug("[*] config.ports: {}".format(config.ports))
    if config.ports:
        if 'all' in config.ports:
            # 扫描全端口
            config.logger.debug('[*] Be going to Scan: ports_all_65535')
            config.ports = "1-65535"
        elif 'c1' in config.ports:
            config.logger.debug('[*] Be going to Scan: ports_common_100')
            config.ports = sorted(config.ports_common_100.split(","))
        elif 'c2' in config.ports:
            config.logger.debug('[*] Be going to Scan: ports_common_200')
            config.ports = sorted(config.ports_common_200.split(","))
        elif 'c3' in config.ports:
            config.logger.debug('[*] Be going to Scan: ports_common_300')
            config.ports = sorted(config.ports_common_300.split(","))
        else:
            # 去除端口之间的空格字符
            config.ports = config.ports.replace(' ', '')
            config.logger.debug('[*] Be going to Scan: {}'.format(config.ports))

            # 检测端口后端小于前端的问题
            for port in config.ports.split(','):
                if '-' in port:
                    port_start = int(port.split("-")[0].strip())
                    port_end = int(port.split("-")[1].strip())
                    if port_end < port_start:
                        config.logger.error('[*] 端口范围格式输入错误,后部范围小于前部范围!!!')
                        print('')
                        sys.exit()
    else:
        config.logger.debug('[*] 请输入需要扫描的端口号列表!!!')


def remove_no_open_port_ip_from_dict(config):
    # 去除端口为空的IP的字典
    if len(config.all_open_ip_port) > 0:
        for ip in config.all_open_ip_port.copy().keys():
            config.all_open_ip_port[ip] = list(set(config.all_open_ip_port[ip]))
            if not config.all_open_ip_port[ip]:
                config.all_open_ip_port.pop(ip)


def open_ip_result_to_file(config):
    if len(config.all_open_ip_port) > 0:
        result_file_ip = config.BASE_DIR.joinpath('log/result_ip_{}.csv'.format(config.start_time))
        config.logger.info('[+] 所有模块开放主机结果存储路径: {}'.format(result_file_ip))
        with open(result_file_ip, 'a+') as fp:
            for ip in config.all_open_ip_port:
                fp.write('{}'.format(ip) + '\n')
    else:
        config.logger.error('[-] 没有开放主机结果,跳过文件输出!!!')


def port_result_to_file(config):
    if len(config.all_open_ip_port) > 0:
        result_file_port = config.BASE_DIR.joinpath('log/result_portscan_{}.csv'.format(config.start_time))
        config.logger.info('[+] 所有模块开放主机和端口结果存储路径: {}'.format(result_file_port))
        with open(result_file_port, 'a+') as fp:
            for ip in config.all_open_ip_port.keys():
                if len(config.all_open_ip_port[ip]):
                    fp.write('{},{}'.format(ip, ','.join(map(str, config.all_open_ip_port[ip]))) + '\n')
    else:
        config.logger.error('[-] 没有开放主机和端口结果,跳过文件输出!!!')


def service_result_to_file(config):
    # 定义结果输出文件
    if len(config.all_ip_port_service) > 0:
        result_file_service = config.BASE_DIR.joinpath('log/result_service_{}.csv'.format(config.start_time))
        config.logger.info('[+] 所有模块开放主机和端口服务识别结果存储路径: {}'.format(result_file_service))
        with open(result_file_service, 'a+') as fp:
            # 获取IP对应的端口服务列表
            for ip in config.all_ip_port_service.keys():
                if len(config.all_ip_port_service[ip]) > 0:
                    # 获取IP对应的端口服务列表的对应端口服务字典
                    # {'type': 'nmap', 'ports': 25, 'proto': 'smtp', 'state': 'filtered', 'product': '', 'version': '', 'response': 'NULL'}
                    for port_service_dict in config.all_ip_port_service[ip]:
                        # print(port_service_dict)
                        if len(port_service_dict) > 0:
                            # 获取IP对应的端口服务列表的对应端口服务
                            result_output = '{},{},{},{},{},"{}","{}","{}"'.format(
                                ip,
                                port_service_dict['ports'],
                                port_service_dict['proto'],
                                port_service_dict['state'],
                                port_service_dict['type'],
                                port_service_dict['product'],
                                port_service_dict['version'],
                                port_service_dict['response'].replace('"', '').replace('\n', '\\n').replace('\r', '\\r'))
                            fp.write(result_output + '\n')
    else:
        config.logger.error('[-] 没有开放主机和端口服务识别结果,跳过文件输出!!!')


def config_get_target(config):
    # 判断命令行是否传入目标IP或目标文件参数
    destination_ips = config.get("target")
    config.logger.debug("[*] destination_ips: {}".format(destination_ips))

    destination_file = config.get("target_filename")
    config.logger.debug("[*] destination_file: {}".format(destination_file))
    # 判断是否输输入目标IP段或目标IP文件
    if not (destination_ips or destination_file):
        config.logger.error("[-] The arguments -i or -iL is required, please provide target !!!")
        sys.exit()
    else:
        config.ip_host = []
        pt = ParseTarget()
        # 如果输入目标文件,判断文件是否存在,存在就进行读取
        if destination_file is not None:
            if file_is_exist(destination_file):
                target_list = file_get_content(config.target_filename)
                tmp_target_list = pt.parse_ip_relaxed(target_list)
                # config.logger.debug("[*]tmp_target_list: {}".format(','.join(tmp_target_list)))
                config.ip_host.extend(tmp_target_list)
                config.logger.debug("[*] config.ip_host: {}".format(','.join(config.ip_host)))
            else:
                config.logger.error('[-] No such file or directory "{host_file}" !!!'.format(host_file=destination_file))
                sys.exit()

        # 如果输入的是目标IPS
        if destination_ips is not None:
            config.logger.debug("[*] destination_ips: {}".format(destination_ips))
            tmp_target_list = pt.parse_ip_relaxed(destination_ips)
            # config.logger.debug("[*]tmp_target_list: {}".format(','.join(tmp_target_list)))
            config.ip_host.extend(tmp_target_list)
            # config.logger.debug("[*]config.ip_host: {}".format(','.join(config.ip_host)))
        else:
            config.logger.debug("[*] destination_ips is not None !!!")
        # 对所有目标地址进行去重
        config.ip_host = list(set(config.ip_host))
        # config.logger.debug("[*]config.ip_host: {}".format(','.join(config.ip_host)))


def complex_ports_str_to_port_segment(ports_str):
    if isinstance(ports_str, list):
        ports_str = ','.join(ports_str)
    if isinstance(ports_str, str):
        ports_str = ports_str.replace(' ', '')

    # # 如果端口格式是 80,1-1000,10001
    if ',' in ports_str and '-' in ports_str:
        port_list = ports_str_to_port_list(ports_str)
        port_list.sort()
        if len(port_list) > 2000:
            # 如果端口超过500个,返回最小端口和最大端口范围 1-10001
            ports_str = '{port_start}-{port_end}'.format(port_start=port_list[0], port_end=port_list[-1])
            return ports_str
        else:
            # 如果端口不超过500个,返回,号拼接的端口列表
            ports_str = ','.join(str(port) for port in port_list)
        return ports_str
    # 如果端口格式是其他格式,就直接返回
    else:
        return ports_str


def ports_str_to_port_list(ports_str):
    port_list = []
    if isinstance(ports_str, list):
        ports_str = ','.join(ports_str)
    if isinstance(ports_str, str):
        ports_str = ports_str.replace(' ', '')

    for port_str in ports_str.split(","):
        if '-' in port_str:
            port_start = int(port_str.split("-")[0].strip())
            port_end = int(port_str.split("-")[1].strip())
            port_list.extend([port for port in range(port_start, port_end + 1)])
        else:
            port_list.append(int(port_str))
    return port_list


def parse_ip_strict(target):
    """
    略显严格的目标IP格式解析
    # 1.1.1.1-1.1.1.10
    # 10.17.1.1/24
    # 10.17.2.30-55
    # 10.111.22.12
    """
    ip_list = list()
    # 校验target格式是否正确
    m = re.match(
        r'\d{1,3}(\.\d{1,3}){3}-\d{1,3}(\.\d{1,3}){3}$', target)
    m1 = re.match(
        r'\d{1,3}(\.\d{1,3}){3}/(1[6789]|2[012346789]|3[012])$', target)
    m2 = re.match(r'\d{1,3}(\.\d{1,3}){3}-\d{1,3}$', target)
    m3 = re.match(r'\d{1,3}(\.\d{1,3}){3}$', target)
    if ',' in target:
        ip_list = target.split(',')
    elif m:
        prev = target.rsplit('.', 4)[0]
        start = target.rsplit('-', 1)[0].rsplit('.', 1)[1]
        end = target.rsplit('-', 1)[1].rsplit('.', 1)[1]
        if int(end) < int(start):
            print('IP范围前端大于后端,请重新输入!!!')
            exit()
        for x in range(int(start), int(end) + 1):
            ip_list.append(prev + "." + str(x))
    elif m1:
        tmp_ip_list = list()
        for x in IP(target, make_net=True):
            tmp_ip_list.append(str(x))
        ip_list = tmp_ip_list[1:]
    elif m2:
        prev = target.rsplit('.', 1)[0]
        st, sp = target.split('.')[-1].split('-')
        if int(sp) < int(st):
            print('IP范围前端大于后端,请重新输入!!!')
            exit()
        for x in range(int(st), int(sp) + 1):
            ip_list.append(prev + "." + str(x))
    elif m3:
        ip_list.append(target)
    else:
        error_msg = "IP {} invalid format".format(target)
        raise Exception(error_msg)

    # 校验 ip 是否正确
    func = lambda x: all([int(y) < 256 for y in x.split('.')])
    for ip in ip_list:
        if not func(ip):
            error_msg = "IP {} invalid format".format(target)
            raise Exception(error_msg)

    return ip_list


class ParseTarget(object):
    """ParseTarget"""

    def __init__(self):
        super(ParseTarget, self).__init__()
        self.ip_list = list()

    def parse_ip_relaxed(self, targets):
        """
        略显宽松的目标IP格式解析
        # 10.17.1.1/24
        # 10.17.2.30-55
        # 10.111.22.12
        """
        if isinstance(targets, list):
            for target in targets:
                ips = parse_ip_strict(target)
                self.ip_list.extend(ips)
        elif isinstance(targets, str):
            if ',' in targets:
                targets = targets.split(',')
                for target in targets:
                    ips = parse_ip_strict(target)
                    self.ip_list.extend(ips)
            else:
                ips = parse_ip_strict(targets)
                self.ip_list.extend(ips)

        # ip 排序去重
        ips = [ip for ip in sorted(set(self.ip_list), key=socket.inet_aton)]
        return ips


if __name__ == '__main__':
    pt = ParseTarget()
    print(parse_ip_strict("127.0.0.1"))
