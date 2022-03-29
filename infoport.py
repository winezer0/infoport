#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys

# 设置不生成pyc文件
sys.dont_write_bytecode = True
import pathlib
from libs.data import config
import platform
import time
from libs.parse_input import ParserCmd

from libs.logger_output import set_logger
from libs.deault_config import make_default_config
from libs.util import file_is_exist, config_get_target, config_get_ports
from libs.util import config_key_with_prefix, remove_no_open_port_ip_from_dict
from libs.util import service_result_to_file, port_result_to_file, open_ip_result_to_file
from configparser import ConfigParser
from modules.check_alive_by_nmap import check_alive_by_nmap
from modules.port_scan_by_nmap import port_scan_by_nmap
from modules.port_scan_by_portscan import port_scan_by_portscan
from modules.port_scan_by_masscan import port_scan_by_masscan
from modules.port_scan_by_asyctcp import port_scan_by_asyctcp
from modules.port_scan_by_telnet import port_scan_by_telnet
from modules.port_scan_by_http import port_scan_by_http
from modules.port_scan_by_blackwater import port_scan_by_blackwater
from modules.service_probe_by_nmap import service_probe_by_nmap
from modules.service_probe_by_tcpscan import service_probe_by_tcpscan


def init():
    # 使用全局字典config保存配置文件中的属性,AttribDict()是修改原生的dict定制的属性字典
    config.BASE_DIR = pathlib.Path(__file__).parent.resolve()
    # print("config.BASE_DIR",config.BASE_DIR)
    # 使用pathlib模块获取程序的绝对路径,BASE_DIR是path类型,替换时需要使用str()转换
    # 之后通过config.BASE_DIR在所有模块中直接调用BASE_DIR变量
    config.os_type = platform.system()
    config.start_time = time.strftime("%Y%m%d%H%M%S", time.localtime())

    # 解析命令行参数
    args = ParserCmd().init()
    # 将用户输入的参数传递到全局字典config,,后续增加命令行功能时可优先于配置文件参数
    # 暂时必须的参数 config.view_detail_flag
    config.update(args)

    # 设置日志路径,并开启日志记录功能
    # 设置默认logger输出文件路径,注意,需要config中存在view_detail_flag参数,否则会报错,
    # view_detail_flag参数默认是从args中获取的,因此需要config.update(args)在config.logger函数前被调用
    # 注意,不能用config.logger输出config.logger [config.logger.info(config)会提示RuntimeError]
    # RuntimeError: SimpleQueue objects should only be shared between processes through inheritance
    config.log_file_path = config.BASE_DIR.joinpath("log/result.log")
    config.dbg_log_file_path = config.BASE_DIR.joinpath("log/runtime.log")
    config.err_log_file_path = config.BASE_DIR.joinpath("log/error.log")

    set_logger(config)
    config.logger.info("[+] args: {}".format(args))

    config_file_path = args.get("config_file")
    config_file_path = config_file_path.replace('$BASE_DIR$', str(config.BASE_DIR))
    config.logger.info("[+] config_file_path: {}".format(config_file_path))

    # 读取配置文件,根据配置文件加入config字典
    if not file_is_exist(config_file_path): make_default_config(config_file_path)
    config_parser = ConfigParser()
    config_parser.read(config_file_path)

    # 将配置文件中的参数批量加入config字典
    for section in config_parser.sections():
        # 每个section是一个list()范围
        # config.logger.debug(section)
        for key, value in config_parser.items(section):
            # print("section:", section)  # section: cpp_nmap
            # print("key:", key)  # key: windows
            # print("value:", value)  # value: $BASE_DIR$\thirdparty\cpp_nmap\nmap.exe
            # 首先导入args到config时,应该添加判断如果相同的键值对已经存在,应该跳过处理
            section_key = section + '_' + key
            section_prefix = section + '_'
            if section_key in config:
                config.logger.debug("[*] 由于键值对{key}已存在,因此不再从config文件中读取该参数.".format(key=key))
            else:
                config[section_key] = value.strip()
                # 每个section包含多个键值对,因此不能直接使用字典进行保存

                # 使用一层字典保存全局变量,配置不支持多个sections,且所有的变量不能重名
                # config示例 {'BASE_DIR': 'C:\\Users\\WINDOWS\\Desktop\\infoport', 'cpp_nmap_min_parallelism', '100',...}
                # config[key] =  value.strip()

                # 使用二层字典保存全局变量,配置支持多个sections,但需要多层次调用变量,选择,直接作为字典保存会导致前后覆盖
                # config[section] = {key, value.strip()}

                # 但是使用数组保存也会导致没有办法调用,最内层是数组,不能使用
                # config示例  {'BASE_DIR': 'C:\\Users\\WINDOWS\\Desktop\\infoport', 'portscan_module': [{'go_portScan', 'p1'}, {'cpp_masscan', 'p2'}, {'inner_socket', 'p3'}],}
                # config[section].append({key, value.strip()})

                # 将section+key作为字典的键值对,可直接使用一级字典保存,但是不能够再使用config[section]直接调用,需要自定义的方式config_key_with_prefix(config, section + '_')批量调出section_的属性
                # {'cpp_nmap_cpp_nmap_linux': '$BASE_DIR$\\thirdparty\\cpp_nmap\\nmap', 'cpp_nmap_cpp_nmap_min_hostgroup': '50','key':'value'}
        # 使用自定义函数读取每个section的元素
        config.logger.debug("[*] {}: {}".format(section_prefix, config_key_with_prefix(config, section_prefix)))
        # 使用自定义函数读取每个section的元素 #必须使用print打印config整体,logger打印自身会报错
        # 自定义参数:{BASE_DIR:C:\Users\WINDOWS\Desktop\infoport} 脚本输入参数:{target:127.0.0.1/30}
        # 配置文件参数:{portscan_module_p1:go_portScan}  配置文件参数:{service_module_s2:inner_tcp}
        # for key, value in config.items(): print("{{{key}:{value}}}".format(key=key, value=value))

    # 导入并解析扫描目标 # config.ip_host #存放所有IP列表
    config_get_target(config)
    # print(config.ip_host)  # ['192.168.88.136', '192.168.88.243',

    # 导入扫描端口 # config.ports #存放所有端口字符串
    config_get_ports(config)
    # print(config.ports) #1-1000


def check_alive():
    # 导入主机存活检测模块# # 检测存活主机 # config.all_alive_ip_host用于存储所有存活IP列表
    config.all_alive_ip_host = []

    # 从配置文件中获取所有支持的存活检测选项
    all_check_alive_module = config.base_all_check_alive_module.replace(" ", '').split(',')

    # 获取用户输入的存活检测模块选项
    if config.check_alive.lower() == 'none':
        config.logger.info("[-] 已关闭存活主机检测模块")
        config.all_alive_ip_host = config.ip_host
    else:
        config.logger.info("[+] 已开启存活主机检测模块")
        if 'all' in config.check_alive:
            input_check_alive_module = all_check_alive_module
        else:
            input_check_alive_module = config.check_alive.replace(" ", '').split(',')

        for input_module in input_check_alive_module:
            for check_alive_module in all_check_alive_module:
                if check_alive_module.startswith(input_module) or check_alive_module.endswith(input_module):
                    func_name = 'check_alive_by_' + check_alive_module.split(':')[-1]
                    # config.logger.info("[+] 正在使用{}模块进行存活主机检测...".format(func_name))
                    globals().get(func_name)(config)  # 函数结果会存储在config[函数名],也会返回存活主机列表
                    config.logger.info('[+] {}: {}'.format(func_name, config[func_name]))
                    config.all_alive_ip_host.extend(config[func_name])
                    break
        # 当未进行存活主机检测,或检测结果为空时,直接进行端口扫描
        if len(config.all_alive_ip_host) == 0:
            config.all_alive_ip_host = config.ip_host
            config.logger.info("[-] 未检测到任何存活主机,将为所有IP进行端口检测!!!")
        else:
            config.logger.info("[+] 所有模块存活IP检测结果: {}".format(config.all_alive_ip_host))


def check_ports():
    # 进行端口扫描探测 #存储所有开放的主机:[端口]
    config.all_open_ip_port = dict()
    # 进行端口扫描探测 #存储所有包含端口的主机
    config.all_open_ip_port_keys = list()

    all_portscan_module = config.base_all_port_scan_module.replace(" ", '').split(',')
    # 获取用户输入的端口扫描模块选项
    if 'all' in config.port_scan:
        input_portscan_module = all_portscan_module
    else:
        input_portscan_module = config.port_scan.replace(" ", '').split(',')
    # 输出被用户指定的端口
    # config.logger.debug('[*]config.ports: {}'.format(config.ports))
    # 输出配置文件中所有存在的端口扫描模块列表
    # config.logger.debug('[*] all_portscan_module: {}'.format(all_portscan_module))
    # 输出用户需要进行的端口扫描模块列表
    # config.logger.debug('[*] input_portscan_module: {}'.format(input_portscan_module))
    # 检测主机端口开放情况
    # globals().get('port_scan_by_nmap')(config) #已测试
    # port_scan_by_nmap(config)  # 已测试
    # config.logger.info('[+]config.port_scan_by_nmap: {}'.format(config.port_scan_by_nmap))
    # port_scan_by_portscan(config)  # 已测试
    # config.logger.info('[+]config.port_scan_by_portscan: {}'.format(config.port_scan_by_portscan))
    # port_scan_by_masscan(config)  # 已测试
    # config.logger.info('[+]config.port_scan_by_masscan: {}'.format(config.port_scan_by_masscan))
    # port_scan_by_asyctcp(config) # 已测试
    # config.logger.info('[+]config.port_scan_by_asyctcp: {}'.format(config.port_scan_by_asyctcp))
    # port_scan_by_http(config) # 已测试
    # config.logger.info('[+]config.port_scan_by_http: {}'.format(config.port_scan_by_http))
    # port_scan_by_telnet(config)  # 已测试
    # config.logger.info('[+]config.port_scan_by_telnet: {}'.format(config.port_scan_by_telnet))
    # port_scan_by_blackwater(config)  # 已测试
    # config.logger.info('[+]config.port_scan_by_blackwater: {}'.format(config.port_scan_by_blackwater))

    # 从配置文件中获取所有支持的端口扫描模块选项
    # 从配置文件获取所有扫描方式-并匹配用户输入的方式进行扫描 # 将用户输入的模块和所有的模块进行匹配,并根据模块函数名进行调用

    real_portscan_module = []
    for input_module in input_portscan_module:
        for portscan_module in all_portscan_module:
            if portscan_module.startswith(input_module) or portscan_module.endswith(input_module):
                real_portscan_module.append(portscan_module)
                # config.logger.debug('[*]portscan_module: {}'.format(portscan_module))
                # 有些情况下，要传递哪个函数这个问题事先还不确定，例如函数名与某变量有关。可以利用 func = globals().get(func_name)来得到函数
                func_name = 'port_scan_by_' + portscan_module.split(':')[-1]
                # config.logger.debug('[*]正在调用函数[{}]进行端口扫描...'.format(func_name))
                globals().get(func_name)(config)
                config.logger.info('[+] {}: {}'.format(func_name, config[func_name]))
                break

    # 合并所有模块的端口扫描结果
    for portscan_module in real_portscan_module:
        func_name = 'port_scan_by_' + portscan_module.split(':')[-1]
        # 将扫描结果加入config.open_ip_port字典,merge函数确实存在问题
        # config.all_open_ip_port = merge(config.all_open_ip_port, config[func_name])
        # 傻瓜方法合并所有扫描结果
        if func_name in config and len(config[func_name].keys()) > 0:
            for ip in config[func_name].keys():
                if ip not in config.all_open_ip_port:
                    config.all_open_ip_port[ip] = list()
                # 如果模块结果中有IP的结果,就加入结果列表
                if config.ignore_ports_flag and len(config[func_name][ip]) > 100:
                    config.logger.error("[-] {}模块检测到主机{}开放的端口超过100个,忽略该扫描结果!!!".format(func_name, ip))
                else:
                    config.all_open_ip_port[ip].extend(config[func_name][ip])
        else:
            config.logger.error("[-] {}模块没有检测到开放主机端口".format(func_name))

    # 进行端口号去重、去None和排序
    for ip in config.all_open_ip_port.keys():
        config.all_open_ip_port[ip] = list(set([port for port in config.all_open_ip_port[ip] if port is not None]))
        config.all_open_ip_port[ip].sort()

    # 移除没有开放端口的键
    remove_no_open_port_ip_from_dict(config)

    config.logger.info("[+] 所有模块检测的开放主机和端口: {}".format(config.all_open_ip_port))


def check_service():
    # 导入端口服务探测模块

    # 进行端口服务探测 #存储所有开放的主机:[端口]的服务信息
    config.all_ip_port_service = dict()

    # 从配置文件中获取所有支持的服务探测扫描模块选项
    all_service_probe_module = config.base_all_service_probe_module.replace(" ", '').split(',')

    # 获取用户输入的端口扫描模块选项
    if 'all' in config.service_scan:
        input_service_probe_module = all_service_probe_module
    else:
        input_service_probe_module = config.service_scan.replace(" ", '').split(',')

    # 输出配置文件中所有存在的端口扫描模块列表
    config.logger.debug('[*] all_service_probe_module: {}'.format(all_service_probe_module))
    # 输出用户需要进行的端口扫描模块列表
    config.logger.debug('[*] input_service_probe_module: {}'.format(input_service_probe_module))

    # service_probe_by_tcpscan(config)
    # print(config["service_probe_by_tcpscan"])
    # service_probe_by_nmap(config)
    # print(config["service_probe_by_nmap"])

    # 从配置文件获取所有扫描方式-并匹配用户输入的方式进行扫描 # 将用户输入的模块和所有的模块进行匹配,并根据模块函数名进行调用
    real_service_probe_module = []
    for input_module in input_service_probe_module:
        for service_probe_module in all_service_probe_module:
            if service_probe_module.startswith(input_module) or service_probe_module.endswith(input_module):
                real_service_probe_module.append(service_probe_module)
                # config.logger.debug('[*] portscan_module: {}'.format(portscan_module))
                # 有些情况下，要传递哪个函数这个问题事先还不确定，例如函数名与某变量有关。可以利用 func = globals().get(func_name)来得到函数
                func_name = 'service_probe_by_' + service_probe_module.split(':')[-1]
                # config.logger.debug('[*] [{}]进行服务扫描...'.format(func_name))
                globals().get(func_name)(config)
                config.logger.info('[+] {}: {}'.format(func_name, config[func_name]))
                break

    # 合并所有模块的服务识别结果
    for service_probe_module in real_service_probe_module:
        func_name = 'service_probe_by_' + service_probe_module.split(':')[-1]
        # 将扫描结果加入config.open_ip_port字典
        # 傻瓜方法合并所有扫描结果
        if func_name in config and len(config[func_name].keys()) > 0:
            for ip in config[func_name].keys():
                if ip not in config.all_ip_port_service:
                    config.all_ip_port_service[ip] = list()
                # 如果模块结果中有IP的结果,就加入结果列表
                config.all_ip_port_service[ip].extend(config[func_name][ip])
        else:
            config.logger.error("[-] {}模块没有检测到开放主机端口服务".format(func_name))

    config.logger.info('[+] 所有模块开放主机和端口服务识别结果: {}'.format(config.all_ip_port_service))


def main():
    init()

    check_alive()

    check_ports()

    check_service()

    # 开放主机列表输出到文件
    open_ip_result_to_file(config)

    # 将端口扫描结果输出到文件
    port_result_to_file(config)

    # 将服务扫描结果输出到文件
    service_result_to_file(config)

    # import os
    # os.unlink('config.ini') # 删除配置文件


if __name__ == '__main__':
    main()
