#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import requests

from libs.util import ports_str_to_port_list, complex_ports_str_to_port_segment

requests.packages.urllib3.disable_warnings()
from concurrent.futures import ThreadPoolExecutor
from libs import telnetlib


def port_scan_by_telnet(config):
    current_function_name = sys._getframe().f_code.co_name  # print('当前函数名为:', current_function_name) # check_live_by_nmap
    config[current_function_name] = []
    config.logger.info("[+] 开始通过{}模块进行IP端口检测!!!".format(current_function_name))
    config[current_function_name] = TelnetScan(config).run()
    # 函数结果会返回到以当前函数名命名的config[]字典中。
    return config[current_function_name]


class TelnetScan(object):
    """
    如果扫描结果返回很多端口，那可能是因为有设备
    此时使用 http 直接访问常见 web 端口
    """

    def __init__(self, config):
        super(TelnetScan, self).__init__()
        self.open_ip_port_list = dict()
        self.logger = config.logger

        self.alive_ip_host = config.all_alive_ip_host
        self.ports = config.ports

        self.run_stop_flag = True
        self.ignore_ports_flag = config.ignore_ports_flag

        # 程序设置
        self.program_name = "telnet"
        # 读取程序必须参数thread_pool_number
        self.thread_pool_number = int(config[self.program_name + '_' + 'thread_pool_number'])
        self.timeout = float(config[self.program_name + '_' + 'timeout'])

        # 其他设置
        self.ip_port_list = list()
        self.port_list = ports_str_to_port_list(self.ports)

        self.init_thread()
        self.init_ip_port_list()

    def init_ip_port_list(self):
        # 生成IP,PORT列表
        for ip in self.alive_ip_host:
            for port in self.port_list:
                self.ip_port_list.append((ip, port))

    def init_thread(self):
        # 根据 IP,Port 设定线程数量, 最大200线程
        if 0 < len(self.ip_port_list) < self.thread_pool_number:
            self.thread_pool_number = len(self.ip_port_list)

    def telnet_scan(self, ip, port):
        if self.run_stop_flag:
            try:
                tn = telnetlib.Telnet(ip, port, timeout=1)
            except Exception as e_msg:
                error_msg = str(e_msg)
                if ' timeout' in error_msg:
                    pass
                    # self.logger.debug("[*]{:<17}{:<7}{}".format(ip, ports,'connect timeout'))
                elif ' ConnectionResetError' in error_msg:
                    pass
                    # self.logger.debug("[*]{:<17}{:<7}{}".format(ip, ports, "Connect Reset"))
                else:
                    pass
                    # self.logger.debug('[*]{:<17}{:<7}{}'.format(ip, ports, error_msg))
            else:
                pass
                # self.logger.debug("[*]{:<17}{:<7}{}".format(ip, ports, "open"))
                if ip not in self.open_ip_port_list: self.open_ip_port_list[ip] = list()
                self.open_ip_port_list[ip].append(port)

    def run(self):
        try:
            with ThreadPoolExecutor(max_workers=self.thread_pool_number) as executor:
                for ip, port in self.ip_port_list:
                    executor.submit(self.telnet_scan, ip, port)
        except KeyboardInterrupt:
            self.logger.error("[-] User aborted.")
            self.run_stop_flag = False
            sys.exit(0)
        except Exception as e:
            self.logger.error(str(e))

        # 输出IP对于端口扫描结果
        ports = complex_ports_str_to_port_segment(self.ports)
        for ip in self.alive_ip_host:
            if ip in self.open_ip_port_list and len(self.open_ip_port_list[ip]) > 0:
                self.logger.debug("[*] {}:{}:{}".format(ip, ports if len(ports) < 20 else str(ports[:20]) + "...", self.open_ip_port_list[ip]))
            else:
                self.logger.error("[-] {}:{}:没有扫描到端口".format(ip, ports if len(ports) < 20 else str(ports[:20]) + "..."))
        return self.open_ip_port_list
