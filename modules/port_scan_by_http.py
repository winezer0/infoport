#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import requests

from libs.util import ports_str_to_port_list, complex_ports_str_to_port_segment

requests.packages.urllib3.disable_warnings()
from concurrent.futures import ThreadPoolExecutor


def port_scan_by_http(config):
    current_function_name = sys._getframe().f_code.co_name  # print('当前函数名为:', current_function_name) # check_live_by_nmap
    config[current_function_name] = []
    config.logger.info("[+] 开始通过{}模块进行IP端口检测!!!".format(current_function_name))
    config[current_function_name] = HttpScan(config).run()
    # 函数结果会返回到以当前函数名命名的config[]字典中。
    return config[current_function_name]


class HttpScan(object):

    def __init__(self, config):
        # 基本设置
        super(HttpScan, self).__init__()
        self.open_ip_port_list = dict()  # 存放IP及其对应的开放端口列表
        self.logger = config.logger
        self.alive_ip_host = config.all_alive_ip_host

        self.ports = config.ports
        self.ignore_ports_flag = config.ignore_ports_flag
        self.run_stop_flag = True

        # 程序设置
        self.program_name = "http"
        self.timeout = float(config[self.program_name + '_' + 'timeout'])
        self.thread_pool_number = int(config[self.program_name + '_' + 'thread_pool_number'])

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

    def http_scan(self, ip, port):
        # 端口探测
        if self.run_stop_flag:
            try:
                url = "http://{}:{}".format(ip, port)
                resp = requests.get(url=url, timeout=self.timeout, verify=False)
                self.logger.debug("[*] Program Output:\n{}".format(str(resp.content) if len(resp.content) < 200 else str(resp.content[:200]) + "..."))
            except Exception as e:
                e_msg_list = ["time out"]
                for e_msg in e_msg_list():
                    if e_msg in str(e): pass
                else:
                    self.logger.debug('[-] http://{}:{} {}'.format(ip, port, str(e)))
            else:
                if ip not in self.open_ip_port_list: self.open_ip_port_list[ip] = list()
                self.open_ip_port_list[ip].append(port)

    def run(self):
        # self.logger.debug(self.ip_port_list)
        try:
            with ThreadPoolExecutor(max_workers=self.thread_pool_number) as executor:
                for ip, port in self.ip_port_list:
                    executor.submit(self.http_scan, ip, port)
        except KeyboardInterrupt:
            self.logger.error("[-] User aborted.")
            self.run_stop_flag = False
            sys.exit(0)
        except Exception as e:
            self.logger.error(str(e))

        # 输出IP对于端口扫描结果
        ports = complex_ports_str_to_port_segment(self.ports)
        for ip in self.open_ip_port_list.keys():
            if ip in self.open_ip_port_list and len(self.open_ip_port_list[ip]) > 0:
                self.logger.debug("[*] {}:{}:{}".format(ip, ports if len(ports) < 20 else str(ports[:20]) + "...", self.open_ip_port_list[ip]))
            else:
                self.logger.error("[-] {}:{}:没有扫描到端口".format(ip, ports if len(ports) < 20 else str(ports[:20]) + "..."))
        return self.open_ip_port_list
