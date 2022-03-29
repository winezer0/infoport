#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from libs import nmap
from concurrent.futures import ThreadPoolExecutor
from libs.util import get_portable_path, complex_ports_str_to_port_segment


def port_scan_by_nmap(config):
    # print('开始进行NmapPortScan')
    current_function_name = sys._getframe().f_code.co_name  # print('当前函数名为:', current_function_name) # check_live_by_nmap
    config[current_function_name] = []
    config.logger.info("[+] 开始通过{}模块进行IP端口检测!!!".format(current_function_name))
    config[current_function_name] = NmapPortScan(config).run()
    # 函数结果会返回到以当前函数名命名的config[]字典中。
    return config[current_function_name]


class NmapPortScan(object):
    """端口扫描"""

    def __init__(self, config):
        # 基本设置
        super(NmapPortScan, self).__init__()
        self.open_ip_port_list = dict()  # 存放IP及其对应的开放端口列表
        self.logger = config.logger
        self.alive_ip_host = config.all_alive_ip_host
        self.ports = config.ports
        self.ignore_ports_flag = config.ignore_ports_flag
        self.run_stop_flag = True

        # 程序设置
        self.program_name = "nmap"
        self.program_path = get_portable_path(config, self.program_name).replace("$BASE_DIR$", str(config.BASE_DIR))
        # self.logger.debug("[*]PATH {}: {}".format(self.program_name, self.program_path))
        # 读取程序必须参数thread_pool_number
        self.thread_pool_number = int(config[self.program_name + '_' + 'thread_pool_number'])
        # 读取程序必须参数port_scan_options
        self.port_scan_options = config[self.program_name + '_' + 'port_scan_options']

        # 其他设置
        self.init_thread()

    def init_thread(self):
        # 设定线程池数量
        # print('优化线程数量...')
        if 0 < len(self.alive_ip_host) < self.thread_pool_number:
            self.thread_pool_number = len(self.alive_ip_host)

    def nmap_scan(self, ip, ports):
        # nmap 端口探测
        # print('进行端口探测...')
        if self.run_stop_flag:
            try:
                nmap_scan = nmap.PortScanner(nmap_search_path=(
                    self.program_path, 'nmap', '/usr/bin/nmap', '/usr/local/bin/nmap', '/sw/bin/nmap',
                    '/opt/local/bin/nmap'))

                self.logger.debug(
                    "[*] Prospects Command:\n {} -oX - {} -p {} {}".format(self.program_path, self.port_scan_options,
                                                                           ports if len(ports) < 20 else str(ports[:20]) + "...", ip))

                nmap_scan.scan(self.port_scan_options, arguments="{ip} -p {ports}".format(ip=ip, ports=ports))

                self.logger.debug("[*] Actual Command:\n {}".format(nmap_scan.command_line()))

                self.logger.debug("[*] Program Output:\n{}".format(nmap_scan.get_nmap_last_output()))

                port_result = nmap_scan[ip]['tcp']
                for port in port_result.keys():
                    state = port_result[port]['state']
                    if state == "open":
                        if ip in self.open_ip_port_list:
                            self.open_ip_port_list[ip].append(port)
                        else:
                            self.open_ip_port_list[ip] = [port]

                # 输出IP对应的端口扫描结果
                if len(self.open_ip_port_list[ip]) > 0:
                    self.logger.debug("[*] {}:{}:{}".format(ip, ports if len(ports) < 20 else str(ports[:20]) + "...", self.open_ip_port_list[ip]))
                else:
                    self.logger.error("[-] {}:{}:没有扫描到端口".format(ip, ports if len(ports) < 20 else str(ports[:20]) + "..."))

            except Exception as e:
                if 'tcp' in str(e):
                    self.logger.error("[-] {}:{}:没有扫描到端口".format(ip, ports if len(ports) < 20 else str(ports[:20]) + "..."))
                else:
                    self.logger.error("[-] {}:{}:{}".format(ip, ports if len(ports) < 20 else str(ports[:20]) + "...", str(e)))
                raise e

    def run(self):
        try:
            with ThreadPoolExecutor(max_workers=self.thread_pool_number) as executor:
                for ip in self.alive_ip_host:
                    executor.submit(self.nmap_scan, ip, complex_ports_str_to_port_segment(self.ports))
        except KeyboardInterrupt:
            self.logger.error("[-] User aborted.")
            self.run_stop_flag = False
            sys.exit(0)
        except Exception as e:
            self.logger.error(str(e))
            self.run_stop_flag = False
            sys.exit(0)

        return self.open_ip_port_list
