#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
from libs import nmap
from concurrent.futures import ThreadPoolExecutor

from libs.util import get_portable_path


def service_probe_by_nmap(config):
    current_function_name = sys._getframe().f_code.co_name  # print('当前函数名为:', current_function_name) # check_live_by_nmap
    config[current_function_name] = []
    config.logger.info("[+] 开始通过{}模块进行端口服务检测!!!".format(current_function_name))
    config[current_function_name] = NmapGetPortService(config).run()
    # 函数结果会返回到以当前函数名命名的config[]字典中。
    return config[current_function_name]


class NmapGetPortService(object):
    """获取端口运行的服务"""

    def __init__(self, config):
        # 基本设置
        super(NmapGetPortService, self).__init__()
        self.ip_port_service_dict = dict()
        self.logger = config.logger
        self.open_ip_port = config.all_open_ip_port
        self.logger = config.logger
        self.run_stop_flag = True

        # 程序设置
        self.program_name = "nmap"
        self.program_path = get_portable_path(config, self.program_name).replace("$BASE_DIR$", str(config.BASE_DIR))
        # self.logger.debug("[*]PATH {}: {}".format(self.program_name, self.program_path))
        # 读取程序必须参数thread_pool_number
        self.thread_pool_number = int(config[self.program_name + '_' + 'thread_pool_number'])
        self.service_probe_options = config[self.program_name + '_' + 'service_probe_options']

        # 其他设置
        self.init_thread()

    def init_thread(self):
        # 设定线程数量
        if 0 < len(self.open_ip_port) < self.thread_pool_number:
            self.thread_pool_number = len(self.open_ip_port)

    def nmap_service_module(self, ip, ports):
        # print('ip, ports', ip, ports) # ip, ports 192.168.1.1 80
        if self.run_stop_flag:
            try:
                nmap_scan = nmap.PortScanner(nmap_search_path=(
                    self.program_path, 'nmap', '/usr/bin/nmap', '/usr/local/bin/nmap', '/sw/bin/nmap',
                    '/opt/local/bin/nmap'))

                command = "{} -oX - {} -p {} {}".format(self.program_path,self.service_probe_options, ports, ip)

                self.logger.debug("[*] Prospects Command:\n {}".format(command))

                nmap_scan.scan(ip, arguments='{} -p {}'.format(self.service_probe_options, ports))

                self.logger.debug("[*] Actual Command:\n {}".format(nmap_scan.command_line()))

                self.logger.debug("[*] Program Output:\n{}".format(nmap_scan.get_nmap_last_output()))

                for ports in nmap_scan[ip]['tcp'].keys():
                    # result = "{:<17}{:<7}{:<10}{:<16}{:<16}{}".format(ip, ports, state, name, product, version)
                    service_result = dict()
                    service_result['type'] = 'nmap'
                    service_result['ports'] = ports
                    service_result['proto'] = nmap_scan[ip]['tcp'][ports]['name']
                    service_result['state'] = nmap_scan[ip]['tcp'][ports]['state']
                    service_result['product'] = nmap_scan[ip]['tcp'][ports]['product']
                    service_result['version'] = nmap_scan[ip]['tcp'][ports]['version']
                    service_result['response'] = 'NULL'
                    # print("service_result",service_result)
                    self.ip_port_service_dict[ip].append(service_result)
            except Exception as e:
                self.logger.error('[-] Nmap Has Exception {}'.format( str(e)))

    def run(self):
        self.logger.info("[+] Nmap -sV 扫描服务可能很慢, 请耐心等待...")
        try:
            with ThreadPoolExecutor(max_workers=self.thread_pool_number) as executor:
                # self.logger.debug(self.open_ip_port)
                for ip in self.open_ip_port.keys():
                    self.ip_port_service_dict[ip] = list()
                    ports = map(str, self.open_ip_port[ip])  # ports = self.open_ip_port[ip]
                    ports = ",".join(ports)
                    # print(ip, ports)  # 192.168.1.1 80
                    executor.submit(self.nmap_service_module, ip, ports)
        except KeyboardInterrupt:
            self.logger.error("[-] User aborted.")
            self.run_stop_flag = False
            sys.exit(0)
        except Exception as e:
            self.logger.error(str(e))
        print(self.ip_port_service_dict)
        return self.ip_port_service_dict
