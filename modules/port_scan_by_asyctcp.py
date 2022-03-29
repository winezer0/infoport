#!/usr/bin/env python
# -*- coding: utf-8 -*-

import asyncio
import sys
import time
from libs.util import ports_str_to_port_list, complex_ports_str_to_port_segment


def port_scan_by_asyctcp(config):
    current_function_name = sys._getframe().f_code.co_name  # print('当前函数名为:', current_function_name) # check_live_by_nmap
    config[current_function_name] = []
    config.logger.info("[+] 开始通过{}模块进行IP端口检测!!!".format(current_function_name))
    config[current_function_name] = AsyncTcpScan(config).run()
    # 函数结果会返回到以当前函数名命名的config[]字典中。
    return config[current_function_name]


class AsyncTcpScan(object):
    def __init__(self, config):
        # 基本设置
        super(AsyncTcpScan, self).__init__()
        self.open_ip_port_list = dict()  # 存放IP及其对应的开放端口列表
        self.logger = config.logger
        self.alive_ip_host = config.all_alive_ip_host
        self.ports = config.ports
        self.ignore_ports_flag = config.ignore_ports_flag

        self.run_stop_flag = True

        self.os_type = config.os_type

        # 程序设置
        self.program_name = "asyctcp"
        self.timeout = float(config[self.program_name + '_' + 'timeout'])
        self.rate = int(config[self.program_name + '_' + 'rate'])

        # 其他设置
        self.init_rate()
        self.port_list = ports_str_to_port_list(self.ports)

    def init_rate(self):
        # 设置扫描速率
        if self.os_type == 'Windows' and self.rate > 500:
            self.rate = 500

    async def async_port_check(self, semaphore, ip, port):
        async with semaphore:
            try:
                conn = asyncio.open_connection(ip, port)
                _, _ = await asyncio.wait_for(conn, timeout=self.timeout)
                return ip, port, 'open'
            except KeyboardInterrupt:
                time.sleep(self.timeout)
                self.logger.error("[-] User aborted.")
                exit(0)
            except Exception as e:
                return ip, port, 'close'
            finally:
                conn.close()

    def callback(self, future):
        # 回调处理结果
        ip, port, status = future.result()
        if status == "open":
            try:
                if ip not in self.open_ip_port_list: self.open_ip_port_list[ip] = []
                self.open_ip_port_list[ip].append(port)
            except Exception as e:
                self.logger.error("[-] Exception {}".format(str(e)))

    def run(self):
        # 处理IP,端口列表
        ip_port_list = [(ip, port) for ip in self.alive_ip_host for port in self.port_list]

        # 开始异步扫描任务
        tasks = list()
        # 限制异步扫描并发量
        sem = asyncio.Semaphore(self.rate * len(self.alive_ip_host))
        for ip, port in ip_port_list:
            task = asyncio.ensure_future(self.async_port_check(sem, ip, port))
            task.add_done_callback(self.callback)
            tasks.append(task)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(asyncio.wait(tasks))

        # 输出IP对于端口扫描结果
        ports = complex_ports_str_to_port_segment(self.ports)
        for ip in self.alive_ip_host:
            if ip in self.open_ip_port_list and len(self.open_ip_port_list[ip]) > 0:
                self.logger.debug("[*] {}:{}:{}".format(ip, ports if len(ports) < 20 else str(ports[:20]) + "...", self.open_ip_port_list[ip]))
            else:
                self.logger.error("[-] {}:{}:没有扫描到端口".format(ip, ports if len(ports) < 20 else str(ports[:20]) + "..."))

        return self.open_ip_port_list
