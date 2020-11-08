#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2020-06-11 16:42:43
@LastEditTime : 2020-08-07 15:16:29
'''
from libs import nmap
from concurrent.futures import ThreadPoolExecutor

class NmapScan(object):
    """端口扫描"""

    def __init__(self, config):
        super(NmapScan, self).__init__()
        self.open_list = dict()
        self.thread_num = config.thread_num
        self.logger = config.logger
        self.ip_list = config.ip_list
        self.ports = config.ports
        self.flag = True
        self.init_thread()

    def init_thread(self):
        '''设定线程数量'''
        if len(self.ip_list) < self.thread_num:
            self.thread_num = len(self.ip_list)

    def nmap_scan(self, ip, ports):
        '''nmap 端口探测'''
        if self.flag:
            try:
                nm_scan = nmap.PortScanner()
                args = "-sS -v -Pn -n -T4 -p {}".format(ports)

                #self.logger.info("sudo nmap -oX {} {}".format(args, ip))
                nm_scan.scan(ip, arguments=args)
                self.logger.debug(nm_scan.command_line())

                port_result = nm_scan[ip]['tcp']
                for port in port_result.keys():
                    state = port_result[port]['state']
                    if state == "open":
                        if ip in self.open_list:
                            self.open_list[ip].append(port)
                        else:
                            self.open_list[ip] = [port]
                        self.logger.debug("{:<17}{:<7}{}".format(ip, port, state))
            except Exception as e:
                raise e
                pass

    def run(self):
        '''Nmap port scan'''
        self.logger.info("[*] Start nmap port scan...")

        #简单处理端口格式
        if isinstance(self.ports,list):
            self.ports = ','.join(self.ports)
        if isinstance(self.ports,str):
            self.ports=self.ports.replace(' ','')

        try:
            with ThreadPoolExecutor(max_workers=self.thread_num) as executor:
                for ip in self.ip_list:
                    executor.submit(self.nmap_scan, ip, self.ports)
        except KeyboardInterrupt:
            self.logger.error("User aborted.")
            self.flag = False
            exit(0)
        
        #端口列表去重,过滤
        if len(self.open_list)>0:
            for ip in self.open_list.keys():
                self.open_list[ip]=list(set(self.open_list[ip]))
                if  len(list(self.open_list[ip]))>200:
                    self.logger.error("{} 常用端口开放 {} 个, 可能有拦截设备, 置空nmap_s模块端口扫描结果.".format(ip, len(self.open_list[ip])))
                    self.open_list[ip]=[]
            self.logger.info(self.open_list)
        return self.open_list
