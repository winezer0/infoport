#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-08-24 17:55:54
@LastEditTime : 2020-08-07 20:05:09
'''

import time
from libs import nmap
from concurrent.futures import ThreadPoolExecutor


class NmapGetPortService(object):
    """获取端口运行的服务"""

    def __init__(self, config, ip_port_dict):
        super(NmapGetPortService, self).__init__()
        self.port_service_list = dict()
        self.ip_port_dict = ip_port_dict
        self.thread_num = config.thread_num
        self.logger = config.logger
        self.init_thread()
        self.flag = True

    def init_thread(self):
        '''设定线程数量'''
        if len(self.ip_port_dict) < self.thread_num:
            self.thread_num = len(self.ip_port_dict)

    def nmap_get_service(self, ip_port):
        '''nmap 获取端口的 service'''
        if self.flag:
            ip, port = ip_port
            #取消本处过滤地点,置于端口扫描结果处理处
            #if  len(port.split(","))>1000:
            #    self.logger.error("{} 常用端口开放 {} 个, 可能有拦截设备, 跳过端口服务识别.".format(ip, len(port.split(","))))
            #    return
            try:
                nm_scan = nmap.PortScanner()
                args = '-p {} -sV '.format(port)
                #args = '-p '+str(port)+' -Pn -sT -sV -n --version-all'
                nm_scan.scan(ip, arguments=args)
                self.logger.debug(nm_scan.command_line())

                self.port_service_list[ip] = list()
                port_result = nm_scan[ip]['tcp']
                
                for port in port_result.keys():
                    state = port_result[port]['state']
                    name = port_result[port]['name']
                    product = port_result[port]['product']
                    version = port_result[port]['version']
                    #result = "{:<17}{:<7}{:<10}{:<16}{:<16}{}".format(ip, port, state, name, product, version)
                    #self.logger.debug(result)
                    service_result = dict()
                    service_result['type'] = 'nmap'
                    service_result['port'] = port
                    service_result['proto'] = name
                    service_result['state'] = state
                    service_result['product'] = product
                    service_result['version'] = version
                    service_result['response'] =  'NULL'
                    self.port_service_list[ip].append(service_result)
            except Exception as e:
                self.logger.error('nmap {} {}'.format( args, e))
                pass

    def run(self):
        self.logger.info("[*] Get the service of the port by nmap -sV...")
        
        #去除端口为空的IP的字典
        if len(self.ip_port_dict)>0:
            for ip in self.ip_port_dict.copy().keys():
                self.ip_port_dict[ip]=list(set(self.ip_port_dict[ip]))
                if self.ip_port_dict[ip] == [] :
                    self.ip_port_dict.pop(ip)
            #self.logger.debug(self.ip_port_dict)
            
        try:
            with ThreadPoolExecutor(max_workers=self.thread_num) as executor:
                self.logger.debug(self.ip_port_dict)
                for ip in self.ip_port_dict.keys():
                    ports = self.ip_port_dict[ip]
                    if  len(ports)>200:
                        self.logger.error("{} 常用端口开放 {} 个, 可能有拦截设备, 跳过端口服务识别.".format(ip, len(ports.split(","))))
                        continue
                    ports = map(str, self.ip_port_dict[ip])
                    ports = ",".join(ports)
                    if ports != '':
                        executor.submit(self.nmap_get_service, (ip, ports))
        except KeyboardInterrupt:
            self.logger.error("User aborted.")
            self.flag = False
            exit(0)
        except Exception as e:
            self.logger.error(e)
            
        #去除端口为空的IP的字典
        if len(self.ip_port_dict)>0:
            for ip in self.ip_port_dict.copy().keys():
                self.ip_port_dict[ip]=list(set(self.ip_port_dict[ip]))
                if self.ip_port_dict[ip] == [] :
                    self.ip_port_dict.pop(ip)
            #self.logger.debug(self.ip_port_dict)

        self.logger.debug(self.port_service_list)
        return self.port_service_list
