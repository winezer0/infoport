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
        self.batch = config.batch
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
            #计算所有扫描端口数量
            count_ports_all=0
            if isinstance(self.ports,list):
                count_ports_all = len(self.ports)
            else:
                if ( '-' in self.ports and  ',' in self.ports):
                    portstrlist = self.ports.split(",")
                    portlist=[]
                    for postStr in portstrlist:
                        if '-' in postStr:
                            port_start= int(postStr.split("-")[0].strip())
                            port_end = int(postStr.split("-")[1].strip())
                            portlist.extend( [str(port) for port in range(port_start,port_end+1)])
                        else:
                            portlist.append(postStr)
                    self.ports=list(set(portlist))
                elif '-' in self.ports:
                    port_start= int(self.ports.split("-")[0].strip())
                    port_end = int(self.ports.split("-")[1].strip())
                    portlist = [str(port) for port in range(port_start,port_end+1)]
                    self.ports=list(set(portlist))
                else :
                    portlist = sorted(self.ports.split(","))
                    self.ports=list(set(portlist))
                count_ports_all = len(self.ports)
            for ip in self.open_list.keys():
                #开放端口去重
                self.open_list[ip]=list(set(self.open_list[ip]))
                #通过比较IP对应的开放端口数量>=所有扫描self.ports数量来判断是否有拦截设备
                #计算所有开放端口
                count_ports_open = len(self.open_list[ip])
                self.logger.debug('IP {} 本次扫描的所有端口 {} 个'.format( ip,count_ports_all ))
                self.logger.debug('IP {} 本次扫描的所有开放端口 {} 个'.format(ip, count_ports_open ))
                if  (count_ports_all >20) and (count_ports_open > count_ports_all*0.5) :
                    formatStr = 'IP {} ,本次扫描端口共 {} 个,开放端口 {} 个, 开放率超过50%,可能有安全设备拦截, 置空模块端口扫描结果'.format( ip, count_ports_all , count_ports_open ) 
                    self.logger.info(formatStr)
                    if self.batch :
                        self.open_list[ip]=[]
                    else:
                        inputstr = input('即将置空扫描结果[确认Y|取消N]: ')
                        if inputstr.lower() == 'n':
                            pass
                        else:
                            self.open_list[ip]=[]
            self.logger.info(self.open_list)
        return self.open_list