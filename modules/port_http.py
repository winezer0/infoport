#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2020-08-07 15:05:57
@LastEditTime : 2020-08-10 11:05:42
'''
import sys
import  requests
requests.packages.urllib3.disable_warnings()
from concurrent.futures import ThreadPoolExecutor

class HttpScan(object):
    """
    如果扫描结果返回很多端口，那可能是因为有设备
    此时使用 http 直接访问常见 web 端口
    """

    def __init__(self, config):
        super(HttpScan, self).__init__()
        self.open_list = dict()
        self.logger = config.logger
        self.thread_num = config.thread_num
        self.timeout = config.timeout
        self.ip_list = config.ip_list
        self.ports = config.ports
        self.flag = True
        self.batch = config.batch

    def init_port(self):
        '''处理port输入'''
        self.logger.debug('self.ports',self.ports)
        
        #简单处理端口格式
        if isinstance(self.ports,list):
            self.ports = ','.join(self.ports)
        if isinstance(self.ports,str):
            self.ports=self.ports.replace(' ','')
        
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
        self.logger.debug('self.ports',self.ports)
                
    def init_thread(self):
        '''根据 IP-Port 设定线程数量, 最大200线程'''
        self.ip_port_list = list()
        for port in self.ports:
            for ip in self.ip_list:
                self.ip_port_list.append((ip, int(port)))
        if len(self.ip_port_list) < self.thread_num:
            self.thread_num = len(self.ip_port_list)
        else:
            #设定最高200线程
            self.thread_num = 200
            
    def web_detect(self, ip_port):
        '''端口探测'''
        if self.flag:
            ip, port = ip_port
            try:
                url = "http://{}:{}".format(ip, port)
                resp = requests.get(url=url, timeout=self.timeout, verify=False)
            except Exception as e_msg:
                error_msg = str(e_msg)
                if ' timeout' in error_msg:
                    pass
                    #self.logger.debug("{:<17}{:<7}{}".format(ip, port,'connect timeout'))
                elif  ' ConnectionResetError' in error_msg:
                    self.logger.debug("{:<17}{:<7}{}".format(ip, port, "Connect Reset"))
                else:
                    self.logger.debug('http://{}:{} {}'.format(ip, port,error_msg))
            else:
                self.logger.debug("{:<17}{:<7}{}".format(ip, port, "open"))

                if ip in self.open_list:
                    self.open_list[ip].append(port)
                else:
                    self.open_list[ip] = [port]

    def run(self):
        self.logger.info("[*] Start http port detect...")
        #初始化输入端口格式
        self.init_port()
        #初始化IP:Port格式与扫描线程
        self.init_thread()
        self.logger.debug(self.ip_port_list)
        try:
            with ThreadPoolExecutor(max_workers=self.thread_num) as executor:
                for ip_port in self.ip_port_list:
                    executor.submit(self.web_detect, ip_port)
        except KeyboardInterrupt:
            self.logger.error("User aborted.")
            self.flag = False
            exit(0)
        except Exception as e_msg:
            self.logger.error(e)

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