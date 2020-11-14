#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2020-06-11 16:38:55
@LastEditTime : 2020-08-07 12:04:35
'''
import asyncio

class AsyncTcpScan(object):
    """端口扫描"""

    def __init__(self, config):
        super(AsyncTcpScan, self).__init__()
        self.open_list = dict()
        self.logger = config.logger
        self.timeout = config.timeout
        self.ip_list = config.ip_list
        self.ports = config.ports
        self.rate = config.rate
        self.os_type = config.os_type
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
        
    async def async_port_check(self, semaphore, ip_port):
        '''端口探测'''
        async with semaphore:
            ip, port = ip_port
            try:
                conn = asyncio.open_connection(ip, port)
                _, _ = await asyncio.wait_for(conn, timeout=self.timeout)
                return (ip, port, 'open')
            except KeyboardInterrupt:
                time.sleep(1)
                self.logger.error("User aborted.")
                exit(0)
            except Exception as e:
                return (ip, port, 'close')
            finally:
                conn.close()

    def callback(self, future):
        '''回调处理结果'''
        ip, port, status = future.result()
        if status == "open":
            self.logger.debug("{:<17}{:<7}{}".format(ip, port, status))
            try:
                if ip in self.open_list:
                    self.open_list[ip].append(port)
                else:
                    self.open_list[ip] = [port]
            except Exception as e:
                pass
                #self.logger.error(e)
        else:
            # self.logger.debug("{}:{} {}".format(ip,port,status))
            pass

    def run(self):
        '''async tcp port scan'''
        self.logger.info("[*] Start async tcp port scan...")
        #初始化端口格式
        self.init_port()
        #设置扫描线程
        if self.os_type == 'Windows':
            if  self.rate >500:
                self.rate = 500
        sem = asyncio.Semaphore(self.rate)  # 限制并发量
        
        #处理IP,端口列表
        ip_port_list = list()
        for ip in self.ip_list:
            for port in self.ports:
                ip_port_list.append((ip, int(port)))
        self.logger.debug(ip_port_list)
        
        tasks = list()
        for ip_port in ip_port_list:
            task = asyncio.ensure_future(self.async_port_check(sem, ip_port))
            task.add_done_callback(self.callback)
            tasks.append(task)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(asyncio.wait(tasks))


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
                if  (count_ports_all >20) and (count_ports_open > count_ports_all*0.9) :
                    formatStr = 'IP {} ,本次扫描端口共 {} 个,开放端口 {} 个, 开放率超过90%,可能有安全设备拦截, 置空tcp_asyc_s模块端口扫描结果'.format( ip, count_ports_all , count_ports_open ) 
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