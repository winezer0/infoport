#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2020-06-11 16:42:43
@LastEditTime : 2020-08-07 15:16:29
'''

import os
import copy
import time
import tempfile
from subprocess import Popen, STDOUT, PIPE
from libs.util import file_get_contents
from concurrent.futures import ThreadPoolExecutor

class goScanPort(object):
    """端口扫描"""

    def __init__(self, config):
        super(goScanPort, self).__init__()
        self.open_list = dict()
        self.thread_num = config.thread_num
        self.os_type = config.os_type
        self.scanport_file = config.scanport_file
        
        self.logger = config.logger
        self.ip_list = config.ip_list
        self.ports = config.ports
        
        self.flag = True
        self.init_thread()
        self.batch = config.batch
        
        
    def init_thread(self):
        '''根据目标IP数量, 设定线程数量, 最大1个线程,多了win会崩'''
        if len(self.ip_list) < -1:
            self.thread_num = len(self.ip_list)
        else:
            self.thread_num = 1
            
    def scanPort_scan(self, ip, ports, scanport_file):
        '''scanPort 端口探测'''
        result_dir = tempfile.gettempdir()
        result_file='{}/{}_port.txt'.format(result_dir ,ip)
        if self.flag:
            try:
                command = "{}  -ip  {} -p {} -path {} ".format( scanport_file,ip, ports,result_dir )
                self.logger.debug('cmd:',command)
                p = Popen(command, shell=True, stderr=STDOUT) # stdout=PIPE, 
                #p = Popen(command, shell=True, stderr=STDOUT) # stdout=PIPE, 
                # self.logger.debug("状态：", p.poll())
                # self.logger.debug("开启进程的pid", p.pid)
                # self.logger.debug("所属进程组的pid", os.getpgid(p.pid))
                # time.sleep(90)
                scanport_output, scanport_err = p.communicate()
            except KeyboardInterrupt:
                time.sleep(1)
                self.logger.error("User aborted.")
                exit(0)
            except Exception as e:
                self.logger.debug(e)
            else:
                try:
                    #self.logger.debug(result_file)
                    file_open = open(result_file,encoding='utf-8')
                    datalist = file_open.readlines()
                    for data in datalist:
                        ports = data.strip().split(',')[-1].replace('[','').replace(']','').split(' ')
                        ip =  data.strip().split(',')[1]
                        for port in ports:
                            self.logger.debug("{:<17}{:<7}{}".format(ip, port, 'open'))
                            if ip in self.open_list:
                                #返回数字类型的端口
                                self.open_list[ip].append(int(port))
                            else:
                                #返回数字类型的端口
                                self.open_list[ip] = [int(port)]
                    file_open.close()
                except FileNotFoundError as e:
                    self.logger.error("没有扫描到端口")
                except Exception as e:
                    self.logger.error(e)
                finally:
                    if os.path.exists(result_file): 
                        os.unlink(result_file)

    def run(self):
        '''goScanPort port scan'''
        self.logger.info("[*] Start scanPort port scan...")
        self.logger.debug('ip_list',self.ip_list)
        self.logger.debug('ip_list',len(self.ip_list))
        #C段处理:ip列表转IP段 存在bug,按ip前三位数对应的后缀进行预测
        if len(self.ip_list)>0:    
            all_ip_list=[]
            ip_prefix_list = [ip.rsplit('.',1)[0]+'.' for ip in self.ip_list]
            ip_prefix_list=list(set(ip_prefix_list))
            #self.logger.debug('tmp_ip_prefix_list',tmp_ip_prefix_list)
            #从前缀列表生成一个'ip前缀':[]字典
            #fromkeys生成的数组的值id是相同的，不要用来指定数组
            #ip_prefix_dict = dict.fromkeys(ip_prefix_list , [])
            ip_prefix_dict = dict()
            for ip_prefix  in ip_prefix_list:
                ip_prefix_dict[ip_prefix]=[]
            #将所有输入IP通过前缀进行区分
            #生成一个'ip前缀':[ip后缀1,ip后缀1,...]字典
            for ip_prefix in ip_prefix_dict.keys():
                for ip in self.ip_list:
                    if ip_prefix in ip:
                        ip_suffix =  ip.rsplit('.',1)[1].strip()
                        ip_prefix_dict[ip_prefix].append(ip_suffix)
            self.logger.debug('ip_prefix_dict',ip_prefix_dict)
            #根据ip前缀字典生成IP格式
            tmp_ip_suffix_list = []
            for ip_prefix in ip_prefix_dict.keys():
                tmp_ip_suffix_list = ip_prefix_dict[ip_prefix]
                tmp_ip_suffix_list=list(set(tmp_ip_suffix_list)) #去重
                tmp_ip_suffix_list = [ int(port) for port in tmp_ip_suffix_list] #排序之前需要改成数字类型
                tmp_ip_suffix_list.sort() #排序
                tmp_ip_suffix_list = [ str(port) for port in tmp_ip_suffix_list] #排序之后需要改成字符串类型
                #获得最大IP数量
                tmp_ip_count = int(tmp_ip_suffix_list[-1]) - int(tmp_ip_suffix_list[0])+1
                #如果ip列表的长度==ip列表的数量,说明是连续格式，可以合并
                if (len(tmp_ip_suffix_list) >= tmp_ip_count) and (len(tmp_ip_suffix_list)!=1):
                    #self.logger.debug('输入的IP是连续的',tmp_ip_suffix_list)
                    ip_prefix_suffix_str  = ip_prefix +str(tmp_ip_suffix_list[0])+'-'+str(tmp_ip_suffix_list[-1])
                    all_ip_list.append(ip_prefix_suffix_str)
                #如果ip列表的长度==ip列表的数量,说明不是连续格式，不进行合并
                else:
                    #self.logger.debug('输入的IP不是连续的',tmp_ip_suffix_list)
                    ip_prefix_suffix_list  = [ip_prefix +str(ip_prefix_suffix) for ip_prefix_suffix in tmp_ip_suffix_list]
                    all_ip_list.extend(ip_prefix_suffix_list)
            self.logger.debug('all_ip_list',all_ip_list)
            self.ip_list = all_ip_list
        
        self.logger.debug('ip_list',self.ip_list)
        self.logger.debug('ip_list',len(self.ip_list))

        #简单处理端口格式
        if isinstance(self.ports,list):
            self.ports = ','.join(self.ports)
        if isinstance(self.ports,str):
            self.ports=self.ports.replace(' ','')

        try:
            with ThreadPoolExecutor(max_workers=self.thread_num) as executor:
                for ip in self.ip_list:
                    executor.submit(self.scanPort_scan, ip, self.ports,  self.scanport_file)
                    #time.sleep(len(self.ports)/100)
        except KeyboardInterrupt:
            self.logger.error("User aborted.")
            self.flag = False
            exit(0)
        except Exception as e:
            self.logger.error(str(e))
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