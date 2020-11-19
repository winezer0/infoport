#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-09-19 09:52:13
@LastEditTime : 2020-08-10 10:45:41
'''

import argparse
import re
import socket
from libs.IPy import IP

from libs.util import file_is_exist
from libs.data import config
#import pathlib
#root_abspath = pathlib.Path(__file__).parent.resolve()  #绝对路径
import os
root_abspath = os.path.split(os.path.realpath(__file__))[0] #绝对路径

class ParserCmd(object):
    """ParserCmd"""

    def __init__(self):
        super(ParserCmd, self).__init__()
        self.parser = self.my_parser()
        self.args = self.parser.parse_args().__dict__

    def my_parser(self):
        '''使用说明'''
        example = """Examples:
                          \r  python3 {shell_name} -i 192.168.1.1/24 -p 1-66535 -ck 3 -st t1 -sv t1
                          \r  python3 {shell_name} -i 192.168.1.1-255  -p t1 -st masscan,goscan,http.nmap,tcpasyc -sv tcp,nmap
                          \r  python3 {shell_name} -i 192.168.1.1-192.168.1.255   -p 80,443,8080,8443 -st t1,t2,t3,t4,t5 -sv t1,t2
                          \r  python3 {shell_name} -i 192.168.1.1-255  -st masscan,goscan,http.nmap,tcpasyc -sv tcp,nmap
                          \r  python3 {shell_name} -iL target.txt  -p all -st masscan -r 3000 -ck  -st t1 -sv t1
                          \r  输入参数简写规则请查看{shell_name}
                          """

        parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,  # 使 example 可以换行
            add_help=True,
            # description = "端口扫描",
        )
        parser.epilog = example.format(shell_name=parser.prog)
        parser.add_argument("-i", dest="target", type=str,
                            help="指定IP目标 : 1.1.1.1 or 1.1.1.1/24 or 1.1.1.1-255  or 1.1.1.1-1.1.1.254, 支持多种格式同时输入")
        parser.add_argument("-iL", dest="target_filename", type=str,
                            help="指定IP文件, 对多个大目标的支持可能不完善,扫描大目标时建议使用masscan,goscan等外部程序")
        parser.add_argument("-c", dest="config_file", type=str, default="{}/../config.cfg".format(root_abspath),
                            help="指定配置文件, example: /usr/local/etc/rpscan.cfg,文件不存在时会自动创建默认配置文件, 程序打包后运行时建议手动指定配置文件")
        parser.add_argument("-p", dest="ports", type=str,
                            help="指定扫描端口, 支持端口分隔符[ , - ] , 支持多种格式同时输入 , 支持简写[ c1(web-100), c2(常用-200), c3(常用-300), all(所有端口)]")
        parser.add_argument("-st", dest="scantype", type=str, default="masscan",
                            help="指定端口扫描方法 [ masscan(默认):t1(简写), goscan:t2 , tcpasyc:t3, telnet:t4, nmap:t5 , http:t6, all(所有方式), c1(t1,t2),c2(t1,t2,t3),c3(t1,t2,t3,t4) ] ,支持同时指定多个扫描方式 ) ")
        parser.add_argument("-sv", dest="get_service", type=str,
                            help="指定服务检测方法, 支持探测方法[tcp:t1, nmap:t2, all(所有方式)], 支持同时指定多个探测方式" )
        parser.add_argument("-ck", dest="is_check_live", default=False, action="store_true",
                            help="使用nmap探测主机是否存活, 默认False")
        parser.add_argument("-t", dest="thread_num", type=int, default=10,
                            help="端口扫描线程, 默认10, 部分模块暂不支持线程设置,目前支持:port_nmap,service_nmap")
        parser.add_argument("-r", dest="rate", type=int, default=1000,
                            help="端口扫描速率, 默认1000, 部分模块暂不支持速率设置, 目前支持:port_tcpasyc,port_masscan")
        parser.add_argument("-v", dest="view", default=False, action="store_true",
                            help="显示调试信息,默认关闭")
        parser.add_argument("-b", dest="batch", default=False, action="store_true",
                            help="使用自动选项处理交互选项, 默认关闭, 目前交互选项: 端口扫描结果置空")
        # args = parser.parse_args()
        # parser.self.logger.debug_help()

        return parser

    @staticmethod
    def init():
        parser = ParserCmd()
        return parser.args


class ParseTarget(object):
    """ParseTarget"""

    def __init__(self):
        super(ParseTarget, self).__init__()
        self.ip_list = list()

    def parse_target(self, targets):
        # ["10.17.1.1/24", "10.17.2.30-55", "10.111.22.12"]
        
        if isinstance(targets, list):
            for target in targets:
                ips = self.parse_ip(target)
                self.ip_list.extend(ips)
        elif isinstance(targets, str):
            if ',' in targets:
                targets = targets.split(',')
                for target in targets:
                    ips = self.parse_ip(target)
                    self.ip_list.extend(ips)
            else:
                ips = self.parse_ip(targets)
                self.ip_list.extend(ips)

        # ip 排序去重
        ips = [ip for ip in sorted(set(self.ip_list), key=socket.inet_aton)]
        return ips

    def parse_ip(self, target):
        # 1.1.1.1-1.1.1.10
        # 10.17.1.1/24
        # 10.17.2.30-55
        # 10.111.22.12

        ip_list = list()
        # 校验target格式是否正确
        m = re.match(
            r'\d{1,3}(\.\d{1,3}){3}-\d{1,3}(\.\d{1,3}){3}$', target)
        m1 = re.match(
            r'\d{1,3}(\.\d{1,3}){3}/(1[6789]|2[012346789]|3[012])$', target)
        m2 = re.match(r'\d{1,3}(\.\d{1,3}){3}-\d{1,3}$', target)
        m3 = re.match(r'\d{1,3}(\.\d{1,3}){3}$', target)
        if ',' in target:
            ip_list = target.split(',')
        elif m:
            prev  = target.rsplit('.', 4)[0]
            start = target.rsplit('-', 1)[0].rsplit('.',1)[1]
            end   = target.rsplit('-', 1)[1].rsplit('.',1)[1]
            if int(end) < int(start):
                print('IP范围前端大于后端,请重新输入!!!')
                exit()
            for x in range(int(start), int(end)+1):
                ip_list.append(prev+"."+str(x))
        elif m1:
            tmp_ip_list = list()
            for x in IP(target, make_net=True):
                tmp_ip_list.append(str(x))
            ip_list = tmp_ip_list[1:]
        elif m2:
            prev = target.rsplit('.', 1)[0]
            st, sp = target.split('.')[-1].split('-')
            if int(sp) < int(st):
                print('IP范围前端大于后端,请重新输入!!!')
                exit()
            for x in range(int(st), int(sp)+1):
                ip_list.append(prev+"."+str(x))
        elif m3:
            ip_list.append(target)
        else:
            error_msg = "IP {} invalid format".format(target)
            raise Exception(error_msg)

        # 校验 ip 是否正确
        func = lambda x:all([int(y)<256 for y in x.split('.')])
        for ip in ip_list:
            if not func(ip):
                error_msg = "IP {} invalid format".format(target)
                raise Exception(error_msg)

        return ip_list

if __name__ == '__main__':
    pt = ParseTarget()
    self.logger.debug(pt.parse_target("123.123.123.123/29"))
    # self.logger.debug(pt.parse_target(["123.123.123.123/30","1.1.1.1-4"]))
