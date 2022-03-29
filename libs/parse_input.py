#!/usr/bin/env python
# -*- coding: utf-8 -*-


import argparse


class ParserCmd(object):

    def __init__(self):
        super(ParserCmd, self).__init__()
        self.parser = self.my_parser()
        self.args = self.parser.parse_args().__dict__

    def my_parser(self):
        example = """Examples:
                          \r  python3 {shell_name} -i 192.168.1.1/24 -p 1-66535 -ck nmap -ps nmap -sv nmap
                          \r  python3 {shell_name} -i 192.168.1.1-255  -p c1 -ck None  -ps  masscan -sv tcpscan,nmap
                          \r  python3 {shell_name} -i 192.168.1.1-192.168.1.255 -p 80,443,8080,8443  -ck all -ps all -sv all
                          \r  
                          \r  其他细节参数及模块对于简写与全拼请查看config.ini
                          \r  
                          \r  T00L Version: 0.3 20220121
                          \r  
                          """

        parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,  # 使 example 支持换行
            add_help=True,
        )
        parser.epilog = example.format(shell_name=parser.prog)
        parser.add_argument("-i", dest="target", type=str, default=None,  # 发布时需要改为 default=None
                            help="指定IP目标 : 1.1.1.1 or 1.1.1.1/24 or 1.1.1.1-255  or 1.1.1.1-1.1.1.254, 支持多种格式同时输入")

        parser.add_argument("-f", dest="target_filename", type=str, default=None,
                            help="指定IP文件, 对多个A段大目标的可能支持不完善,扫描大目标时建议使用masscan等外部程序进行单独扫描")

        parser.add_argument("-c", dest="config_file", type=str, default="$BASE_DIR$/config.ini",
                            help="指定自定义配置文件, example: /usr/local/etc/infoport.ini, 文件不存在时会自动创建默认配置文件, 程序打包后运行时建议手动指定配置文件")

        parser.add_argument("-p", dest="ports", type=str, default="c2",
                            help="指定扫描端口范围, 支持端口分隔符[',','-'], 支持简写 c1:web-100,c2:common-200,c3:common-300,all(所有端口)")

        parser.add_argument("-ck", dest="check_alive", type=str, default="all",
                            help="指定主机检测方法, c1:nmap,all(所有方式),none(不检测),支持全拼(如nmap)或简写(c1)")

        parser.add_argument("-ps", dest="port_scan", type=str, default="p1,p2,p3,p4",
                            help="指定端口扫描方法, p1:masscan,p2:blackwater,p3:portscan,p4:asyctcp,p5:telnet,p6:http,p7:nmap,all(所有方式),支持全拼(如nmap)或简写(p1)")

        parser.add_argument("-sv", dest="service_scan", type=str, default="s1",
                            help="指定服务检测方法, s1:tcpscan,s2:nmap,all(所有方式),支持全拼(如nmap)或简写(s2)")

        parser.add_argument("-v", dest="view_detail_flag", default=False, action="store_true",  # 发布时需要改为 default=False True
                            help="显示程序运行时的所有调试信息,查看服务扫描的细节时需要,默认关闭")

        parser.add_argument("-b", dest="ignore_ports_flag", default=False, action="store_true",
                            help="设置当模块扫描到单主机超过100个端口时忽略该结果, 默认关闭")

        # args = parser.parse_args()
        # parser.self.logger.debug_help()

        return parser

    @staticmethod
    def init():
        parser = ParserCmd()
        return parser.args


if __name__ == '__main__':
    args = ParserCmd().init()
    print(args)
