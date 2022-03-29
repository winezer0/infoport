#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from libs import nmap
import tempfile
from libs.util import get_portable_path
import sys


def check_alive_by_nmap(config):
    current_function_name = sys._getframe().f_code.co_name
    # print('当前函数名为:', current_function_name) # check_live_by_nmap
    config[current_function_name] = []
    config.logger.info("[+] 开始通过{}模块进行存活IP检测!!!".format(current_function_name))
    config[current_function_name] = NmapCheckLiveHost(config).run()
    # 函数结果会返回到以当前函数名命名的config[]字典中。
    return config[current_function_name]


class NmapCheckLiveHost(object):
    # 获取存活主机列表
    def __init__(self, config):
        # 基本设置
        super(NmapCheckLiveHost, self).__init__()
        self.alive_host = list()
        self.logger = config.logger
        self.ip_list = config.ip_host

        # 程序设置
        self.program_name = "nmap"
        self.program_path = get_portable_path(config, self.program_name).replace("$BASE_DIR$", str(config.BASE_DIR))
        # print("[*]PATH {}: {}".format(self.program_name, self.program_path))
        self.check_live_options = config[self.program_name + '_' + 'check_live_options']

    def nmap_scan_alive(self):
        target_file_fp = tempfile.NamedTemporaryFile(prefix='nmap_alive_target_', suffix='.txt', delete=False)
        target_file_fp.write("\n".join(self.ip_list).encode("utf-8"))
        target_file_fp.close()
        # Windows下路径格式化,直接传入nmap会出现bug
        target_file_fp.name = target_file_fp.name.replace('\\', '\\\\')
        # print(target_file_fp.name)

        # nmap存活检测-基于icmp
        # nmap -sP -PI 192.168.1.1/24 -T4 # -PI 进行ping扫描
        # nmap ‐sn ‐PE ‐T4 192.168.1.0/24 # -PE与P0功能一样 无ping扫描
        # -iL 从已有的ip列表文件中读取并扫描
        # -sn 不进行端口扫描
        # -n  不做DNS解析
        # -R 总是做DNS反向解析
        # --min-hostgroup/max-hostgroup <size>：指定最小、最大的并行主机扫描组大小
        # --min-parallelism/max-parallelism <numprobes>：指定最小、最大并行探测数量
        # -oN/-oX/-oS/-oG <file>：分别输出正常、XML、s|
        # Warning: The -sP option is deprecated. Please use -sn

        # 不同版本的输出XML结果可能不同,目前nmap.py已修改适配 Nmap version 7.91 windows
        try:
            nmap_scan = nmap.PortScanner(nmap_search_path=(
                self.program_path, 'nmap', '/usr/bin/nmap', '/usr/local/bin/nmap', '/sw/bin/nmap',
                '/opt/local/bin/nmap'))

            self.logger.debug(
                "[*] Prospects Command:\n {} -oX - {} -iL {}".format(self.program_path, self.check_live_options,
                                                                     target_file_fp.name))

            nmap_scan.scan(self.check_live_options, arguments="-iL {}".format(target_file_fp.name))

            self.logger.debug("[*] Actual Command:\n {}".format(nmap_scan.command_line()))

            self.logger.debug("[*] Program Output:\n{}".format(nmap_scan.get_nmap_last_output()))

            for host in nmap_scan.all_hosts():
                if nmap_scan[host]["status"]["state"] == "up":
                    self.alive_host.append(host)
        except KeyboardInterrupt:
            self.logger.error("[-] User aborted.")
            exit(0)
        except Exception as e:
            self.logger.error(str(e))
        finally:
            os.unlink(target_file_fp.name)
        self.logger.debug(
            "[*] Nmap存活检测结果:目标IP数量[{}], 存活IP数量[{}]".format(len(self.ip_list), len(self.alive_host)))

    def run(self):
        # 检测存活主机
        # self.logger.info("[+] Check Live Host By Nmap...")
        self.nmap_scan_alive()
        return self.alive_host
