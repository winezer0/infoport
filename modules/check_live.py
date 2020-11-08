#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-08-24 17:55:54
@LastEditTime : 2020-08-05 09:25:51
'''

import os
import time
from libs import nmap
import tempfile
import sys

class CheckHostLive(object):
    """获取存活主机列表"""

    def __init__(self, config):
        super(CheckHostLive, self).__init__()
        self.live_host = list()
        self.logger = config.logger
        self.ip_list = config.ip_list
        self.nmap_min_hostgroup = config.nmap_min_hostgroup
        self.nmap_min_parallelism = config.nmap_min_parallelism

    def nmap_scan(self, ip_list):
        self.logger.debug(ip_list)
        target_file_fp = tempfile.NamedTemporaryFile(
            prefix='tmp_port_scan_target_', suffix='.txt', delete=False)
        target_file_fp.write("\n".join(ip_list).encode("utf-8"))
        target_file_fp.close()
        #Windows下路径格式化,直接传入nmap会出现bug
        target_file_fp.name=target_file_fp.name.replace('\\','\\\\')
        self.logger.debug(target_file_fp.name)
        self.command = "-v -sn -PS -n --min-hostgroup {} --min-parallelism {} -iL {}".format(
            self.nmap_min_hostgroup, self.nmap_min_parallelism, target_file_fp.name)
        self.logger.debug(self.command )
        try:
            nm_scan = nmap.PortScanner()
            nm_scan.scan(self.command, arguments="")
            self.logger.debug(nm_scan.command_line())
            for host in nm_scan.all_hosts():
                if nm_scan[host]["status"]["state"] == "up":
                    self.live_host.append(host)
        except KeyboardInterrupt:
            self.logger.error("User aborted.")
            exit(0)
        except Exception as e:
            
            self.logger.error(str(e))
        finally:
            os.unlink(target_file_fp.name)
            pass
        self.logger.info("All host: {}, live host: {}".format(len(ip_list), len(self.live_host)))

    def run(self):
        '''检测存活主机'''
        self.logger.info("[*] Check Live Host...")
        self.nmap_scan(self.ip_list)

        return self.live_host
