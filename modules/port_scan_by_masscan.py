#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import time
from libs import demjson
import tempfile
import subprocess
from libs.util import file_get_contents, get_portable_path, complex_ports_str_to_port_segment
from concurrent.futures import ThreadPoolExecutor


def port_scan_by_masscan(config):
    current_function_name = sys._getframe().f_code.co_name  # print('当前函数名为:', current_function_name) # check_live_by_nmap
    config[current_function_name] = []
    config.logger.info("[+] 开始通过{}模块进行IP端口检测!!!".format(current_function_name))
    config[current_function_name] = MasscanScan(config).run()
    # 函数结果会返回到以当前函数名命名的config[]字典中。
    return config[current_function_name]


class MasscanScan(object):
    """端口扫描"""

    def __init__(self, config):
        # 基本设置
        super(MasscanScan, self).__init__()
        self.open_ip_port_list = dict()  # 存放IP及其对应的开放端口列表

        self.logger = config.logger
        self.alive_ip_host = config.all_alive_ip_host
        self.ports = config.ports
        self.ignore_ports_flag = config.ignore_ports_flag
        self.run_stop_flag = True
        # 程序设置
        self.program_name = "masscan"
        self.program_path = get_portable_path(config, self.program_name).replace("$BASE_DIR$", str(config.BASE_DIR))
        # self.logger.debug("[*]PATH {}: {}".format(self.program_name, self.program_path))
        # 读取程序必须参数thread_pool_number
        self.thread_pool_number = int(config[self.program_name + '_' + 'thread_pool_number'])
        # 读取程序必须参数port_scan_options
        self.port_scan_options = config[self.program_name + '_' + 'port_scan_options']

        # 其他设置
        self.init_thread()

    def init_thread(self):
        # 设定线程池数量
        # print('优化线程数量...')
        if 0 < len(self.alive_ip_host) < self.thread_pool_number:
            self.thread_pool_number = len(self.alive_ip_host)

    def masscan_scan(self, ip, ports):
        # masscan 探测端口
        if self.run_stop_flag:
            result_file_fp = tempfile.NamedTemporaryFile(prefix='tmp_port_scan_result_', suffix='.txt', delete=False)
            try:
                command = "{} {} -p {} {} -oJ {}".format(self.program_path, ip, ports, self.port_scan_options,
                                                         result_file_fp.name)

                self.logger.debug('[*] Prospects Command:\n{}'.format(command))

                # p = Popen(command, shell=True, stderr=STDOUT)  # stdout=PIPE,
                # self.logger.debug("[*]状态：", p.poll())
                # self.logger.debug("[*]开启进程的pid", p.pid)
                # self.logger.debug("[*]所属进程组的pid", os.getpgid(p.pid))
                # time.sleep(90)

                # masscan_output, masscan_err = p.communicate()
                p = subprocess.Popen(command, bufsize=100000,
                                     stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
                # wait until finished
                # get output
                (program_last_output, program_err) = p.communicate()
                program_last_output = bytes.decode(program_last_output)
                program_err = bytes.decode(program_err)
                # print("program_last_output", program_last_output)  # 非实时的扫描结果中没有端口Ip等信息
                # print("program_err", program_err)  # 扫描结果
            except KeyboardInterrupt:
                time.sleep(1)
                self.logger.error("[-] User aborted.")
                sys.exit(0)
            except Exception as e:
                self.logger.debug(str(e))
            finally:
                result_file_fp.close()
                self.masscan_scan_result_analysis(ip, ports, result_file_fp.name)

                # 输出IP对应的端口扫描结果
                if len(self.open_ip_port_list[ip]) > 0:
                    self.logger.debug("[*] {}:{}:{}".format(ip, ports if len(ports) < 20 else str(ports[:20]) + "...",
                                                            self.open_ip_port_list[ip]))
                else:
                    self.logger.error(
                        "[-] {}:{}:没有扫描到端口".format(ip, ports if len(ports) < 20 else str(ports[:20]) + "..."))

    def masscan_scan_result_analysis(self, ip, ports, result_file):
        try:
            data = file_get_contents(result_file)
            data = demjson.decode(data)
            self.logger.debug("[*] Program Output:\n{}".format(str(data).replace("},", "},\n")))
            for result in data:
                # print(result) # 每一个result都有IP、端口、状态等信息
                ip = result.get("ip")
                port = result.get("ports")[0].get("port")
                status = result.get("ports")[0].get("status")
                if status == "open":
                    if ip in self.open_ip_port_list:
                        self.open_ip_port_list[ip].append(port)
                    else:
                        self.open_ip_port_list[ip] = [port]
            self.logger.debug("[*] {}:{}:{}".format(ip, ports if len(ports) < 20 else str(ports[:20]) + "...",
                                                    self.open_ip_port_list[ip]))
        except demjson.JSONDecodeError as e:
            if "No value to decode" in str(e):
                self.logger.error("[-] {}:{}:没有扫描到端口".format(ip, ports if len(ports) < 20 else str(ports[:20]) + "..."))
            else:
                self.logger.error("[-] JSONDecodeError: {}".format(e))
        except Exception as e:
            self.logger.error("[-] OtherError: {}".format(e))
        finally:
            # pass
            os.unlink(result_file.name)

    def run(self):
        try:
            with ThreadPoolExecutor(max_workers=self.thread_pool_number) as executor:
                for ip in self.alive_ip_host:
                    executor.submit(self.masscan_scan, ip, complex_ports_str_to_port_segment(self.ports))
        except KeyboardInterrupt:
            self.logger.error("[-] User aborted.")
            self.run_stop_flag = False
            sys.exit(0)
        except Exception as e:
            self.logger.error(str(e))
            self.run_stop_flag = False
            sys.exit(0)

        return self.open_ip_port_list
