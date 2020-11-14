#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2020-06-12 13:52:55
@LastEditTime : 2020-08-11 11:23:56
'''
import sys
import time
import json
import pathlib
import platform
from loguru import logger
from configparser import ConfigParser

from libs.util import get_content
from libs.util import file_is_exist
from libs.util import cmd_is_exist
from libs.data import config
from libs.parse import ParserCmd
from libs.parse import ParseTarget

def set_logger( ):
    # 初始化日志
    logger.remove()
    logger_format1 = "[<green>{time:HH:mm:ss}</green>] <level>{message}</level>"
    logger_format2 = "<green>{time:YYYY-MM-DD HH:mm:ss,SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
    logger_format3 = "<level>{message}</level>"
    #logger.add(sys.stdout, format=logger_format1, level="DEBUG") #显示DEBUG到桌面
    #logger.add(sys.stdout, format=logger_format1, level="INFO")#显示INFO到桌面
    logger.add(config.log_file_path, format=logger_format3, level="INFO", rotation="10 MB", enqueue=True, encoding="utf-8", errors="ignore")
    # logger.add(config.log_file_path, format=logger_format2, level="INFO", rotation="00:00", enqueue=True, encoding="utf-8", errors="ignore")
    logger.add(config.err_log_file_path, rotation="10 MB", level="ERROR", enqueue=True, encoding="utf-8", errors="ignore")
    logger.add(config.dbg_log_file_path, rotation="10 MB", level="DEBUG", enqueue=True, encoding="utf-8", errors="ignore")
    
    config.pop("log_file_path")
    config.pop("err_log_file_path")
    config.pop("dbg_log_file_path")
    config.logger = logger
    
def reset_logger(view='False'):
    # 初始化日志
    logger_format = "[<green>{time:HH:mm:ss}</green>] <level>{message}</level>"
    if view:
        logger.add(sys.stdout, format=logger_format, level="DEBUG")
    else:
        logger.add(sys.stdout, format=logger_format, level="INFO")
    
def get_masscan_file():
    os_type = platform.system()
    config.os_type = os_type
    masscan_path = config.root_abspath.joinpath("masscan")
    if os_type == 'Linux' or os_type == 'Darwin':
        if cmd_is_exist("masscan"):
            masscan_file = cmd_is_exist("masscan")
        else:
            masscan_file = str(masscan_path.joinpath("masscan"))
    if os_type == 'Windows':
        if cmd_is_exist("masscan.exe"):
            masscan_file = cmd_is_exist("masscan.exe")
        else:
            masscan_file = str(masscan_path.joinpath("masscan.exe"))
    return masscan_file

#新增golang端口扫描工具
def get_scanport_file():
    os_type = platform.system()
    config.os_type = os_type
    scanport_path = config.root_abspath.joinpath("scanport")
    if os_type == 'Linux' or os_type == 'Darwin':
        if cmd_is_exist("scanport"):
            scanport_file = cmd_is_exist("scanport")
        else:
            scanport_file = str(scanport_path.joinpath("scanport"))
    if os_type == 'Windows':
        if cmd_is_exist("scanport.exe"):
            scanport_file = cmd_is_exist("scanport.exe")
        else:
            scanport_file = str(scanport_path.joinpath("scanport.exe"))
    return scanport_file

def set_path(root_abspath):
    config.root_abspath = root_abspath

    # 设置日志路径
    config.log_file_path = root_abspath.joinpath("log/result.log")
    config.dbg_log_file_path = root_abspath.joinpath("log/runtime.log")
    config.err_log_file_path = root_abspath.joinpath("log/error.log")

    # 获取 masscan 路径
    config.masscan_file = get_masscan_file()
    # 获取 goscan路径
    config.scanport_file = get_scanport_file()

def parames_is_right():
    """
    检测给的参数是否正常、检查目标文件或字典是否存在
    """
    host = config.get("target")
    host_file = config.get("target_filename")
    if not (host or host_file):
        config.logger.error("The arguments -i or -iL is required, please provide target !")
        exit(0)
    if host_file:
        if not file_is_exist(host_file):
            config.logger.error("No such file or directory \"{}\"".format(host_file))
            exit(0)
            
def init_options():
    # 初始化日志
    set_logger()
    # 解析命令行参数
    args = ParserCmd().init()
    config_file = args.get("config_file")
    
    
    # 自动创建一个配置文件
    if not file_is_exist(config_file):
        config.logger.error("No such file or directory \"{}\"".format(config_file))
        config_file_open = open(config_file,"w+")
        config_str=r"""
[base]
timeout = 10
[rate]
nmap_min_hostgroup = 50
nmap_min_parallelism = 100
[port]
common_web_100 = 8080,80,81,8081,7001,8000,8088,8888,9090,8090,88,8001,82,9080,8082,8089,9000,8443,9999,8002,89,8083,8200,8008,90,8086,801,8011,8085,9001,9200,8100,8012,85,8084,8070,7002,8091,8003,99,7777,8010,443,8028,8087,83,7003,10000,808,38888,8181,800,18080,8099,8899,86,8360,8300,8800,8180,3505,7000,9002,8053,1000,7080,8989,28017,9060,888,3000,8006,41516,880,8484,6677,8016,84,7200,9085,5555,8280,7005,1980,8161,9091,7890,8060,6080,8880,8020,7070,889,8881,9081,8009,7007,8004,38501,1010
common_port_200 = 21,22,23,25,53,69,80,81,82,83,84,85,86,87,88,89,110,111,123,135,137,138,139,143,161,389,443,445,465,500,512,513,523,548,623,624,873,993,995,1080,1099,1158,1241,1433,1434,1521,1533,1863,2049,2100,2181,2375,2376,2483,2484,3128,3306,3307,3308,3389,3690,4333,4786,4848,5000,5432,5800,5900,5901,5984,5985,5986,6000,6001,6379,7001,8000,8001,8002,8003,8004,8005,8006,8007,8008,8009,8010,8011,8012,8013,8014,8015,8016,8017,8018,8019,8020,8021,8022,8023,8024,8025,8026,8027,8028,8029,8030,8031,8032,8033,8034,8035,8036,8037,8038,8039,8040,8041,8042,8043,8044,8045,8046,8047,8048,8049,8050,8051,8052,8053,8054,8055,8056,8057,8058,8059,8060,8061,8062,8063,8064,8065,8066,8067,8068,8069,8070,8071,8072,8073,8074,8075,8076,8077,8078,8079,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8161,8168,8181,8443,8888,9000,9080,9090,9200,9300,9418,9999,10000,10250,11211,16992,16993,27017,27018,27019,32764,50050,50060,61616
common_port_300 = 21,22,23,25,53,69,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,110,111,123,135,137,138,139,143,161,389,443,445,465,500,512,513,515,523,548,623,624,636,800,801,802,803,804,805,806,807,808,873,880,888,889,902,993,995,1000,1010,1080,1099,1158,1241,1433,1434,1521,1533,1863,1883,1979,1980,2049,2100,2181,2375,2376,2379,2483,2484,3000,3012,3128,3306,3307,3308,3389,3505,3690,4333,4730,4786,4848,5000,5050,5222,5432,5555,5601,5672,5800,5900,5901,5938,5984,5985,5986,6000,6001,6080,6379,6666,6677,7000,7001,7002,7003,7004,7005,7006,7007,7008,7009,7070,7077,7080,7180,7200,7777,7890,8000,8001,8002,8003,8004,8005,8006,8007,8008,8009,8010,8011,8012,8013,8014,8015,8016,8017,8018,8019,8020,8021,8022,8023,8024,8025,8026,8027,8028,8029,8030,8031,8032,8033,8034,8035,8036,8037,8038,8039,8040,8041,8042,8043,8044,8045,8046,8047,8048,8049,8050,8051,8052,8053,8054,8055,8056,8057,8058,8059,8060,8061,8062,8063,8064,8065,8066,8067,8068,8069,8070,8071,8072,8073,8074,8075,8076,8077,8078,8079,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8099,8100,8101,8161,8168,8180,8181,8200,8280,8300,8360,8393,8443,8484,8545,8686,8762,8800,8811,8880,8881,8888,8889,8899,8989,9000,9001,9002,9003,9042,9060,9070,9080,9081,9082,9083,9084,9085,9086,9087,9088,9089,9090,9091,9092,9093,9094,9095,9099,9100,9200,9300,9400,9418,9500,9900,9990,9991,9992,9993,9994,9995,9996,9997,9998,9999,10000,10051,10250,11211,12580,16992,16993,17110,18080,18081,18191,18983,18443,27017,27018,27019,28017,28080,28443,29095,32764,38501,38888,41516,50000,50001,50002,50050,50060,50070,50080,61616"""
        config_file_open.write(config_str)
        config_file_open.close()

    # 解析配置文件参数
    if not file_is_exist(config_file):
        config.logger.error("No such file or directory \"{}\"".format(config_file))
        exit(0)
    else:
        cfg = ConfigParser()
        cfg.read(config_file)
        for section in cfg.sections():
            for k,v in cfg.items(section):
                config[k] = v.strip()
                #logger.debug(k,v )
        config.timeout = cfg.getint("base", "timeout")
        config.portStrInput  ='Null'
    config.update(args)
    parames_is_right()
    
    # 重新初始化日志,根据输入的view参数指定窗口输出的日志信息级别
    reset_logger(config.view)
    
    # 解析目标资产
    pt = ParseTarget()
    if config.target:
        config.ip_list = pt.parse_target(config.target)
    elif config.target_filename:
        target_list = get_content(config.target_filename)
        config.ip_list = pt.parse_target(target_list)
    #logger.debug('config.ip_list',config.ip_list)
    
    # 解析扫描的端口
    config.portStrInput = config.ports
    #logger.debug('config.ports',config.ports)
    if config.ports:
        if  'all' in config.ports:
            #扫描全端口
            logger.debug('Scan all_ports_65535')
            config.ports = "1-65535"
        elif 't1' in config.ports:
            logger.debug('Scan common_web_100')
            config.ports = sorted(config.pop("common_web_100").split(","))
        elif 't2' in config.ports:
            logger.debug('Scan common_port_200')
            config.ports = sorted(config.pop("common_port_200").split(","))
        elif 't3' in config.ports:
            logger.debug('Scan common_port_300')
            config.ports = sorted(config.pop("common_port_300").split(","))
        else:
            config.ports = config.ports.replace(' ','') #去除端口之间的空格字符
            logger.debug('Scan {}'.format(config.ports))
            #处理端口后端小于前端的问题
            if '-' in config.ports:
                port_start= int(config.ports.split("-")[0].strip())
                port_end = int(config.ports.split("-")[1].strip())
                if port_end < port_start:
                    print('端口范围格式输入错误,后部范围小于前部范围!!!')
                    exit()
        logger.debug('config.ports',config.ports)
    else:
        logger.debug('请输入端口号')






