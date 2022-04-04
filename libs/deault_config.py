#!/usr/bin/env python
# -*- coding: utf-8 -*-
from libs.data import config
from libs.util import file_is_exist


def make_default_config(config_file_path):
    # 创建一个默认的配置文件
    if file_is_exist(config_file_path):
        return
    else:
        config_str = r"""
#第三方程序命名规则 [program]
#参数命名规则,使用最短命名 如[windows,linux,min_hostgroup,min_parallelism]
#程序及其参数调用方法,使用config.program_param 如[config.nmap_windows]
#所选的所有端口扫描及服务探测工具,建议至少支持单IP格式-多端口格式扫描 nmap支持|portscan支持(扫描有遗漏)|masscan支持(扫描有遗漏)

[nmap]
Windows = $BASE_DIR$\thirdparty\nmap\nmap.exe
Linux = $BASE_DIR$\thirdparty\nmap\nmap
Darwin = nmap
check_live_options = -v -sn -PE -n --min-hostgroup 50 --min-parallelism 100
port_scan_options = -sS -v -n -T4
service_probe_options = -sV -T4 -Pn
thread_pool_number = 1
#外部扫描模块  #使用线程池+内置线程控制实现

[portscan]
windows = $BASE_DIR$\thirdparty\portscan\portscan.exe
linux = $BASE_DIR$\thirdparty\portscan\portscan
Darwin = portscan
port_scan_options = -t 10000
thread_pool_number = 1
#外部扫描模块  #使用线程池+内置线程控制实现

[masscan]
windows = $BASE_DIR$\thirdparty\masscan\masscan.exe
linux = $BASE_DIR$\thirdparty\masscan\masscan
Darwin = masscan
port_scan_options = --rate=10000 --wait=3
thread_pool_number = 1
#外部扫描模块  #使用线程池+内置线程控制实现

[blackwater]
windows = $BASE_DIR$\thirdparty\blackwater\blackwater.exe
linux = $BASE_DIR$\thirdparty\blackwater\blackwater
Darwin = blackwater
thread_pool_number = 1
port_scan_options = --concurrency=10000 --timeout=1000
#外部扫描模块  #使用线程池+内置线程控制实现

[asyctcp]
rate = 500
timeout = 0.5
#内置python扫描模块  #使用异步函数实现

[http]
thread_pool_number = 100
timeout = 1
#内置python扫描模块 #使用线程池实现

[telnet]
thread_pool_number = 100
timeout = 0.5
#内置python扫描模块 #使用线程池实现

[tcpscan]
thread_pool_number = 100
timeout = 0.5
#内置python扫描模块 #使用线程池实现

[base]
all_check_alive_module = c1:nmap
all_port_scan_module= p1:masscan,p2:blackwater,p3:portscan,p4:asyctcp,p5:telnet,p6:http,p7:nmap
all_service_probe_module= s1:tcpscan,s2:nmap
#all_alive_check_module #所有存活检测模块及对应缩写
#all_port_scan_module #所有端口扫描模块及对应缩写
#all_service_probe_module #所有服务扫描模块及对应缩写

[ports]
common_100 = 8080,80,81,8081,7001,8000,8088,8888,9090,8090,88,8001,82,9080,8082,8089,9000,8443,9999,8002,89,8083,8200,8008,90,8086,801,8011,8085,9001,9200,8100,8012,85,8084,8070,7002,8091,8003,99,7777,8010,443,8028,8087,83,7003,10000,808,38888,8181,800,18080,8099,8899,86,8360,8300,8800,8180,3505,7000,9002,8053,1000,7080,8989,28017,9060,888,3000,8006,41516,880,8484,6677,8016,84,7200,9085,5555,8280,7005,1980,8161,9091,7890,8060,6080,8880,8020,7070,889,8881,9081,8009,7007,8004,38501,1010
common_200 = 21,22,23,25,53,69,80,81,82,83,84,85,86,87,88,89,110,111,123,135,137,138,139,143,161,389,443,445,465,500,512,513,523,548,623,624,873,993,995,1080,1099,1158,1241,1433,1434,1521,1533,1863,2049,2100,2181,2375,2376,2483,2484,3128,3306,3307,3308,3389,3690,4333,4786,4848,5000,5432,5800,5900,5901,5984,5985,5986,6000,6001,6379,7001,8000,8001,8002,8003,8004,8005,8006,8007,8008,8009,8010,8011,8012,8013,8014,8015,8016,8017,8018,8019,8020,8021,8022,8023,8024,8025,8026,8027,8028,8029,8030,8031,8032,8033,8034,8035,8036,8037,8038,8039,8040,8041,8042,8043,8044,8045,8046,8047,8048,8049,8050,8051,8052,8053,8054,8055,8056,8057,8058,8059,8060,8061,8062,8063,8064,8065,8066,8067,8068,8069,8070,8071,8072,8073,8074,8075,8076,8077,8078,8079,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8161,8168,8181,8443,8888,9000,9080,9090,9200,9300,9418,9999,10000,10250,11211,16992,16993,27017,27018,27019,32764,50050,50060,61616
common_300 = 21,22,23,25,53,69,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,110,111,123,135,137,138,139,143,161,389,443,445,465,500,512,513,515,523,548,623,624,636,800,801,802,803,804,805,806,807,808,873,880,888,889,902,993,995,1000,1010,1080,1099,1158,1241,1433,1434,1521,1533,1863,1883,1979,1980,2049,2100,2181,2375,2376,2379,2483,2484,3000,3012,3128,3306,3307,3308,3389,3505,3690,4333,4730,4786,4848,5000,5050,5222,5432,5555,5601,5672,5800,5900,5901,5938,5984,5985,5986,6000,6001,6080,6379,6666,6677,7000,7001,7002,7003,7004,7005,7006,7007,7008,7009,7070,7077,7080,7180,7200,7777,7890,8000,8001,8002,8003,8004,8005,8006,8007,8008,8009,8010,8011,8012,8013,8014,8015,8016,8017,8018,8019,8020,8021,8022,8023,8024,8025,8026,8027,8028,8029,8030,8031,8032,8033,8034,8035,8036,8037,8038,8039,8040,8041,8042,8043,8044,8045,8046,8047,8048,8049,8050,8051,8052,8053,8054,8055,8056,8057,8058,8059,8060,8061,8062,8063,8064,8065,8066,8067,8068,8069,8070,8071,8072,8073,8074,8075,8076,8077,8078,8079,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8099,8100,8101,8161,8168,8180,8181,8200,8280,8300,8360,8393,8443,8484,8545,8686,8762,8800,8811,8880,8881,8888,8889,8899,8983,8989,9000,9001,9002,9003,9042,9060,9070,9080,9081,9082,9083,9084,9085,9086,9087,9088,9089,9090,9091,9092,9093,9094,9095,9099,9100,9200,9300,9400,9418,9500,9900,9990,9991,9992,9993,9994,9995,9996,9997,9998,9999,10000,10051,10250,11211,12580,16992,16993,17110,18080,18081,18191,18443,18983,27017,27018,27019,28017,28080,28443,29095,32764,38501,38888,41516,50000,50001,50002,50050,50060,50070,50080,61616
common_udp = U:53,U:161,37777,U:137,U:523,U:123,U:520,U:5683,U:1701,U:1645,U:1604,U:5060,U:5353,U:5351,U:2425,U:1900
"""
        with open(config_file_path, "w+", encoding='utf-8') as fp:
            fp.write(config_str)
