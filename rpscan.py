#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-05-23 09:52:13
@LastEditTime : 2020-08-10 10:44:40
'''
import os
import sys
import time
sys.dont_write_bytecode = True  # 不生成pyc文件
#base_dir = os.path.split(os.path.realpath(__file__))[0]

import pathlib
from libs.data import config
from libs.initialize import set_path


def main():
    # 设置路径
    root_abspath = pathlib.Path(__file__).parent.resolve()  #绝对路径
    set_path(root_abspath)

    # 初始化，主要是导入配置文件、解析命令行参数
    from libs.initialize import init_options
    init_options()
    logger=config.logger
    from modules.check_live import CheckHostLive
    from modules.masscan_s import MasscanScan
    from modules.async_s import AsyncTcpScan
    from modules.nmap_s import NmapScan
    from modules.http_s import HttpScan
    from modules.goscanport import goScanPort
    from modules.get_service_nmap import NmapGetPortService
    from modules.get_service_tcp import TcpGetPortService
    
    # 检测存活 ip
    if config.is_check_live:
        chl = CheckHostLive(config)
        config.ip_list = chl.run()
    if len(config.ip_list) < 1:
        exit()
#############################
    # 端口扫描
    if config.scantype:
        logger.debug('config.scantype ',config.scantype)
        logger.debug('config.ports ',config.ports)
        open_port_dict_masscan=dict()
        open_port_dict_http=dict()
        open_port_dict_goscan=dict()
        open_port_dict_tcpasyc=dict()
        open_port_dict_nmap=dict()
        
        #增加all参数
        if 'all' in config.scantype:
            config.scantype = 't1,t2,t3,t4,t5'
            #print(config.scantype )
        for scantype in config.scantype.split(','):
            scantype = scantype.strip()
            logger.debug('now scantype',scantype)
            if  ("masscan" in scantype) or ("t1" in scantype) :
                m_scan = MasscanScan(config)
                open_port_dict_masscan = m_scan.run()
                #返回的端口号类型是数字
            elif ("goscan" in scantype) or ("t2" in scantype) :
                go_scan = goScanPort(config)
                open_port_dict_goscan = go_scan.run()
            elif ("tcpasyc" in scantype) or ("t3" in scantype) :
                a_scan = AsyncTcpScan(config)
                #返回的端口号类型是数字
                open_port_dict_tcpasyc = a_scan.run()
            elif ("http" in scantype) or ("t4" in scantype) :
                h_scan = HttpScan(config)
                #返回的端口号类型是数字
                open_port_dict_http = h_scan.run()
            elif ("nmap" in scantype) or ("t5" in scantype) :
                n_scan = NmapScan(config)
                #返回的端口号类型是数字
                open_port_dict_nmap = n_scan.run()
            else:
                logger.debug(' [!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!]')
                logger.debug(' [!! Scantype Input Error: {} !!!!!!!]'.format(scantype))
                logger.debug(' [!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!]')
                
    #所有扫描端口结果处理
        # {'1.1.1.1': [80, 25, 443, 110], '1.1.1.2': [80, 25, 443, 110], '1.1.1.3': [80, 25, 443, 110]}
        open_port_dict_all=dict()
        #获得所有输出结果字典的键
        open_port_dict_all_keys=[]
        open_port_dict_all_keys.extend(open_port_dict_masscan.keys())
        open_port_dict_all_keys.extend(open_port_dict_goscan.keys())
        open_port_dict_all_keys.extend(open_port_dict_tcpasyc.keys())
        open_port_dict_all_keys.extend(open_port_dict_nmap.keys())
        open_port_dict_all_keys.extend(open_port_dict_http.keys())
        open_port_dict_all_keys=list(set(open_port_dict_all_keys))
        logger.debug('此次扫描的所有开放IP',open_port_dict_all_keys)
        #fromkeys 方法只用来创建新字典，不负责保存
        open_port_dict_all = dict.fromkeys(open_port_dict_all_keys,[])
        #logger.debug(open_port_dict_all)
        for ip in open_port_dict_all.keys():
            #logger.debug( ip )
            if open_port_dict_masscan.__contains__(ip):
                open_port_dict_all[ip].extend(open_port_dict_masscan[ip])
            if open_port_dict_goscan.__contains__(ip):
                open_port_dict_all[ip].extend(open_port_dict_goscan[ip])
            if open_port_dict_tcpasyc.__contains__(ip):
                open_port_dict_all[ip].extend(open_port_dict_tcpasyc[ip])
            if open_port_dict_tcpasyc.__contains__(ip):
                open_port_dict_all[ip].extend(open_port_dict_tcpasyc[ip])
            if open_port_dict_http.__contains__(ip):
                open_port_dict_all[ip].extend(open_port_dict_http[ip])
            open_port_dict_all[ip]=list(set(open_port_dict_all[ip]))
            logger.debug('open_port_dict_all : {}'.format(open_port_dict_all ))
        #定义最终结果输出文件
        #result_file_port="log/result_port_{}.txt".format(time.time())
        result_file_port="{}/log/result_port.csv".format(root_abspath)
        logger.info('ports result file : {}'.format( result_file_port ))
        result_file_port_open = open(result_file_port,'a+')
        for ip in open_port_dict_all.keys():
            if len(open_port_dict_all[ip]):
                output = '{},{}'.format(ip,open_port_dict_all[ip])
                logger.info(output)
                result_file_port_open.write(output+'\n')
        result_file_port_open.close()
    else:
        logger.debug("NO ScanType")
        exit()
###########################
    print('*************************************************************************************')
###########################
#端口对应服务扫描
    if len(open_port_dict_all) > 0:
        #存储服务结果 #需要返回固定的字典格式
        #{'8.8.8.8': [{'type': 'nmap', 'port': 25, 'proto': 'smtp', 'state': 'filtered', 'product': '', 'version': '', 'response': 'NULL'}, {'type': 'nmap', 'port': 110, 'proto': 'pop3', 'state': 'filtered', 'product': '', 'version': '', 'response': 'NULL'}], '1.1.1.1': [{'type': 'nmap', 'port': 25, 'proto': 'smtp', 'state': 'filtered', 'product': '', 'version': '', 'response': 'NULL'}, {'type': 'nmap', 'port': 110, 'proto': 'pop3', 'state': 'filtered', 'product': '', 'version': '', 'response': 'NULL'}, {'type': 'nmap', 'port': 443, 'proto': 'http', 'state': 'open', 'product': 'Cloudflare http proxy', 'version': '', 'response': 'NULL'}]}
        port_service_list_tcp=dict()
        port_service_list_nmap=dict()
        open_port_sevice_all=dict()
        if config.get_service:
            #增加all参数
            if 'all' in config.get_service:
                config.get_service = 't1,t2'
            #循环获取指纹件
            for get_service in config.get_service.split(','):
                get_service = get_service.strip()
                logger.debug('now get_service',get_service)
                if  ("tcp" in get_service) or ("t1" in get_service) :
                    tgps = TcpGetPortService(config=config, ip_port_dict=open_port_dict_all)
                    port_service_list_tcp = tgps.run()
                elif  ("nmap" in get_service) or ("t2" in get_service) :
                    ngps = NmapGetPortService(config=config, ip_port_dict=open_port_dict_all)
                    port_service_list_nmap = ngps.run()
                else:
                    logger.info(' [!! Get Service type Input Error: {} !!!!!!!]'.format(get_service))

            #所有端口服务结果合并 处理 合并失败，存在bug列表合并bug  需要深拷贝绕过
            # {'1.1.1.2': [{'port': 25, 'state': 'filtered', 'name': 'smtp', 'product': '', 'version': ''}, {'port': 80, 'state': 'open', 'name': 'http', 'product': 'Cloudflare http proxy', 'version': ''}, {'port': 110, 'state': 'filtered', 'name': 'pop3', 'product': '', 'version': ''}, {'port': 443, 'state': 'open', 'name': 'http', 'product': 'Cloudflare http proxy', 'version': ''}], '1.1.1.1': [{'port': 25, 'state': 'filtered', 'name': 'smtp', 'product': '', 'version': ''}, {'port': 110, 'state': 'filtered', 'name': 'pop3', 'product': '', 'version': ''}, {'port': 443, 'state': 'open', 'name': 'http', 'product': 'Cloudflare http proxy', 'version': ''}]}
            # {'1.1.1.1': [{'port': 443, 'proto': 'https', 'payload': "b'HTTP/1.1 400 Bad Request\\r\\nServer: cloudflare\\r\\nDate: Fri, 06 Nov 2020 18:30:49 GMT\\r\\nContent-Type: text/html\\r\\nContent-Length: 253\\r\\nConnection: close\\r\\nCF-RAY: -\\r\\n\\r\\n<html>\\r\\n<head><title>400 The plain HTTP request was sent to HTTPS port</title></head>\\r\\n<body>\\r\\n<center><h1>400 Bad Request</h1></center>\\r\\n<center>The plain HTTP request was sent to HTTPS port</center>\\r\\n<hr><center>cloudflare</center>\\r\\n</body>\\r\\n</html>\\r\\n'"}, {'port': 25, 'proto': 'unknow', 'payload': 'timed out'}, {'port': 110, 'proto': 'unknow', 'payload': 'timed out'}], '1.1.1.2': [{'port': 80, 'proto': 'https', 'payload': "b'HTTP/1.1 302 Moved Temporarily\\r\\nDate: Fri, 06 Nov 2020 18:30:50 GMT\\r\\nTransfer-Encoding: chunked\\r\\nConnection: keep-alive\\r\\nCache-Control: private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0\\r\\nExpires: Thu, 01 Jan 1970 00:00:01 GMT\\r\\nLocation: https://one.one.one.one/family/\\r\\ncf-request-id: 06406c692c000077e2f8848000000001\\r\\nServer: cloudflare\\r\\nCF-RAY: 5ee0e355187377e2-LAX\\r\\n\\r\\n0\\r\\n\\r\\n'"}, {'port': 443, 'proto': 'https', 'payload': "b'HTTP/1.1 400 Bad Request\\r\\nServer: cloudflare\\r\\nDate: Fri, 06 Nov 2020 18:30:50 GMT\\r\\nContent-Type: text/html\\r\\nContent-Length: 253\\r\\nConnection: close\\r\\nCF-RAY: -\\r\\n\\r\\n<html>\\r\\n<head><title>400 The plain HTTP request was sent to HTTPS port</title></head>\\r\\n<body>\\r\\n<center><h1>400 Bad Request</h1></center>\\r\\n<center>The plain HTTP request was sent to HTTPS port</center>\\r\\n<hr><center>cloudflare</center>\\r\\n</body>\\r\\n</html>\\r\\n'"}, {'port': 25, 'proto': 'unknow', 'payload': 'timed out'}, {'port': 110, 'proto': 'unknow', 'payload': 'timed out'}]}
            #结果是字典,不合并端口服务,只合并IP
            #open_port_sevice_all=dict(port_service_list_tcp,**port_service_list_nmap) #失败
            logger.debug('port_service_list_nmap : {}'.format(port_service_list_nmap))
            logger.debug('port_service_list_tcp : {}'.format(port_service_list_tcp))
            open_port_sevice_all_keys=[]
            open_port_sevice_all_keys.extend(port_service_list_tcp.keys())
            open_port_sevice_all_keys.extend(port_service_list_nmap.keys())
            open_port_sevice_all_keys=list(set(open_port_sevice_all_keys))
            #open_port_sevice_all = dict.fromkeys(open_port_sevice_all_keys,[]) #此处不能用fromkeys
            for open_port_sevice_keys  in open_port_sevice_all_keys:
                open_port_sevice_all[open_port_sevice_keys]=[]
            for ip in open_port_sevice_all.keys():
                if port_service_list_tcp.__contains__(ip):
                    open_port_sevice_all[ip].extend(port_service_list_tcp[ip])
                if port_service_list_nmap.__contains__(ip):
                    open_port_sevice_all[ip].extend(port_service_list_nmap[ip])
                #open_port_sevice_all[ip]=list(set(open_port_sevice_all[ip])) #TypeError: unhashable type: 'dict'
            logger.debug(open_port_sevice_all)
            #定义结果输出文件
            #result_file_service="log/result_service_{}.txt".format(time.time())
            result_file_service="{}/log/result_service.csv".format(root_abspath)
            logger.info('service result file : {}'.format( result_file_service ))
            result_file_service_open = open(result_file_service,'a+')
            #写入结果文件
            #获取IP对应的端口服务列表
            for ip in open_port_sevice_all.keys():
                if len(open_port_sevice_all[ip]) :
                    #获取IP对应的端口服务列表的对应端口服务字典
                    #{'type': 'nmap', 'port': 25, 'proto': 'smtp', 'state': 'filtered', 'product': '', 'version': '', 'response': 'NULL'}
                    for port_service_dict in open_port_sevice_all[ip]:
                        if len(port_service_dict) :
                            #获取IP对应的端口服务列表的对应端口服务
                            result_output = '{},{},{},{},{},"{}","{}","{}"'.format(
                            ip,
                            port_service_dict['port'],
                            port_service_dict['proto'],
                            port_service_dict['state'],
                            port_service_dict['type'],
                            port_service_dict['product'],
                            port_service_dict['version'],
                            port_service_dict['response'].replace('"',''))
                            logger.info(result_output)
                            result_file_service_open.write(result_output+'\n')
            #写入结果文件完毕
            result_file_service_open.close()
    else:
        logger.error('open_port_dict_all==0 ')

if __name__ == "__main__":
    main()
