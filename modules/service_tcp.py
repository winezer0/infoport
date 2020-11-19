#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-08-24 17:55:54
@LastEditTime : 2020-08-07 20:05:09
'''
import random
import time
from concurrent.futures import ThreadPoolExecutor
import socket
import re

class TcpGetPortService(object):
    """获取端口运行的服务"""
    
    def __init__(self, config, ip_port_dict):
        super(TcpGetPortService, self).__init__()
        self.port_service_list = dict()
        self.ip_port_dict = ip_port_dict
        self.thread_num = config.thread_num
        self.logger = config.logger
        self.init_thread()
        self.flag = True
        self.SIGNS= (
        #协议 | 版本 | 关键字
        b'smb|smb|^\0\0\0.\xffSMBr\0\0\0\0.*',
        b"xmpp|xmpp|^\<\?xml version='1.0'\?\>",
        b'netbios|netbios|^\x79\x08.*BROWSE',
        b'netbios|netbios|^\x79\x08.\x00\x00\x00\x00',
        b'netbios|netbios|^\x05\x00\x0d\x03',
        b'netbios|netbios|^\x82\x00\x00\x00',
        b'netbios|netbios|\x83\x00\x00\x01\x8f',
        b'backdoor|backdoor|^500 Not Loged in',
        b'backdoor|backdoor|GET: command',
        b'backdoor|backdoor|sh: GET:',
        b'bachdoor|bachdoor|[a-z]*sh: .* command not found',
        b'backdoor|backdoor|^bash[$#]',
        b'backdoor|backdoor|^sh[$#]',
        b'backdoor|backdoor|^Microsoft Windows',
        b'db2|db2|.*SQLDB2RA',
        b'dell-openmanage|dell-openmanage|^\x4e\x00\x0d',
        b'finger|finger|^\r\n    Line      User',
        b'finger|finger|Line     User',
        b'finger|finger|Login name: ',
        b'finger|finger|Login.*Name.*TTY.*Idle',
        b'finger|finger|^No one logged on',
        b'finger|finger|^\r\nWelcome',
        b'finger|finger|^finger:',
        b'finger|finger|^must provide username',
        b'finger|finger|finger: GET: ',
        b'ftp|ftp|^220.*\n331',
        b'ftp|ftp|^220.*\n530',
        b'ftp|ftp|^220.*FTP',
        b'ftp|ftp|^220 .* Microsoft .* FTP',
        b'ftp|ftp|^220 Inactivity timer',
        b'ftp|ftp|^220 .* UserGate',
        b'ftp|ftp|^220.*FileZilla Server',
        b'ldap|ldap|^\x30\x0c\x02\x01\x01\x61',
        b'ldap|ldap|^\x30\x32\x02\x01',
        b'ldap|ldap|^\x30\x33\x02\x01',
        b'ldap|ldap|^\x30\x38\x02\x01',
        b'ldap|ldap|^\x30\x84',
        b'ldap|ldap|^\x30\x45',
        b'ldp|ldp|^\x00\x01\x00.*?\r\n\r\n$',
        b'rdp|rdp|^\x03\x00\x00\x0b',
        b'rdp|rdp|^\x03\x00\x00\x11',
        b'rdp|rdp|^\x03\0\0\x0b\x06\xd0\0\0\x12.\0$',
        b'rdp|rdp|^\x03\0\0\x17\x08\x02\0\0Z~\0\x0b\x05\x05@\x06\0\x08\x91J\0\x02X$',
        b'rdp|rdp|^\x03\0\0\x11\x08\x02..}\x08\x03\0\0\xdf\x14\x01\x01$',
        b'rdp|rdp|^\x03\0\0\x0b\x06\xd0\0\0\x03.\0$',
        b'rdp|rdp|^\x03\0\0\x0b\x06\xd0\0\0\0\0\0',
        b'rdp|rdp|^\x03\0\0\x0e\t\xd0\0\0\0[\x02\xa1]\0\xc0\x01\n$',
        b'rdp|rdp|^\x03\0\0\x0b\x06\xd0\0\x004\x12\0',
        b'rdp-proxy|rdp-proxy|^nmproxy: Procotol byte is not 8\n$',
        b'msrpc|msrpc|^\x05\x00\x0d\x03\x10\x00\x00\x00\x18\x00\x00\x00\x00\x00',
        b'msrpc|msrpc|\x05\0\r\x03\x10\0\0\0\x18\0\0\0....\x04\0\x01\x05\0\0\0\0$',
        b'mssql|mssql|^\x05\x6e\x00',
        b'mssql|mssql|^\x04\x01',
        b'mssql|mysql|;MSSQLSERVER;',
        b'mysql|mysql|mysql_native_password',
        b'mysql|mysql|^\x19\x00\x00\x00\x0a',
        b'mysql|mysql|^\x2c\x00\x00\x00\x0a',
        b'mysql|mysql|hhost \'',
        b'mysql|mysql|khost \'',
        b'mysql|mysql|mysqladmin',
        b'mysql|mysql|whost \'',
        b'mysql|mysql|^[.*]\x00\x00\x00\n.*?\x00',
        b'mysql-secured|mysql|this MySQL server',
        b'mysql-secured|MariaDB|MariaDB server',
        b'mysql-secured|mysql-secured|\x00\x00\x00\xffj\x04Host',
        b'db2jds|db2jds|^N\x00',
        b'nagiosd|nagiosd|Sorry, you \(.*are not among the allowed hosts...',
        b'nessus|nessus|< NTP 1.2 >\x0aUser:',
        b'oracle-tns-listener|\(ERROR_STACK=\(ERROR=\(CODE=',
        b'oracle-tns-listener|\(ADDRESS=\(PROTOCOL=',
        b'oracle-dbsnmp|^\x00\x0c\x00\x00\x04\x00\x00\x00\x00',
        b'oracle-https|^220- ora',
        b'rmi|rmi|\x00\x00\x00\x76\x49\x6e\x76\x61',
        b'rmi|rmi|^\x4e\x00\x09',
        b'postgresql|postgres|Invalid packet length',
        b'postgresql|postgres|^EFATAL',
        b'rpc-nfs|rpc-nfs|^\x02\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00',
        b'rpc|rpc|\x01\x86\xa0',
        b'rpc|rpc|\x03\x9b\x65\x42\x00\x00\x00\x01',
        b'rpc|rpc|^\x80\x00\x00',
        b'rsync|rsync|^@RSYNCD:',
        b'smux|smux|^\x41\x01\x02\x00',
        b'snmp-public|snmp-public|\x70\x75\x62\x6c\x69\x63\xa2',
        b'snmp|snmp|\x41\x01\x02',
        b'socks|socks|^\x05[\x00-\x08]\x00',
        b'ssl|ssl|^..\x04\0.\0\x02',
        b'ssl|ssl|^\x16\x03\x01..\x02...\x03\x01',
        b'ssl|ssl|^\x16\x03\0..\x02...\x03\0',
        b'ssl|ssl|SSL.*GET_CLIENT_HELLO',
        b'ssl|ssl|^-ERR .*tls_start_servertls',
        b'ssl|ssl|^\x16\x03\0\0J\x02\0\0F\x03\0',
        b'ssl|ssl|^\x16\x03\0..\x02\0\0F\x03\0',
        b'ssl|ssl|^\x15\x03\0\0\x02\x02\.*',
        b'ssl|ssl|^\x16\x03\x01..\x02...\x03\x01',
        b'ssl|ssl|^\x16\x03\0..\x02...\x03\0',
        b'sybase|sybase|^\x04\x01\x00',
        b'telnet|telnet|Telnet',
        b'telnet|telnet|^\xff[\xfa-\xff]',
        b'telnet|telnet|^\r\n%connection closed by remote host!\x00$',
        b'rlogin|rlogin|login: ',
        b'rlogin|rlogin|rlogind: ',
        b'rlogin|rlogin|^\x01\x50\x65\x72\x6d\x69\x73\x73\x69\x6f\x6e\x20\x64\x65\x6e\x69\x65\x64\x2e\x0a',
        b'tftp|tftp|^\x00[\x03\x05]\x00',
        b'uucp|uucp|^login: password: ',
        b'vnc|vnc|^RFB',
        b'imap|imap|^\* OK.*?IMAP',
        b'pop|pop|^\+OK.*?',
        b'smtp|smtp|^220.*?SMTP',
        b'smtp|smtp|^554 SMTP',
        b'ftp|ftp|^220-',
        b'ftp|ftp|^220.*?FTP',
        b'ftp|ftp|^220.*?FileZilla',
        b'ssh|ssh|^SSH-',
        b'ssh|ssh|connection refused by remote host.',
        b'rtsp|rtsp|^RTSP/',
        b'sip|sip|^SIP/',
        b'nntp|nntp|^200 NNTP',
        b'sccp|sccp|^\x01\x00\x00\x00$',
        b'webmin|webmin|.*MiniServ',
        b'webmin|webmin|^0\.0\.0\.0:.*:[0-9]',
        b'websphere-javaw|websphere-javaw|^\x15\x00\x00\x00\x02\x02\x0a',
        b'smb|smb|^\x83\x00\x00\x01\x8f',
        b'docker-daemon|docker-daemon|^\x15\x03\x01\x00\x02\x02',
        b'mongodb|mongodb|MongoDB',
        b'Rsync|Rsync|@RSYNCD:',
        b'Squid|Squid|X-Squid-Error',
        b'mssql|Mssql|MSSQLSERVER',
        b'Vmware|Vmware|VMware',
        b'iscsi|iscsi|\x00\x02\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
        b'redis|redis|^-ERR unknown command',
        b'redis|redis|^-ERR wrong number of arguments',
        b'redis|redis|^-DENIED Redis is running',
        b'memcached|memcached|^ERROR\r\n',
        b'websocket|websocket|Server: WebSocket',
        b'https|https|Instead use the HTTPS scheme to access'
        b'https|https|HTTPS port',
        b'https|https|Location: https',
        b'http|http|^HTTP',
        b'http|topsec|^\x15\x03\x03\x00\x02\x02',
        b'SVN|SVN|^\( success \( 2 2 \( \) \( edit-pipeline svndiff1',
        b'dubbo|dubbo|^Unsupported command',
        b'http|elasticsearch|cluster_name.*elasticsearch',
        b'RabbitMQ|RabbitMQ|^AMQP\x00\x00\t\x01',
    )
    
    def init_thread(self):
        '''设定线程数量'''
        if len(self.ip_port_dict) < self.thread_num:
            self.thread_num = len(self.ip_port_dict)
    
    def tcp_get_service(self, ip_port):
        '''tcp 获取端口的 service'''
        socket.setdefaulttimeout(1)
        if self.flag:
            #self.logger.debug('ip_port',ip_port)
            ip, port = ip_port
            try :
                response1 = b''
                proto = 'Unknow'
                payload = 'X' * int(random.random() * 100)
                payload1 = ('GET / HTTP/1.1\r\nHOST: %s\r\nUser-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12F70 Safari/600.1.4\r\nAccept: text/html\r\nCookie: adminUser=123\r\n\r\n'  % ip)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((ip, int(port)))
                if result == 0:
                    sock.sendall(payload1.encode())
                    response1 = sock.recv(512)
                    for pattern in self.SIGNS:
                        pattern = pattern.split(b'|')
                        if re.search(pattern[-1], response1, re.IGNORECASE):
                            proto = pattern[1].decode()
                            break
                    
                    service_result = dict()
                    service_result['type'] = 'tcpscan'
                    service_result['port'] = port
                    service_result['proto'] = proto
                    service_result['state'] = 'open'
                    service_result['product'] =  'NULL'
                    service_result['version'] = 'NULL'
                    service_result['response'] = str(response1)
                    #self.logger.debug(ip,service_result)
                    self.port_service_list[ip].append(service_result)
            except Exception as e:
                #self.logger.debug("%s\t%s\t%s" % (ip, port ,e ))
                service_result = dict()
                service_result['type'] = 'tcpscan'
                service_result['port'] = port
                service_result['proto'] = 'unkonw'
                service_result['state'] = 'filtered'
                service_result['product'] =  'NULL'
                service_result['version'] = 'NULL'
                service_result['response'] = str(e)
                #self.logger.debug(ip,service_result)
                self.port_service_list[ip].append(service_result)
            finally:
                sock.close()
    
    def run(self):
        self.logger.info("[*] Get the service of the port by tcp socket...")

        try:
            with ThreadPoolExecutor(max_workers=self.thread_num) as executor:
                self.logger.debug(self.ip_port_dict)
                for ip in self.ip_port_dict.keys():
                    self.port_service_list[ip] = list()
                    ports = self.ip_port_dict[ip]
                    #取消本处过滤地点,置于端口扫描结果处理处
                    #if  len(list(ports))>200:
                    #    self.logger.error("{} 常用端口开放 {} 个, 可能有拦截设备, 跳过端口服务识别.".format(ip, len(ports.split(","))))
                    #    continue
                    for port in ports:
                        executor.submit(self.tcp_get_service, (ip,port))
        except KeyboardInterrupt:
            self.logger.error("User aborted.")
            self.flag = False
            exit(0)
        except Exception as e:
            self.logger.debug('Exception',e)

        self.logger.debug(self.port_service_list)
        return self.port_service_list
