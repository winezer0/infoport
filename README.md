<!--
 * @Author: winezero
 * @ReAuthor: reber
 * @LastEditTime : 2020-11-08
 -->
# Rportscan

### 功能

* 解析目标 ip

* 识别存活主机

* 端口扫描

  * goscanport 扫描存活主机端口
  
  * masscan 扫描存活主机端口
  
  * async tcp 扫描存活主机端口

  * http 探测常见的 web 端口

  * nmap 扫描存活主机端口(-sS, 使用sudo)

* 服务识别

### 安装必要模块
* 安装 masscan [(Download)](https://github.com/robertdavidgraham/masscan)
    * 自带的有 mac(v1.0.4) 和 win(v1.0.6 免杀) 下编译好的 masscan，其它平台不能用的自行编译安装

* 安装 nmap 并加入环境变量 [(Download)](https://nmap.org/dist/?C=M&O=D)
    * 如果是 win 的话安装 winpcap [(Download)](https://www.winpcap.org/install/default.htm)

* pip3 install -r requirements.txt

### 参数
```
➜  python3 rpscan.py -h                                              
usage: rpscan.py [-h] [-i TARGET] [-iL TARGET_FILENAME] [-c CONFIG_FILE]
                 [-p PORTS] [-st SCANTYPE] [-sv GET_SERVICE] [-ck]
                 [-t THREAD_NUM] [-r RATE]

optional arguments:
  -h, --help           show this help message and exit
  -i TARGET            扫描指定IP目标 : 1.1.1.1 or 1.1.1.1/24 or 1.1.1.1-255 or
                       1.1.1.1-1.1.1.254, 支持多种格式同时输入
  -iL TARGET_FILENAME  扫描指定IP文件, 对多个大目标的支持可能不完善,扫描大目标时建议使用masscan,goscan等外部程序
  -c CONFIG_FILE       扫描配置文件路径, example: /usr/local/etc/rpscan.cfg,
                       文件不存在时会自动创建默认配置文件,
                        程序打包后运行时建议手动指定配置文件
  -p PORTS             指定扫描端口, 支持分隔符[,-],
                       支持端口简写[t1(web-100),t2(常用-200),t3(常用-300),all(全端口)],
                       支持多种格式同时输入
  -st SCANTYPE         端口扫描方法指定 (masscan(默认):t1(简写), goscan:t2 , tcpasyc:t3 ,
                       nmap:t4 , http:t5),支持同时指定多个扫描方式 )
  -sv GET_SERVICE      进行端口服务检测, 支持探测方法[tcp:t1, nmap:t2], 支持同时指定多个探测方式
  -ck                  使用nmap探测主机是否存活, 默认False
  -t THREAD_NUM        端口扫描线程, 默认10, 部分模块暂不支持线程设置,目前支持:nmap_s,nmap_service
  -r RATE              端口扫描速率, 默认1000, 部分模块暂不支持速率设置, 目前支持:tcpasyc,masscan
  -v                   显示调试信息,默认关闭
Examples:
  python3 rpscan.py -i 192.168.1.1/24 -p 1-66535 -ck 3 -st t1 -sv t1
  python3 rpscan.py -i 192.168.1.1-255  -p t1 -st masscan,goscan,http.nmap,tcpasyc -sv tcp,nmap
  python3 rpscan.py -i 192.168.1.1-192.168.1.255   -p 80,443,8080,8443 -st t1,t2,t3,t4,t5 -sv t1,t2
  python3 rpscan.py -i 192.168.1.1-255  -st masscan,goscan,http.nmap,tcpasyc -sv tcp,nmap
  python3 rpscan.py -iL target.txt  -p all -st masscan -r 3000 -ck  -st t1 -sv t1
  输入参数简写规则请查看rpscan.py
```

