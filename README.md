<!--
 * @Author: winezero
 * @reference: reber
 * @LastEditTime : 2020-11-08
 -->
# Rportscan  NovaSEC

* Author: winezero NovaSEC

* Reference: reber

* 开发需求：

  * 结合多种方式进行端口扫描，目前支持masscan、goscan、tcpscan、httpscan、nmapscan，支持并行扫描
  
  * 结合多种方式进行端口指纹识别，目前支持nmap、socket匹配，支持并行扫描
  
  * 其他功能慢看需求、大家可以提issues

* 代码实现：

  * 基于https://github.com/reber0/Rpscan修改，致谢reber0

* 运行环境：

  * windows-linux-python3.7-3.8
  
  * 已将所有的依赖包下载到本地，无需安装依赖

* 缺陷bug：

  * 本质上是一辆拼装车，扫描超多目标时可能会有外部调用的bug，所以部分模块我都限制了线程。

  * 会一直迭代更新，使用方法请查看rpscan.py -h


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

  * nmap nmap指纹识别
  
  * tcp socket指纹识别

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

扫描二维码关注NovaSEC公众号，谢谢支持

https://github.com/winezer0/RPscan/blob/main/NovaSEC%E5%85%AC%E4%BC%97%E5%8F%B7%E4%BA%8C%E7%BB%B4%E7%A0%81.jpg

