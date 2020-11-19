<!--
 * @Author: winezero
 * @reference: reber
 * @LastEditTime : 2020-11-08
 -->
# INFOPORT  NOVASEC|酒零

* Author: winezero NovaSEC

* Reference: reber

### 功能

* 解析目标 ip

* 识别存活主机

  * nmap 识别存活主机
  
* 端口扫描

  * goscanport 扫描存活主机端口
  
  * masscan 扫描存活主机端口
  
  * async tcp 扫描存活主机端口

  * http 探测常见的 web 端口

  * nmap 扫描存活主机端口(-sS, 使用sudo)
  
  * telnet 扫描存活主机端口(-sS, 使用sudo)

* 服务识别

  * nmap nmap指纹识别
  
  * tcp socket指纹识别


* 开发需求：

  * 结合多种方式进行端口扫描，目前支持masscan、goscan、tcpscan、httpscan、nmapscan，支持并行扫描
  
  * 结合多种方式进行端口指纹识别，目前支持nmap、socket匹配，支持并行扫描
  
  * 其他功能慢看需求、大家可以提issues

* 代码实现：
  * 基本组件基于 masscan、nmap
  * 基本框架基于 https://github.com/reber0/Rpscan 修改，致谢reber0
  * goscan 基于 https://github.com/xs25cn/scanPort 修改，致谢xs25cn
  * tcp指纹识别模块基于 https://github.com/fanyingjie2/tcpscan 修改，致谢fanyingjie2

* 缺陷bug：

  * 本质上是一辆拼装车，扫描超多目标时可能会有外部调用的bug，所以部分模块我都限制了线程。

  * 会一直迭代更新，使用方法请查看help

### 安装必要模块

* 安装 nmap 并加入环境变量 [(Download)](https://nmap.org/dist/?C=M&O=D)
    * 如果是 win 的话安装 winpcap [(Download)](https://www.winpcap.org/install/default.htm)

* 【可忽略】安装 masscan [(Download)](https://github.com/robertdavidgraham/masscan)
    * 自带的有 mac(v1.0.4) 和 win(v1.0.6 免杀) 下编译好的 masscan，其它平台不能用的自行编译安装

* 【可忽略】安装 goscanport 
    * 自带的有 linux和 win下编译好的 goscanport，其它平台不能用的自行编译目录下的源码
 
* 运行环境：
  * windows-linux-python3.7-3.8
  * 已将所有的依赖包下载到本地，无需安装依赖
  
### 参数
```
➜  python3 infoport.py -i 1.1.1.1 -p c1 -st all -sv all -h
usage: infoport.py [-h] [-i TARGET] [-iL TARGET_FILENAME] [-c CONFIG_FILE] [-p PORTS] [-st SCANTYPE] [-sv GET_SERVICE] [-ck]
                   [-t THREAD_NUM] [-r RATE] [-v] [-b]

optional arguments:
  -h, --help           show this help message and exit
  -i TARGET            指定IP目标 : 1.1.1.1 or 1.1.1.1/24 or 1.1.1.1-255 or 1.1.1.1-1.1.1.254, 支持多种格式同时输入
  -iL TARGET_FILENAME  指定IP文件, 对多个大目标的支持可能不完善,扫描大目标时建议使用masscan,goscan等外部程序
  -c CONFIG_FILE       指定配置文件, example: /usr/local/etc/rpscan.cfg,文件不存在时会自动创建默认配置文件, 程序打包后运行时建议手动指定配置
文件
  -p PORTS             指定扫描端口, 支持端口分隔符[ , - ] , 支持多种格式同时输入 , 支持简写[ c1(web-100), c2(常用-200), c3(常用-300), all(所
有端口)]
  -st SCANTYPE         指定端口扫描方法 [ masscan(默认):t1(简写), goscan:t2 , tcpasyc:t3, telnet:t4, nmap:t5 , http:t6, all(所有方式),
                       c1(t1,t2),c2(t1,t2,t3),c3(t1,t2,t3,t4) ] ,支持同时指定多个扫描方式 )
  -sv GET_SERVICE      指定服务检测方法, 支持探测方法[tcp:t1, nmap:t2, all(所有方式)], 支持同时指定多个探测方式
  -ck                  使用nmap探测主机是否存活, 默认False
  -t THREAD_NUM        端口扫描线程, 默认10, 部分模块暂不支持线程设置,目前支持:port_nmap,service_nmap
  -r RATE              端口扫描速率, 默认1000, 部分模块暂不支持速率设置, 目前支持:port_tcpasyc,port_masscan
  -v                   显示调试信息,默认关闭
  -b                   使用自动选项处理交互选项, 默认关闭, 目前交互选项: 端口扫描结果置空

Examples:
  python3 infoport.py -i 192.168.1.1/24 -p 1-66535 -ck 3 -st t1 -sv t1
  python3 infoport.py -i 192.168.1.1-255  -p t1 -st masscan,goscan,http.nmap,tcpasyc -sv tcp,nmap
  python3 infoport.py -i 192.168.1.1-192.168.1.255   -p 80,443,8080,8443 -st t1,t2,t3,t4,t5 -sv t1,t2
  python3 infoport.py -i 192.168.1.1-255  -st masscan,goscan,http.nmap,tcpasyc -sv tcp,nmap
  python3 infoport.py -iL target.txt  -p all -st masscan -r 3000 -ck  -st t1 -sv t1
  输入参数简写规则请查看infoport.py
```

###########################################################

* 更新记录：


  * 202001117
  
  修改扫描类型s1\s2\s3为c1、c2、c3。c表示常用。
  
  全端口开放超过50%时，提示是否清空模块扫描结果
  
  项目重命名为INFOPORT

  * 202001117
  
增加telnet模块用于判断端口是否开放，已本地化

扫描类型增加s1,s2,s3参数,s1=t1,t2,s2=t1,t2,t3,s3=t1,t2,t3,t6


  * 20201113 

当开放端口大于全部扫描端口的90%时候，判断为存在waf

增加端口扫描结果是否置空的交互选项，用于人工判断端口是否真实开放

优化输入端口范围【1000-500】 前端端口大于后端端口报错问题

优化输入IP地址范围【1.1.1.254-9】 前端IP大于后端IP不报错问题

增加-st all参数,使用所有方式进行端口探测

增加-sv all参数,使用所有方式进行服务探测

优化默认控制台输出：端口扫描结果，端口服务解析结果


  * 20201101

处理cfg路径文件不存在问题，不存在自动生成：

间接优化exe程序下需要手动指定 -c config文件位置问题

  * 20201101

py脚本情况下支持任意路径调用程序。

exe程序下需要手动指定 -c config文件位置

绝对路径文件：日志文件，exe文件，masscan、goscan输出

  * 20201101

多种端口扫描方式并行

输出优化结果

  * 20201101

alive测试 ping no ,arp no ,跳过ok,  nmap ok 

端口扫描 nmap,masscan,http,tcp,syn,socket  开关  OK

指纹识别 nmap,socket 开关


  * 20201101

扫描IP格式验证

IP段1.1.1.1/28，IP范围1.1.1.1-1.1.1.2,1.1.1.1-2，多个IP  OK

扫描端口格式验证 

端口范围1-65535，多个端口25,110,80 ,综合格式25,110,80-100 ，快捷字段 all,t1,t2,t3 OK 

###########################################################

扫描二维码关注NovaSEC公众号，谢谢支持

https://github.com/winezer0/RPscan/blob/main/NovaSEC%E5%85%AC%E4%BC%97%E5%8F%B7%E4%BA%8C%E7%BB%B4%E7%A0%81.jpg

