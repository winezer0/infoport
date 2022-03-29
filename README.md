# INFOPORT  NOVASEC|酒零

- 发现端口扫描不能少了nmap的指纹识别,但是namp扫描端口真的太慢了,所以打算实现一个portscan+nmap,
- 多次重构后最终实现了多个端口扫描器与服务识别项目的组合,并且都可以通过进行自定义命令配置
- 程序结构重构后逻辑已经十分简单明了,可以很轻易的拼接自己需要的扫描器。

### 更新

* 20220121 修复一些参数和显示BUG
* 20220120 重构整体结构

### Todo

1. 暂无

### 注意

1. 使用前请解压[thirdparty.zip]为[thirdparty]目录,其中为Nmap等第三方程序。

### 功能

* 解析目标ip和端口
* 识别存活主机
  1. nmap
  2. 跳过 

* 端口扫描 任选
  1. python asynctcp、telnet、http不建议
  2. masscan、nmap 
  3. 其他golang portscan及rust blackwater 


* 服务识别 任选
  1. nmap
  2. python tcp socket

### 使用

1. 使用前请根据自己的系统配置config.ini和libs/parse_input.py中的第三方程序运行路径及运行参数,默认仅测试了windows环境,linux环境可能需要sudo和chmod处理可执行文件。
2. 如果程序已处于环境变量-如nmap,就不需要填写nmap的绝对路径,直接填写nmap即可。
3. $BASE_DIR$代表当前脚本文件所在路径,打包后应该是当前程序的所在路径。
4. 目前不适用于大量IP段扫描的情况，适合用于准确度需较高的端口分析。 
5. 可以使用pyinstaller 4.x版本直接进行脚本打包。 

![help](https://user-images.githubusercontent.com/46115146/150475963-224a086e-9183-421f-a808-6c7615364843.png)

![run](https://user-images.githubusercontent.com/46115146/150475950-0e29a307-2068-4f2c-bee5-43ead36cc00e.png)

![run-v](https://user-images.githubusercontent.com/46115146/150475939-d163e3a1-0702-4eae-9706-348a2cb9c9a3.png)



### 其他

===========================

```
20220121 修复命令调用错误、优化显示效果
20220120 重构整体结构
20201119
            1、修改s1\s2\s3为c1、c2、c3。c表示常用。
            2、全端口开放超过50%时，提示是否清空模块扫描结果
            3、项目重命名为INFOPORT
202001117
            增加telnet模块用于判断端口是否开放，已本地化
             #扫描类型增加s1,s2,s3参数
            's1'= 't1,t2'
            's2' = 't1,t2,t3'
            's3' = 't1,t2,t3,t6'
20201113
            当开放端口大于全部扫描端口的90%时候，判断为存在waf
            增加端口扫描结果是否置空的交互选项，用于人工判断端口是否真实开放
            优化输入端口范围【1000-500】 前端端口大于后端端口报错问题
            优化输入IP地址范围【1.1.1.254-9】 前端IP大于后端IP不报错问题
20201113 	
			需要增加强制全端口服务识别功能
            增加-st all参数,使用所有方式进行端口探测
            增加-sv all参数,使用所有方式进行服务探测
            优化默认控制台输出：端口扫描结果，端口服务解析结果
20201101
            处理cfg路径文件不存在问题，不存在自动生成：
            间接优化exe程序下需要手动指定 -c config文件位置问题
20201101
            py脚本情况下支持任意路径调用程序。
            exe程序下需要手动指定 -c config文件位置
            绝对路径文件：日志文件，exe文件，masscan、goscan输出

20201101
            多种端口扫描方式并行
            输出优化结果

20201101
            alive测试 ping no ,arp no ,跳过ok,  nmap ok 
            端口扫描 nmap,masscan,http,tcp,syn,socket  开关  OK
            指纹识别 nmap,socket 开关

20201101
            扫描IP格式验证
            参数输入 IP段1.1.1.1/28，IP范围1.1.1.1-1.1.1.2,1.1.1.1-2，多个IP  OK
            INFOPortrp -i 1.1.1.1/28 -p 25,110 -st goscan -s ok
            INFOPortrp -i 1.1.1.1-1.1.1.2 -p 25,110 -st goscan -s ok
            INFOPortrp -i 1.1.1.1,1.1.1.2 -p 25,110 -st goscan -s  ok 
扫描端口格式验证
		端口输入 端口范围1-65535，多个端口25,110,80 ,综合格式25,110,80-100 ，快捷字段 all,t1,t2,t3 OK 
```




### NOVASEC团队公众号

![NOVASEC-二维码](https://user-images.githubusercontent.com/46115146/150318610-ad46b4bb-d98e-44c5-ac88-207654f1d3c6.jpg)

