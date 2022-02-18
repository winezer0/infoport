# INFOPORT  NOVASEC|酒零

* 发现端口扫描不能少了nmap的指纹识别,但是namp扫描端口真的太慢了,所以打算实现一个Go语言快速的portscan+nmap,多次重构后最终实现了多个端口扫描器与服务识别项目的组合,并且都可以通过进行自定义命令配置

* 程序结构重构后逻辑已经十分简单明了,可以很轻易的拼接自己需要的扫描器。

### 功能

* 解析目标ip和端口
* 识别存活主机
  * nmap
  * 跳过 

* 端口扫描 任选
  * python asynctcp、telnet、http不建议
  * masscan、nmap 
  * 其他golang portscan及rust blackwater 


* 服务识别 任选
  * nmap
  * python tcp socket

### 使用

* 使用前请根据自己的系统配置config.ini和libs/parse_input.py中的第三方程序运行路径及运行参数,默认仅测试了windows环境,linux环境可能需要sudo和chmod处理可执行文件。
* 如果程序已处于环境变量-如nmap,就不需要填写nmap的绝对路径,直接填写nmap即可。
* $BASE_DIR$代表当前脚本文件所在路径,打包后应该是当前程序的所在路径。
* 目前不适用于大量IP段扫描的情况，适合用于准确度需较高的端口分析。 
* 可以使用pyinstaller 4.x版本直接进行脚本打包。 


![help](https://user-images.githubusercontent.com/46115146/150475963-224a086e-9183-421f-a808-6c7615364843.png)


![run](https://user-images.githubusercontent.com/46115146/150475950-0e29a307-2068-4f2c-bee5-43ead36cc00e.png)


![run-v](https://user-images.githubusercontent.com/46115146/150475939-d163e3a1-0702-4eae-9706-348a2cb9c9a3.png)


### 更新记录：

* 20220121 修复一些参数和显示BUG

* 20220120 重构整体结构


### NOVASEC团队公众号

![NOVASEC-二维码](https://user-images.githubusercontent.com/46115146/150318610-ad46b4bb-d98e-44c5-ac88-207654f1d3c6.jpg)

