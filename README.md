# INFOPORT  NOVASEC|酒零

* infoport 发现端口扫描不能少了nmap的指纹识别,但是namp扫描端口真的太慢了,所以打算实现一个Go语言快速的portscan+nmap,选择的多了发现合并了太多的扫描方式 最终励志成为超级端口扫描分析器的python脚本。 
* infoport 目前不适用于大量IP段扫描的情况，适合用于准确度需较高的端口分析。 
* infoport 可以使用pyinstaller 4.x版本直接进行脚本打包。 


### 功能

* 解析目标ip和端口
* 识别存活主机
  * nmap
* 端口扫描
  * python asynctcp、telnet、http 
  * masscan、nmap 
  * 其他golang portscan及rust blackwater 
* 服务识别
  * nmap
  * python tcp socket

### 使用

  * 使用前请根据自己的系统配置config.ini中的第三方程序运行路径及运行参数,默认仅测试了windows环境,linux环境可能需要sudo和chmod处理可执行文件。
  * 如果程序已处于环境变量-如nmap,就不需要填写nmap的绝对路径,直接填写nmap即可。
   * $BASE_DIR$代表当前脚本文件所在路径,打包后应该是当前程序的所在路径。

![help](https://user-images.githubusercontent.com/46115146/150317966-e66fc686-efe2-46d7-a19d-9710c6109275.png)

![run](https://user-images.githubusercontent.com/46115146/150318363-22a78d4c-5ff8-436c-b880-7cca89b94488.png)

### 更新记录：

* 20220120 重构整体结构


### 扫描二维码关注NovaSEC公众号，谢谢支持

![NOVASEC-二维码](https://user-images.githubusercontent.com/46115146/150318610-ad46b4bb-d98e-44c5-ac88-207654f1d3c6.jpg)

