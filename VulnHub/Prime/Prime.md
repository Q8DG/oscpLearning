# Prime

## 1、nmap

![image-20240207091154786](./assets/image-20240207091154786.png)

![image-20240207091416818](./assets/image-20240207091416818.png)

![image-20240207091406422](./assets/image-20240207091406422.png)

![image-20240207092311287](./assets/image-20240207092311287.png)

## 2、web渗透

### 随便看看

![image-20240207091709300](./assets/image-20240207091709300.png)

### 首页隐写查看

![image-20240207091931087](./assets/image-20240207091931087.png)

### 目录爆破

#### gobuster

![image-20240207092119725](./assets/image-20240207092119725.png)

#### feroxbuster

![image-20240207093222823](./assets/image-20240207093222823.png)

#### dirsearch

![image-20240207101949899](./assets/image-20240207101949899.png)

#### dirb

只有dirb扫出来

![image-20240207102011956](./assets/image-20240207102011956.png)

### whatweb

![image-20240207102203368](./assets/image-20240207102203368.png)

![image-20240207093116212](./assets/image-20240207093116212.png)

### searchsploit WordPress 5.2.2

WordPress利用点基本上都是插件或者主题，这里暂时都不可用

![image-20240207094158311](./assets/image-20240207094158311.png)

### /dev

![image-20240207100001787](./assets/image-20240207100001787.png)

![image-20240207100026426](./assets/image-20240207100026426.png)

### /secret.txt

![image-20240207102448819](./assets/image-20240207102448819.png)

![image-20240207102118186](./assets/image-20240207102118186.png)

### Fuzz_For_Web

![image-20240207103752609](./assets/image-20240207103752609.png)

### wfuzz

尝试dirb跑出来的两个根目录下的php文件

#### image.php

![image-20240207104743780](./assets/image-20240207104743780.png)

#### index.php

![image-20240207104816432](./assets/image-20240207104816432.png)

![image-20240207104953170](./assets/image-20240207104953170.png)

![image-20240207105218493](./assets/image-20240207105218493.png)

### location.txt

![image-20240207105109132](./assets/image-20240207105109132.png)

![image-20240207105235487](./assets/image-20240207105235487.png)

### secrettier360

![image-20240207105938923](./assets/image-20240207105938923.png)

这里告诉我们找到了正确的参数，又没说要继续做什么，那么这里就要有一个思路，看看有没有本地文件包含。

### 文件包含漏洞

![image-20240207110315103](./assets/image-20240207110315103.png)

### 包含出password.txt

![image-20240207110938168](./assets/image-20240207110938168.png)

### 尝试ssh登入

![image-20240207152848512](./assets/image-20240207152848512.png)

### 尝试登入wordpress

刚刚发现有两个用户，saket加上获得的密码没法登入，使用victor用户加密码成功登入后台。或者使用wordpress扫描工具、仔细观察页面信息同样也可以发现有价值的东西。

![image-20240207111536955](./assets/image-20240207111536955.png)

![image-20240207122612945](./assets/image-20240207122612945.png)

### wordpress渗透

利用点基本上都是插件或者主题，这里以及成功进入后台，可以尝试这个思路。

#### wpscan

![image-20240207122343509](./assets/image-20240207122343509.png)

#### 插件尝试

先试试看看上传的zip包能否被执行。上传插件走不通

![image-20240207150320985](./assets/image-20240207150320985.png)

#### 主题尝试

![image-20240207150507186](./assets/image-20240207150507186.png)

#### 主题编辑器

靠经验去寻找有可写权限的文件

![image-20240207150825804](./assets/image-20240207150825804.png)

## 3、内网渗透

### 拿下系统shell

通过主题编辑器上的readme.txt文件，很容易就确认目录

![image-20240207151545153](./assets/image-20240207151545153.png)

### user.txt(flag)

![image-20240207152441330](./assets/image-20240207152441330.png)

### 计划任务

![image-20240207153440673](./assets/image-20240207153440673.png)

### 随便看看

![image-20240207153811813](./assets/image-20240207153811813.png)

### find查找备份文件

由于是个网站，可尝试找找备份文件

![image-20240207161721697](./assets/image-20240207161721697.png)

### 提权

#### /enc提权【难】

##### 简单尝试

enc目录有可写权限，又可执行无密码执行enc，可尝试提权。不过好像库里又不是enc，还待商榷。

![image-20240207153941424](./assets/image-20240207153941424.png)

![image-20240207154046583](./assets/image-20240207154046583.png)

##### backup_password

当一个东西执行完成后，发现没什么效果，那么这里就要有一个思路。文件为什么执行，执行之后有什么效果，会实现什么东西。最容易想到的就执行完成后在当前目录释放某些东西。

![image-20240207161955586](./assets/image-20240207161955586.png)

##### enc.txt/key.txt

看到enc、key这些关键字就要联想出openssl的对称加密算法中的enc

![image-20240207162557677](./assets/image-20240207162557677.png)

##### ↓密码问题↓【难】

###### 先记录到本地，慢慢破解

![image-20240207163043238](./assets/image-20240207163043238.png)

###### string "ippsec" into md5 hash(key)

注意这里-n参数表示的换行符一定要注意，有换行和没有换行的md5值是不同的，如果不是很清楚可以两种都去尝试。

![image-20240207163301057](./assets/image-20240207163301057.png)

###### md5 hash into hex(key)

![image-20240207204134818](./assets/image-20240207204134818.png)

###### 生成CipherTypes(用于遍历密钥类型字典)

![image-20240207202910572](./assets/image-20240207202910572.png)

###### 还差一步，遍历-CipherType

![image-20240207204236720](./assets/image-20240207204236720.png)

###### 写bash的for循环脚本

发现一个结果也没有，尝试把-n去掉

![image-20240207210417692](./assets/image-20240207210417692.png)

去掉-n后，就可以解出

![image-20240207210400646](./assets/image-20240207210400646.png)

###### 优化bash脚本

把使用哪种类型的加密类型给显示出来

```bash
# 最终脚本
$ for Cipher in $(cat CipherTypes);do echo 'nzE+iKr82Kh8BOQg0k/LViTZJup+9DReAsXd/PCtFZP5FHM7WtJ9Nz1NmqMi9G0i7rGIvhK2jRcGnFyWDT9MLoJvY1gZKI2xsUuS3nJ/n3T1Pe//4kKId+B3wfDW/TgqX6Hg/kUj8JO08wGe9JxtOEJ6XJA3cO/cSna9v3YVf/ssHTbXkb+bFgY7WLdHJyvF6lD/wfpY2ZnA1787ajtm+/aWWVMxDOwKuqIT1ZZ0Nw4=' | openssl enc -d -a -$Cipher -K 3336366137346362336339353964653137643631646233303539316333396431 2>/dev/null;echo $Cipher;done
```

![image-20240207210517549](./assets/image-20240207210517549.png)

##### 使用tribute_to_ippsec成功ssh登入saket用户

![image-20240207211100569](./assets/image-20240207211100569.png)

##### sudo -l

![image-20240207211635032](./assets/image-20240207211635032.png)

##### /tmp/challenge

![image-20240207212145515](./assets/image-20240207212145515.png)

#### 尝试内核提权【易】

##### 寻找漏洞

![image-20240207154327404](./assets/image-20240207154327404.png)

##### 查看使用方法

使用方法很简单，gcc编译加执行即可（靶机上也有gcc）

![image-20240207154526609](./assets/image-20240207154526609.png)

##### 下载45010.c

用户家目录下没法写文件，换到/tmp目录下写

![image-20240207155043989](./assets/image-20240207155043989.png)

##### 编译执行

![image-20240207155227603](./assets/image-20240207155227603.png)

### root.txt(flag)

![image-20240207155306300](./assets/image-20240207155306300.png)