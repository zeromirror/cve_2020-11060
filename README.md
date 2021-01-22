# glpi_cve-2020-11060

对存在`CVE-2020-11060`的站点进行攻击



## Poc目录结构

-   `Poc.py`  ：攻击脚本）
-   `crcChanger` ： 用于构造特定crc的文件，在`Poc.py`中被调用
-   `payload` 
    -   `payload` ： 拥有一块不被压缩的phpwebshell，用于攻击的最后步骤
    -   `a` ： 动态生成，根据数据库dump的结果，生成相应的a文件，起到打开`<?=/*`的作用
-   `tmp_data`
    -   `log` ： 攻击的日志信息
    -   `wire`  ： 发出的`requests请求`的相关数据
    -   `xxx.html` ：每一次`requests`返回的response相关的信息
    -   `yyy` ：脚本运行过程中的临时文件



## 使用说明
1. 需要拥有目标glpi站点，可以编辑资产的权限账户
2. 将wifi资产数据备份，为了日后还原
3. 删除所有的wifi资产
4. 新建一条wifi路由数据，随便填入数据
5. 使用本脚本进行攻击，攻击方法如下
    `python3 Poc.py --host xxxx --cookie "yyyy" --webshell "zzz.php"`

<font color='red'>注意事项: </font>

	1. host参数请加上 `http/https`
	2. host参数为目标glpi的根目录
	3. cookie参数请加上 **引号**，因为如果有cookie中的分号会截断命令
	4. 最后的webshell路径为`zzz.php`
	5. 由于时间会影响生产的结果，所以有一定失败的概率，失败了请多试几次（换点文件名）
	6. 目前成功率`18/20`



### 环境配置

-   `python3`
    -   `requests` (安装方法： `pip3 install requests`)



### 参数

-   `--cookie/-C`<font color='red'>(必须)</font>
    -   使用指定的`cookie`
-   `--host/-H` <font color='red'>(必须)</font>
    -   对指定的`host`进行攻击
-   `--webshell/-W`<font color='red'>(必须)</font>
    -   最后生成的webshell的路径
-   `--proxy/-P`
    -   使用指定的 **http代理**（用于`burpsuit`）
