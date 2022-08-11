# butterfly
这是一款信息收集工具


该工具参数列表如下图
![参数列表](https://github.com/wz-wsl/butterfly/blob/main/info.PNG)
支持  端口扫描  目录扫描  子域名扫描  js文件扫描

其中端口扫描和子域名扫描是利用了phpinfo.me和tool.box3.cn这两个网站进行被动信息收集

![port](https://github.com/wz-wsl/butterfly/blob/main/port.PNG)
python butterfly.py -ps http://www.baid.com
这是扫描成果，端口是工具里写的常用端口

如果想扫描其他端口，请在工具里添加或者利用psm和dsm这两个参数进行指定端口范围
例如 python butterfly.py -ps http://www.baidu.com -psm 79 -dsm  81
这串指令的意思是扫描79到81之间的端口

![domain](https://github.com/wz-wsl/butterfly/blob/main/domain.PNG)
这是子域名扫描
python butterfly.py -do http://www.baidu.com

![js](https://github.com/wz-wsl/butterfly/blob/main/js.PNG)
这是js文件扫描
python butterfly.py -js http://www.baidu.com

![f](https://github.com/wz-wsl/butterfly/blob/main/dir.PNG)
这是目录扫描
python butterfly.py -ds http://www.baidu.com -f 字典路径
