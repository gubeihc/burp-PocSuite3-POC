# burp-PocSuite3-POC

## 使用说明 burp插件 需要添加 jython-standalone-2.7.1.jar 环境 加载插件

![image](https://github.com/gubeihc/burp-PocSuite3-POC/blob/main/image/1.png)


## 这样就加载成功了 Errors 错误不影响使用，我也不会修改，有会的哥哥带带我
![image](https://github.com/gubeihc/burp-PocSuite3-POC/blob/main/image/2.png)


## 这里就写了 PocSuite3 poc模版，


## 然后有两种模式， in 和re  用来匹配  response 可以自行修改添加其他模式、或者提需求。

### 模式1 in空格xxx字符串用来匹配 字符串是否 在请求响应体里面
![image](https://github.com/gubeihc/burp-PocSuite3-POC/blob/main/image/3.png)
![image](https://github.com/gubeihc/burp-PocSuite3-POC/blob/main/image/4.png)
![image](https://github.com/gubeihc/burp-PocSuite3-POC/blob/main/image/5.png)



### 模式2 re空格xxx通过正则来匹配字符串是否在响应体里面

![image](https://github.com/gubeihc/burp-PocSuite3-POC/blob/main/image/6.png)
![image](https://github.com/gubeihc/burp-PocSuite3-POC/blob/main/image/7.png)


# 生成的代码保存到本地任意空白py文件
# 这只是一个最简单的请求模版，代码放github了 各位可以根据自己的需求自定义

# 通过 pocsuite -r xxx.py -u xxx 来调用
