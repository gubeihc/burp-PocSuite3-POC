# -*-coding:utf-8 -*-
from burp import IBurpExtender, IScannerCheck
from burp import IMessageEditorTabFactory, IContextMenuFactory
from javax.swing import JMenuItem, JOptionPane
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
import json
import re
from urlparse import urlparse

class BurpExtender(IBurpExtender, IScannerCheck, IMessageEditorTabFactory, IContextMenuFactory):
    def __init__(self):
        self.pattern_text = ''
        self.matchmode = ''
        self.re_text='''
            flag=re.findall("xxx",response.text)
            if flag:
                result["url"] = response.url
                result["flag"] = flag[0]
            if result:
                output.success(result)
            return output        
        '''
        self.in_text='''    
            flag="xxx"
            if flag in response.text:
                result["url"] = response.url
                result["flag"] = flag
            if result:
                output.success(result)
            return output        '''
        self.moban_get=''
        self.moban_post=''
        self.path=''
        self.post_mode=''


    def registerExtenderCallbacks(self, callbacks):
        print("@author: gubei")
        print("burp to pocsuite code")
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        # 这里是插件加载的名称
        self._callbacks.setExtensionName("copy-poc")
        callbacks.registerMessageEditorTabFactory(self)
        callbacks.registerContextMenuFactory(self)

        # 创建按钮函数

    def createMenuItems(self, invocation):
        self.menus = []
        self.invocation = invocation
        self.menus.append(JMenuItem("poc-template", None, actionPerformed=lambda x: self.run(x)))
        return self.menus

    def stripTrailingNewlines(self, data):
        while data[-1] in (10, 13):
            data = data[:-1]
        return data
    def run(self, x):

        currentRequest = self.invocation.getSelectedMessages()[0]
        requestInfo = self._helpers.analyzeRequest(currentRequest)
        header = ''
        self.httpRequest = currentRequest.getRequest()
        self.headers = requestInfo.getHeaders()
        self.getMethod = requestInfo.getMethod()
        self.getUrl = requestInfo.getUrl()
        self.server = currentRequest.getHttpService()
        self.Request = self.stripTrailingNewlines(self.httpRequest)
        self.reqBodys = currentRequest.getRequest()[requestInfo.getBodyOffset():].tostring()
        self.exclude = ["Accept-Encoding", "Sec-Ch-Ua", "Host", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User",
                   "Sec-Fetch-Dest", "Sec-Ch-Ua-Mobil", "Sec-Ch-Ua-Platform", "Sec-Ch-Ua-Mobile", "sec-ch-ua",
                   "sec-ch-ua-mobile", "sec-ch-ua-platform", ]
        if x.getSource().text == 'poc-template':
            if self.getMethod == "GET":
                self.path = str(self.getUrl).replace(str(urlparse(str(self.getUrl)).scheme) + "://"+ str(urlparse(str(self.getUrl)).netloc),"")
                for u in self.headers[1:]:
                    key = u.split(": ")[0]
                    value = "".join((u.split(": ")[1:]))
                    if key in self.exclude:
                        pass
                    else:
                        e = '"' + key + '"' + ":" + '"' + value.replace('"', '\\"') + '"' + ","
                        header = header + e + '\n'
                # 这里是get 模版
                matchpattern = JOptionPane.showInputDialog("matchpattern:")
                self.matchmode = str(matchpattern).split(" ")[0]
                if self.matchmode == "in":
                    self.pattern_text = str(matchpattern).split(" ")[1]
                    if '"' or  "'" in self.pattern_text:
                        self.pattern_text=self.pattern_text.replace('"',r"\"") or self.pattern_text.replace("'",r"\'")
                    self.in_text=self.in_text.replace("xxx",self.pattern_text)
                    self.moban_get = """
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
)
import re
from urllib.parse import urlparse

from pocsuite3.lib.core.poc import Output
minimum_version_required('1.9.8')
class DemoPOC(POCBase):
    vulID = '123'
    version = '1'
    author = 'gubei'
    vulDate = '2022-08-08'
    createDate = '2022-08-08'
    updateDate = '2022-08-08'
    references = []
    name = 'test'
    appPowerLink = ''
    appName = ''
    appVersion = ''
    vulType = 'SQL Injection'
    desc = 'Vulnerability description'
    samples = ['']
    install_requires = ['']
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': ''}
    suricata_request = ''
    suricata_response = ''
    def urlstr(self,url: str):
        if url:

            data = urlparse(url)
            try:
                if data.scheme:
                    urls = data.scheme + "://" + data.netloc
                else:
                    urls = "http://" + data.path.split("/")[0]
                    print(urls)
                return urls
            except Exception as e:
                pass
        else:
            pass
    def _verify(self):
        result = {}
        headers={
        %s
        }
        output = Output(self)
        url=self.urlstr(self.url)
        url = url + str("%s")
        try:
            response = requests.get(url,headers=headers)  
            %s
        except Exception as e:
            pass
    def _attack(self):
        result = {}
        result['VerifyInfo'] = {}
        result['VerifyInfo']['URL'] = self.url
        return self.parse_output(result)
    def _shell(self):
        return self._verify()
register_poc(DemoPOC)                

                                    """ % (header, self.path, self.in_text)
                elif self.matchmode == "re":
                    self.pattern_text = str(matchpattern).split(" ")[1]
                    self.re_text=self.re_text.replace("xxx",self.pattern_text)
                    if '"' or  "'" in self.pattern_text:
                        self.pattern_text=self.pattern_text.replace('"',r"\"") or self.pattern_text.replace("'",r"\'")
                    self.moban_get = """
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
)

from urllib.parse import urlparse
from pocsuite3.lib.core.poc import Output
minimum_version_required('1.9.8')
class DemoPOC(POCBase):
    vulID = '123'
    version = '1'
    author = 'gubei'
    vulDate = '2022-08-08'
    createDate = '2022-08-08'
    updateDate = '2022-08-08'
    references = []
    name = 'test'
    appPowerLink = ''
    appName = ''
    appVersion = ''
    vulType = 'SQL Injection'
    desc = 'Vulnerability description'
    samples = ['']
    install_requires = ['']
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': ''}
    suricata_request = ''
    suricata_response = ''
    def urlstr(self,url: str):
        if url:
            data = urlparse(url)
            try:
                if data.scheme:
                    urls = data.scheme + "://" + data.netloc
                else:
                    urls = "http://" + data.path.split("/")[0]
                    print(urls)
                return urls
            except Exception as e:
                pass
        else:
            pass
    def _verify(self):
        result = {}
        headers={
        %s
        }
        output = Output(self)
        url=self.urlstr(self.url)
        url = url + str("%s")
        try:
            response = requests.get(url,headers=headers)  
            %s
        except Exception as e:
            pass
    def _attack(self):
        result = {}
        result['VerifyInfo'] = {}
        result['VerifyInfo']['URL'] = self.url
        return self.parse_output(result)
    def _shell(self):
        return self._verify()
register_poc(DemoPOC)
                                    """ % (header, self.path, self.re_text)
                else:
                    print("match pattern error")
                # 这里是 给生成好的模版复制到系统粘贴上 直接粘贴
                systemClipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
                transferText = StringSelection(self.moban_get)
                systemClipboard.setContents(transferText, None)
                print("GET请求复制完成，请粘贴到ide 执行")
                print("copy ok!!!")
                self.re_text = '''
            flag=re.findall("xxx",response.text)
            if flag:
                result["url"] = response.url
                result["flag"] = flag[0]
            if result:
                output.success(result)
            return output        
                        '''
                self.in_text = '''    
            flag="xxx"
            if flag in response.text:
                result["url"] = response.url
                result["flag"] = flag
            if result:
                output.success(result)
            return output        '''
                # 这里是post 模版
            elif self.getMethod == "POST":
                self.data={}
                self.path = str(self.getUrl).replace(str(urlparse(str(self.getUrl)).scheme) + "://"+ str(urlparse(str(self.getUrl)).netloc),"")
                for u in self.headers[1:]:
                    key = u.split(": ")[0]
                    value = "".join((u.split(": ")[1:]))
                    if key in self.exclude:
                        pass
                    else:
                        e = '"' + key + '"' + ":" + '"' + value.replace('"', '\\"') + '"' + ","
                        header = header + e + '\n'
                try:
                    if json.loads(self.reqBodys) and '{' in self.reqBodys:
                        print("is ok json post  测试 ")
                        self.post_mode="json"
                        self.data=json.loads(self.reqBodys)
                        print(self.data,type(self.data))
                    else:
                        print("nononono")
                        self.data={}
                except:
                    self.post_mode="data"
                    print("is ok data post")
                    split_body_param = self.reqBodys.split('&')
                    for body_param in split_body_param:
                        print(split_body_param,"&")
                        if '=' in body_param and len(body_param.split('=')) == 2:
                            post_key, post_value = body_param.split('=')
                            urldecode_value = self._helpers.urlDecode(post_value)
                            self.data[post_key]=urldecode_value
                            print(post_key,urldecode_value,"======")
                matchpattern = JOptionPane.showInputDialog("matchpattern:")
                self.matchmode = str(matchpattern).split(" ")[0]
                if self.matchmode == "in":
                    self.pattern_text = str(matchpattern).split(" ")[1]
                    if '"' or  "'" in self.pattern_text:
                        self.pattern_text=self.pattern_text.replace('"',r"\"") or self.pattern_text.replace("'",r"\'")
                    self.in_text = self.in_text.replace("xxx", self.pattern_text)
                    self.moban_post='''
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
)
from pocsuite3.lib.core.poc import Output
from urllib.parse import urlparse


minimum_version_required('1.9.8')


class DemoPOC(POCBase):
    vulID = '123'
    version = '1'
    author = 'gubei'
    vulDate = '2022-08-08'
    createDate = '2022-08-08'
    updateDate = '2022-08-08'
    references = []
    name = 'test'
    appPowerLink = ''
    appName = ''
    appVersion = ''
    vulType = 'SQL Injection'
    desc = 'Vulnerability description'
    samples = ['']
    install_requires = ['']
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': ''}
    suricata_request = ''
    suricata_response = ''
    def urlstr(self,url: str):
        if url:
    
            data = urlparse(url)
            try:
                if data.scheme:
                    urls = data.scheme + "://" + data.netloc
                else:
                    urls = "http://" + data.path.split("/")[0]
                    print(urls)
                return urls
            except Exception as e:
                pass
        else:
            pass
    def _verify(self):
        result = {}
        headers = {%s}
        output = Output(self)
        url=self.urlstr(self.url)
        url = url + str("%s")
        data=%s
        try:
            response = requests.post(url, headers=headers,%s=data)
            %s
        except Exception as e:
            pass
        


    def _attack(self):
        result = {}
        result['VerifyInfo'] = {}
        result['VerifyInfo']['URL'] = self.url
        return self.parse_output(result)

    def _shell(self):
        return self._verify()


register_poc(DemoPOC)

                '''%(header,self.path,self.data,self.post_mode,self.in_text)
                elif self.matchmode == "re":
                    self.pattern_text = str(matchpattern).split(" ")[1]
                    if '"' or  "'" in self.pattern_text:
                        self.pattern_text=self.pattern_text.replace('"',r"\"") or self.pattern_text.replace("'",r"\'")
                    self.re_text=self.re_text.replace("xxx",self.pattern_text)
                    self.moban_post = '''
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pocsuite3.api import (
    minimum_version_required, POCBase, register_poc, requests, logger,
)
from pocsuite3.lib.core.poc import Output
from urllib.parse import urlparse
import re

minimum_version_required('1.9.8')

class DemoPOC(POCBase):
    vulID = '123'
    version = '1'
    author = 'gubei'
    vulDate = '2022-08-08'
    createDate = '2022-08-08'
    updateDate = '2022-08-08'
    references = []
    name = 'test'
    appPowerLink = ''
    appName = ''
    appVersion = ''
    vulType = 'SQL Injection'
    desc = 'Vulnerability description'
    samples = ['']
    install_requires = ['']
    pocDesc = 'User manual of poc'
    dork = {'zoomeye': ''}
    suricata_request = ''
    suricata_response = ''
    def urlstr(self,url: str):
        if url:
    
            data = urlparse(url)
            try:
                if data.scheme:
                    urls = data.scheme + "://" + data.netloc
                else:
                    urls = "http://" + data.path.split("/")[0]
                    print(urls)
                return urls
            except Exception as e:
                pass
        else:
            pass
    def _verify(self):
        result = {}
        headers = {%s}
        output = Output(self)
        url=self.urlstr(self.url)
        url = url + str("%s")
        data=%s
        try:
            response = requests.post(url, headers=headers,%s=data)
            %s
        except Exception as e:
            pass
    def _attack(self):
        result = {}
        result['VerifyInfo'] = {}
        result['VerifyInfo']['URL'] = self.url
        return self.parse_output(result)
    def _shell(self):
        return self._verify()
register_poc(DemoPOC)                    
                                    ''' % (header, self.path, self.data, self.post_mode,self.re_text)
                systemClipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
                transferText = StringSelection(self.moban_post)
                systemClipboard.setContents(transferText, None)
                self.re_text = '''
            flag=re.findall("xxx",response.text)
            if flag:
                result["url"] = response.url
                result["flag"] = flag[0]
            if result:
                output.success(result)
            return output        
                                        '''
                self.in_text = '''    
            flag="xxx"
            if flag in response.text:
                result["url"] = response.url
                result["flag"] = flag
            if result:
                output.success(result)
            return output        '''
                print("POST请求复制完成，请粘贴到ide 执行")
                print("copy ok!!!")

