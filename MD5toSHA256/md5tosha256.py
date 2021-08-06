import os
import re
import time
import numpy as np
from msedge.selenium_tools import EdgeOptions, Edge

headers = {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36 Edg/85.0.564.41'
}

print('load data...')
rootpath = os.path.abspath(os.path.join(os.getcwd(), "..")) + '/'
sha256set = np.loadtxt(rootpath + "overview.csv", delimiter=",", usecols=(0), dtype=str, skiprows=1) # usecols=(0) 0表示hash值是第0列，这个需要按情况做修改。
print('finish data load...')

opt = EdgeOptions() # 使用基于Chromium内核的Microsoft Edge浏览器，其他浏览器需要看情况更改
opt.use_chromium = True
# opt.add_argument("headless") # 无头浏览器，如果运行出错请注释掉这句。
opt.add_argument("disable-gpu")
opt.add_experimental_option('excludeSwitches', ['enable-logging'])
driver = Edge(executable_path = rootpath + "msedgedriver.exe", options = opt) # 这里msedgedriver.exe需要跟下载的webdriver名字对应，默认在项目文件根目录
for filehash in sha256set:
    noerror = 1
    while(noerror):
        try:
            fileurl = 'https://www.virustotal.com/gui/file/' + filehash + '/behavior/VirusTotal%20Cuckoofork'
            driver.get(fileurl)
            driver.implicitly_wait(7)
            driver.find_element_by_tag_name('body')
            time.sleep(1.5)
            print(driver.current_url)
            matchresult = re.findall(r"file.(.*?).detection", driver.current_url, re.M)
            with open(os.getcwd() + '/sha256.txt', 'a+', encoding='UTF-8') as f: # 保存文件
                f.write(matchresult[0] + '\n')
            f.close()
            noerror = 0
        except:
            noerror = 1
