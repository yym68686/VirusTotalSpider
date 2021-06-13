import os
import json
import time
import pyperclip # 读取剪贴板
import numpy as np
from selenium.webdriver.common.keys import Keys
from msedge.selenium_tools import EdgeOptions, Edge
from selenium.webdriver.common.action_chains import ActionChains

headers = {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36 Edg/85.0.564.41'
}

print('load data...')
lastpath = os.path.abspath(os.path.dirname(os.path.dirname(__file__))) + '/'
path = os.path.abspath(os.path.dirname(__file__)) + '/jsondir/'
csvpath = os.path.abspath(os.path.dirname(__file__)) + '/'
sha256set = np.loadtxt(lastpath + "overview.csv", delimiter=",", usecols=(8), dtype=str, skiprows=1)
print('finish data load...')

opt = EdgeOptions() # 使用基于Chromium内核的Microsoft Edge浏览器
opt.use_chromium = True
# opt.add_argument("headless") # 无头浏览器，如果运行出错请注释掉这句。
opt.add_argument("disable-gpu")
opt.add_experimental_option('excludeSwitches', ['enable-logging'])
driver = Edge(executable_path = lastpath + "msedgedriver.exe", options = opt)
i = 0
for filehash in sha256set[2069:2225]:
    if filehash != "":
        fileurl = 'https://www.virustotal.com/gui/file/' + filehash + '/behavior/VirusTotal%20Cuckoofork'
        window_handles = driver.window_handles
        driver.switch_to.window(window_handles[0])
        driver.get(fileurl)
        driver.implicitly_wait(7)
        driver.find_element_by_tag_name('body')
        time.sleep(2)
        print(driver.current_url)# 输出当前链接
        if driver.current_url == "https://www.virustotal.com/gui/captcha": # 检测是否被网站拦截，拦截了手动通过图形验证码限时60s
            ActionChains(driver).move_by_offset(342, 146).click().perform() # 自动点击，打开图形验证码
            ActionChains(driver).move_by_offset(-342, -146).perform()
            time.sleep(60) # 等待手动通过
        if "Cuckoofork" not in driver.current_url: # 不存在Cuckoofork文件则跳过此sha256
            continue
        ActionChains(driver).move_by_offset(34, 131).click().perform() # 点击下载文件
        ActionChains(driver).move_by_offset(-34, -131).perform()       # 恢复鼠标偏移
        time.sleep(2)
        if len(window_handles) != 1: # 检测当前几个浏览器标签页，这里需要保证网络通畅，否则可能出错
            driver.switch_to.window(window_handles[1]) # 切换窗口
            driver.find_element_by_tag_name('body') # 等待body元素出现
            ActionChains(driver).move_by_offset(1, 1).click().key_down(Keys.CONTROL).send_keys('a').send_keys('c').key_up(Keys.CONTROL).perform() # 点击浏览器，全选网页内容并复制到粘贴板，此时禁止其他复制行为
            ActionChains(driver).move_by_offset(-1, -1).perform() # 恢复偏移
            driver.close() # 关闭标签页
            data = pyperclip.paste()   # 将文本复制，并用文件保存下来
            if data != "1" and ("error" not in data) and ("info" in data): # 过滤不符合要求的文本
                pyperclip.copy("1") # 检测复制有效flag标记
                json_data = json.loads(data) # 加载json数据
                with open(path + filehash + '.json', 'w', encoding='UTF-8') as f: # 保存文件
                    json.dump(json_data, f, ensure_ascii=False)
                f.close()
            if "RecaptchaRequiredError" in data: # 检测到ip被ban，立即停止
                print("blocked")
                exit(0)
            time.sleep(5)
        print(i) # 显示当前是第多少个sha256已经完成下载
    i = i + 1