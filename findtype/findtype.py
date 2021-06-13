import os
import time
import numpy as np
import pandas as pd
from selenium.webdriver.common.keys import Keys
from msedge.selenium_tools import EdgeOptions, Edge
from selenium.webdriver.common.action_chains import ActionChains

# 所有类型的文件字典
filetypeSet = {"EXE": "EXE", "DLL": "DLL", "Office Open XML Document": "DOCX", "RAR": "RAR", "PDF": "PDF", "Rich": "RTF", "PowerPoint": "PPT", "PostScript": "PostScript", "Outlook": "Outlook", "VBA": "VBA", "unknown": "unknown", "ZIP": "ZIP", "Office Open XML Spreadsheet": "XLSX", "MS Excel Spreadsheet": "XLX", "MS Word Document": "DOC", "ELF": "ELF", "Mach-O": "Mach-O"}
headers = {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36 Edg/85.0.564.41'
}
print('load data...')
lastpath = os.path.abspath(os.path.dirname(os.path.dirname(__file__))) + '/'
csvpath = os.path.abspath(os.path.dirname(__file__)) + '/'
x_train = np.loadtxt(lastpath + "overview.csv", delimiter=",", usecols=(0, 1), dtype=str, skiprows=1)
sha256set = np.loadtxt(lastpath + "overview.csv", delimiter=",", usecols=(8), dtype=str, skiprows=1)
print('finish data load...')

opt = EdgeOptions()
opt.use_chromium = True
# opt.add_argument("headless")
opt.add_argument("disable-gpu")
opt.add_experimental_option('excludeSwitches', ['enable-logging'])
driver = Edge(executable_path = lastpath + "msedgedriver.exe", options = opt)

i = 0
for filehash in sha256set:
    i += 1
    if filehash == '': # 没有sha256
        with open(csvpath + 'success.csv', 'a') as f:
            f.write("no" +'\n')
        f.close()
    else:
        fileurl = "https://www.virustotal.com/gui/file/" + filehash + "/details"
        try:
            shanow = 0
            df = 0
            notfound = 0
            while shanow != filehash: # 复制失败，就会一直尝试这个sha256，直到这个sha256复制成功，成功得到文件类型。
                driver.get(fileurl)
                driver.implicitly_wait(7)
                length = 10
                high = 200
                driver.find_element_by_tag_name('body')
                if driver.current_url == "https://www.virustotal.com/gui/captcha":
                    ActionChains(driver).move_by_offset(342, 146).click().perform()
                    ActionChains(driver).move_by_offset(-342, -146).perform()
                    time.sleep(60)
                if driver.current_url == "https://www.virustotal.com/gui/item-not-found":
                    notfound = 1
                    break
                driver.find_element_by_tag_name('body')
                ActionChains(driver).move_by_offset(length, high).click().click().key_down(Keys.CONTROL).send_keys('a').key_up(Keys.CONTROL).perform()
                # ActionChains(driver).move_by_offset(length, high).click().click().key_down(Keys.CONTROL).send_keys('a').send_keys('a').key_up(Keys.CONTROL).perform()
                ActionChains(driver).move_by_offset(-length, -high).key_down(Keys.CONTROL).send_keys('c').key_up(Keys.CONTROL).perform()
                df = pd.read_clipboard(header=None).values
                filetype = 0
                typenow = 0
                for typename in df:
                    if "File type" in typename:
                        filetype = list(typename)[1]
                        typenow = typename
                    if "SHA-256" in typename:
                        shanow = list(typename)[1]

            if notfound == 1:
                with open(csvpath + 'success.csv', 'a') as f:
                    f.write("no" + '\n')
                f.close()
                continue

            if df[1][1] == "learn":
                with open(csvpath + 'success.csv', 'a') as f:
                    f.write("no" + '\n')
                f.close()
                continue

            with open(csvpath + 'log.txt', 'a') as f:
                    f.write(str(typenow) + " " + str(shanow) + '\n')
            f.close()
            notype = 0
            for filetypeitem, filevalue in filetypeSet.items():
                if filetypeitem in filetype:
                    print(i)
                    with open(csvpath + 'success.csv', 'a') as f:
                        f.write(str(filevalue) +'\n')
                    f.close()
                    notype = 1
                    break
            if notype == 0:
                with open(csvpath + 'success.csv', 'a') as f:
                    f.write("try " + filehash + '\n')
                f.close()
                print("failed", filehash)
        except:
            print("failed")
            with open(csvpath + 'success.csv', 'a') as f:
                f.write("failed " + filehash + '\n') # 对于获取失败的文件类型，完成后需要手动查询
            f.close()
            with open(csvpath + 'log.txt', 'a') as f:
                    f.write("error " + filehash + '\n')
            f.close()