import copy
import re

import core.config
from core.colors import red, good, green, end
from core.config import xsschecker
from core.filterChecker import filterChecker
from core.generator import generator
from core.htmlParser import htmlParser
from core.requester import requester
from core.log import setup_logger

logger = setup_logger(__name__)
#核心 ，python爬取了页面中所有的链接和表单信息

def crawl(scheme, host, main_url, form, blindXSS, blindPayload, headers, delay, timeout, encoding):
    if form:
        for each in form.values():
            url = each['action']
            if url:
                if url.startswith(main_url):#startswith用来判断当前字符串是否是以另外一个给定的子字符串“开头”的，根据判断结果返回 true 或 false
                    pass
                elif url.startswith('//') and url[2:].startswith(host):#[2:]代表url列表中第2+1项到最后一项
                    url = scheme + '://' + url[2:]#scheme代表默认协议http/https
                elif url.startswith('/'):
                    url = scheme + '://' + host + url
                    #'\w'匹配字母或数字或下划线或汉字0-9、a-z、A-Z、_（下划线）、汉字和其他国家的语言符号
                elif re.match(r'\w', url[0]):
                    url = scheme + '://' + host + '/' + url
                if url not in core.config.globalVariables['checkedForms']:
                    core.config.globalVariables['checkedForms'][url] = []
                method = each['method']
                GET = True if method == 'get' else False
                inputs = each['inputs']
                paramData = {}
                for one in inputs:
                    paramData[one['name']] = one['value']
                    for paramName in paramData.keys():
                        if paramName not in core.config.globalVariables['checkedForms'][url]:
                            core.config.globalVariables['checkedForms'][url].append(paramName)
                            paramsCopy = copy.deepcopy(paramData)
                            paramsCopy[paramName] = xsschecker
                            response = requester(
                                url, paramsCopy, headers, GET, delay, timeout)
                            occurences = htmlParser(response, encoding)
                            positions = occurences.keys()
                            #验证方式是判断generator函数是否生成了payload
                            efficiencies = filterChecker(
                                url, paramsCopy, headers, GET, delay, occurences, timeout, encoding)
                            vectors = generator(occurences, response.text)
                            if vectors:
                                for confidence, vects in vectors.items():
                                    try:
                                        payload = list(vects)[0]
                                        logger.vuln('Vulnerable webpage: %s%s%s' %
                                                    (green, url, end))
                                        logger.vuln('Vector for %s%s%s: %s' %
                                                    (green, paramName, end, payload))
                                        break
                                    except IndexError:
                                        pass
                            if blindXSS and blindPayload:
                                paramsCopy[paramName] = blindPayload
                                requester(url, paramsCopy, headers,
                                          GET, delay, timeout)
