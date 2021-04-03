import copy
#copy模块提供了通用的浅层复制和深层复制操作
from urllib.parse import urlparse, unquote
#urlparse可以实现url的识别和分段，分为 URL parsing (网址解析）和URL quoting（地址引用）
#URL只允许一部分ASCII字符，其他字符（如汉字）是不符合标准的，此时就要进行编码。
# URL引用函数侧重于获取程序数据，并通过引用特殊字符和适当地编码非ASCII文本来使其作为URL组件安全使用。它们还支持逆转这些操作，
# 以使URL组件的内容重新创建原始数据，如果上述URL解析函数未覆盖该任务的话。
from core.colors import good, green, end
from core.requester import requester
from core.utils import getUrl, getParams
from core.log import setup_logger

logger = setup_logger(__name__)

#遍历每个参数 --利用用户自己提供的payload求暴力破解测试每一个参数
def bruteforcer(target, paramData, payloadList, encoding, headers, delay, timeout):
    GET, POST = (False, True) if paramData else (True, False)
    host = urlparse(target).netloc  # Extracts host out of the url 从地址中解析出主机地址
    #logger=>handler=>formatter分别是一对多的关系，日志的格式其实是由formatter决定的，
    # 所以想要扩展成你想要的各种格式，就重写定制formatter组件就可以了，它实际上和Java里面Log4j的LayOut组件类似。
    logger.debug('Parsed host to bruteforce: {}'.format(host))#解析主机 格式化字符串的函数 str.format()，它增强了字符串格式化的功能
    url = getUrl(target, GET)
    logger.debug('Parsed url to bruteforce: {}'.format(url))#解析URL 格式化字符串的函数 str.format()，它增强了字符串格式化的功能
    params = getParams(target, paramData, GET)#解析参数
    logger.debug_json('Bruteforcer params:', params)
    if not params:
        logger.error('No parameters to test.')#没有参数可以测试了
        quit()#退出
    for paramName in params.keys():
        progress = 1  
        paramsCopy = copy.deepcopy(params)#深拷贝
        for payload in payloadList:
            logger.run('Bruteforcing %s[%s%s%s]%s: %i/%i\r' %
                       (green, end, paramName, green, end, progress, len(payloadList)))
            if encoding:
                payload = encoding(unquote(payload)) #编码payload
            paramsCopy[paramName] = payload
            response = requester(url, paramsCopy, headers,
                                 GET, delay, timeout).text
            if encoding:
                payload = encoding(payload)
            if payload in response:
                logger.info('%s %s' % (good, payload))
            progress += 1
    logger.no_format('')
