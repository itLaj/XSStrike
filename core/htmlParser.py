import re

from core.config import badTags, xsschecker
from core.utils import isBadContext, equalize, escaped, extractScripts

#解析html 检测我们的输入输出到html哪种环境
def htmlParser(response, encoding):
    rawResponse = response  # raw response returned by requests 请求返回的原始响应
    response = response.text  # response content
    if encoding:  # if the user has specified an encoding, encode the probe in that 如果用户指定了编码，则使用该编码对探测器进行编码
        response = response.replace(encoding(xsschecker), xsschecker)
        # replace() 把字符串中的 old（旧字符串） 替换成 new(新字符串)，如果指定第三个参数max，则替换不超过 max 次。
    reflections = response.count(xsschecker)#用于统计字符串里某个字符 xsschecker 出现的次数
    position_and_context = {} #位置上下文
    environment_details = {} #环境细节
    clean_response = re.sub(r'<!--[.\s\S]*?-->', '', response) #re.sub用于替换字符串中的匹配项 去掉标签
    #[\s\S]*?表示匹配任意字符，且只匹配一次，即懒惰匹配； [\s\S]*没有带?号，也表示匹配任意字符，但允许匹配任意次，即贪婪匹配。
    script_checkable = clean_response
    for script in extractScripts(script_checkable):
        occurences = re.finditer(r'(%s.*?)$' % xsschecker, script)
        #re.finditer(pattern, string, flags=0)返回一个产生匹配对象实体的迭代器，能产生字符串中所有RE模式串的非重叠匹配。
        #字符串被从左向右扫描，匹配按发现顺序返回。空字符串被包括在结果中除非它们触碰到另一个匹配的开头。
        #flags参数是可选参数。如果向它传递re模块中的宏常量，就会对匹配方式产生对应的影响。
        if occurences:
            for occurence in occurences:
                thisPosition = occurence.start(1)
                position_and_context[thisPosition] = 'script'
                environment_details[thisPosition] = {}
                environment_details[thisPosition]['details'] = {'quote' : ''}
                for i in range(len(occurence.group())):
                    #group()返回一个或多个匹配的字串。如果只有一个参数，结果只有单个字符串；如果有多个参数，结果是一个元组，元组里每一项对应一个参数。
                    # 没有参数，group1默认是0（整个匹配串被返回）。如果groupN参数是0，对应的返回值是整个匹配串；如果它属于[1，99]，返回对应的一项括号分隔的群。
                    # 如果参数是负数或大于模式串中定义的群数，IndexError异常会被抛出。如果模式串没有任何匹配，group返回None；如果模式串多次匹配，group将返回最后一次匹配。
                    currentChar = occurence.group()[i]
                    if currentChar in ('/', '\'', '`', '"') and not escaped(i, occurence.group()):#编码
                        environment_details[thisPosition]['details']['quote'] = currentChar
                    elif currentChar in (')', ']', '}', '}') and not escaped(i, occurence.group()):
                        break
                script_checkable = script_checkable.replace(xsschecker, '', 1)#replace("is", "was", 3)返回字符串中的 old（旧字符串） 替换成 new(新字符串)后生成的新字符串，如果指定第三个参数max，则替换不超过 max 次。
    if len(position_and_context) < reflections:
        attribute_context = re.finditer(r'<[^>]*?(%s)[^>]*?>' % xsschecker, clean_response)
        for occurence in attribute_context:
            match = occurence.group(0)
            thisPosition = occurence.start(1)
            parts = re.split(r'\s', match)# \s用于匹配空白字符。
            tag = parts[0][1:]
            for part in parts:
                if xsschecker in part:
                    Type, quote, name, value = '', '', '', ''
                    if '=' in part:
                        quote = re.search(r'=([\'`"])?', part).group(1)
                        name_and_value = part.split('=')[0], '='.join(part.split('=')[1:])
                        if xsschecker == name_and_value[0]:
                            Type = 'name'
                        else:
                            Type = 'value'
                        name = name_and_value[0]
                        value = name_and_value[1].rstrip('>').rstrip(quote).lstrip(quote)
                    else:
                        Type = 'flag'
                    position_and_context[thisPosition] = 'attribute'
                    environment_details[thisPosition] = {}
                    environment_details[thisPosition]['details'] = {'tag' : tag, 'type' : Type, 'quote' : quote, 'value' : value, 'name' : name}
    if len(position_and_context) < reflections:
        html_context = re.finditer(xsschecker, clean_response)
        for occurence in html_context:
            thisPosition = occurence.start()
            if thisPosition not in position_and_context:
                position_and_context[occurence.start()] = 'html'
                environment_details[thisPosition] = {}
                environment_details[thisPosition]['details'] = {}
    if len(position_and_context) < reflections:
        comment_context = re.finditer(r'<!--[\s\S]*?(%s)[\s\S]*?-->' % xsschecker, response)
        for occurence in comment_context:
            thisPosition = occurence.start(1)
            position_and_context[thisPosition] = 'comment'
            environment_details[thisPosition] = {}
            environment_details[thisPosition]['details'] = {}
    database = {}
    for i in sorted(position_and_context):
        database[i] = {}
        database[i]['position'] = i
        database[i]['context'] = position_and_context[i]
        database[i]['details'] = environment_details[i]['details']

    bad_contexts = re.finditer(r'(?s)(?i)<(style|template|textarea|title|noembed|noscript)>[.\s\S]*(%s)[.\s\S]*</\1>' % xsschecker, response)
    non_executable_contexts = []
    for each in bad_contexts:
        non_executable_contexts.append([each.start(), each.end(), each.group(1)])

    if non_executable_contexts:
        for key in database.keys():
            position = database[key]['position']
            badTag = isBadContext(position, non_executable_contexts)
            if badTag:
                database[key]['details']['badTag'] = badTag
            else:
                database[key]['details']['badTag'] = ''
    return database
