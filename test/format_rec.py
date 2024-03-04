import re

def parse_logs(logs):
    # 定义正则表达式模式，用于匹配时间、日期和其他内容
    time_pattern = r'\d{2}:\d{2}:\d{2}\.\d{9}'
    date_pattern = r'\[\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4}\]'
    context_pattern = r'\b\w+\b'
    
    # 正则表达式模式的编译
    time_regex = re.compile(time_pattern)
    date_regex = re.compile(date_pattern)
    context_regex = re.compile(context_pattern)
    
    # 迭代日志
    for log in logs:
        # 使用正则表达式模式匹配时间、日期和其他内容
        time_match = time_regex.search(log)
        date_match = date_regex.search(log)
        context_match = context_regex.search(log)
        
        # 如果找到匹配项，则替换为相应的字段名
        if time_match:
            log = log.replace(time_match.group(), "<time>")
        if date_match:
            log = log.replace(date_match.group(), "<date>")
        if context_match:
            log = log.replace(context_match.group(), "<context>")
        
        # 生成替换后的日志
        yield log

# 假设logs是一个包含日志行的列表
logs = [
    "01:40:19.601661779 1 httpd (7513) > open",
    "10.35.35.118 - - [19/Jan/2022:08:41:07 +0000] \"POST /wp-admin/admin-ajax.php HTTP/1.1\" 200 1168 \"https://intranet.price.fox.org/wp-admin/edit.php\" \"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:86.0) Gecko/20100101 Firefox/86.0\""
]

# 使用生成器解析和替换日志
parsed_logs = parse_logs(logs)

# 打印替换后的日志
for log in parsed_logs:
    print(log)