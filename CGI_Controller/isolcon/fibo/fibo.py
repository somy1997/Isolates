#!/usr/bin/env python3

# import os
import cgi
# import sys
# import json

print("Content-Type: text/html")    # HTML is following
print()                             # blank line, end of headers

# For JSON input :
# content_len = int(os.environ["CONTENT_LENGTH"])
# req_body = sys.stdin.read(content_len)
# event = json.loads(req_body)
# n = event['input']

# For query string input :
n = int(cgi.FieldStorage().getvalue('input'))

def fibo(n) :
    a = 0
    b = 1
    c = 0
    for _ in range(n-1) :
        c = a + b
        a = b
        b = c
    return a

print(fibo(n))


