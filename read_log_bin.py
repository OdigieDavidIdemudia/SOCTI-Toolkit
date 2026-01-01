
import os

try:
    with open('error.log', 'rb') as f:
        content = f.read()
        # try decoding as utf-16
        try:
            print(content.decode('utf-16'))
        except:
             print(content.decode('utf-8', errors='ignore'))
except Exception as e:
    print(e)
