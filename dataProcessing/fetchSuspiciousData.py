import pandas as pd
import configparser
from requests import get, post

config = configparser.ConfigParser()
config.read_file(open('settings.ini'))
ip = config['settings']['remote_ip']
port = config['settings']['remote_port']

suspiciousObjs = []
url = f"http://{ip}:{port}/tshark/_search?scroll=1m"
url2 = f"http://{ip}:{port}/_search/scroll"
headers = {'Content-Type': 'application/json'}

def fetchRecursive(response):
    try:
        if len(response['hits']['hits']) == 10000:
            for obj in response['hits']['hits']:
                suspiciousObjs.append(obj['_source'].copy())
                
            scrollId = response['_scroll_id']
            data = '{"scroll": "1m", "scroll_id": "' + str(scrollId) + '"}'
            response2 = get(url2, headers=headers, data=data).json()
            fetchRecursive(response2)

    except Exception as e:
        print(e)

res = get(url, headers=headers, data='{"size": 10000}').json()

fetchRecursive(res)

df = pd.DataFrame(suspiciousObjs)
df.to_csv('tmpData/suspiciousData.csv', index=None)