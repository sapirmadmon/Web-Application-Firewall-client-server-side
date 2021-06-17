#Sapir you need to paste here the path of requests.mitm. I think c:/requests.mitm
#If you can't find the path, run a search.
#The file requests.mitm is created after you run the command mitmproxy -w +requests.mitm
from mitmproxy.addons import export
from mitmproxy.io import FlowReader

filename = '/Users/niralon/requests.mitm'

with open(filename, 'rb') as fp:
    reader = FlowReader(fp)
    list=[]
    for flow in reader.stream():
        encoding = 'utf-8'
        list.append(export.httpie_command(flow))

    for l in list:
        print(l)