from mitmproxy.io import FlowReader
from mitmproxy.addons import export



filename = '/Users/niralon/requests.mitm'

with open(filename, 'rb') as fp:
    reader = FlowReader(fp)

    for flow in reader.stream():
        print(export.cleanup_request(flow))