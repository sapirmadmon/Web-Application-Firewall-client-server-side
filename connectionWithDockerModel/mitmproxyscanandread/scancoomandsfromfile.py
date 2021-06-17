from mitmproxy.addons import export
from mitmproxy.addons.export import cleanup_request, pop_headers, request_content_for_console
import shlex
from mitmproxy import flow
from mitmproxy.io import FlowReader


def httpie(f: flow.Flow) -> str:
    request = cleanup_request(f)
    request = pop_headers(request)
    args = [request.url]
    cmd = ' '.join(shlex.quote(arg) for arg in args)
    if request.content:
        cmd += " <<< " + shlex.quote(request_content_for_console(request))
    return cmd


filename = '/Users/niralon/requests.mitm'

def makeCommands():
    with open(filename, 'rb') as fp:
        reader = FlowReader(fp)
        list=[]
        for flow in reader.stream():
            encoding = 'utf-8'
            list.append(httpie(flow))


    url_list=[]
    for l in list:
        i = l.find('?')
        if(i != -1 ):
            url_list.append(l[i+1:])
    #print(url_list)


    final=['']
    index=0
    for url in url_list:
        for c in url.split('%'):
            try:
                final[index] += chr(int(c[0:2], 16))
                final[index] += c[2:]
            except:
                pass
        index+=1
        final.append('')
    return(final)