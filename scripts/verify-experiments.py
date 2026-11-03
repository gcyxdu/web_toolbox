import urllib.request,json,time
base='http://127.0.0.1:8090'
def get(path):return json.load(urllib.request.urlopen(base+path))
for name in ['tee','kangaroo','visualfl']:
 req=urllib.request.Request(base+'/api/run/'+name,data=b'',method='POST')
 print(name,json.load(urllib.request.urlopen(req)),flush=True)
 deadline=time.monotonic()+190
 while time.monotonic()<deadline:
  job=get('/api/experiments').get(name,{})
  if job.get('state') in ['completed','failed']:
   print(name,json.dumps(job,ensure_ascii=True),flush=True)
   if job['state']=='failed':raise RuntimeError(name+' failed')
   break
  time.sleep(1)
 else:raise RuntimeError(name+' timeout')
print('ALL INTERFACE RUNS PASSED',flush=True)
