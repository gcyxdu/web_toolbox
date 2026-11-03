from pathlib import Path
import subprocess,time,re,json,sys,os,threading
import urllib.request
ROOT=Path(__file__).resolve().parents[1];RUNTIME=ROOT/'.runtime';RUNTIME.mkdir(exist_ok=True)
JAVA=next((p for p in [Path('C:/Users/cunyuan/.jdks/ms-17.0.15/bin/java.exe'),Path('C:/Program Files/Microsoft/jdk-21.0.2.13-hotspot/bin/java.exe')] if p.exists()),None)
try:
 RESULTS=json.loads((RUNTIME/'experiment-results.json').read_text(encoding='utf-8'))
 for job in RESULTS.values():
  if job.get('state')=='running':job.update(state='failed',error='上次服务已停止，请重新运行')
except (OSError,ValueError):RESULTS={}
LOCK=threading.Lock()
def run_sgboost():
 subprocess.run([sys.executable,str(ROOT/'adapters/prepare_sgboost.py')],cwd=ROOT,capture_output=True,check=True)
 procs=[];started=time.perf_counter()
 try:
  for cls in ['cloud.CloudServiceProvider','dataowner.DataOrganizer','dataowner.DataOwner']:
   log=open(RUNTIME/(cls+'.log'),'wb');p=subprocess.Popen([str(JAVA),'-Dfile.encoding=UTF-8','-cp',str(RUNTIME/'SGBoost-local.jar'),cls],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT);procs.append((cls,p,log));time.sleep(2)
  deadline=time.monotonic()+120
  while time.monotonic()<deadline:
   data=(RUNTIME/'dataowner.DataOrganizer.log').read_text(encoding='utf-8',errors='replace')
   if re.search(r'\d+ms',data):break
   if any(p.poll() not in (None,0) for _,p,_ in procs):raise RuntimeError('SGBoost 进程异常，详见 .runtime 下日志')
   time.sleep(1)
  accuracy=re.findall(r'Accuracy:\s*([0-9.]+)',data);duration=re.findall(r'(\d+)ms',data)
  if not accuracy or not duration:raise RuntimeError('未在时限内取得完整训练指标；进程已清理，详见日志')
  return {'mode':'SGBoost 原始 JAR（仅适配数据路径）','accuracy':round(float(accuracy[-1])*100,2),'accuracy_history':[round(float(x)*100,2) for x in accuracy],'duration_ms':int(duration[-1]),'wall_ms':round((time.perf_counter()-started)*1000),'correctness':None,'note':'准确率与训练时间来自 Organizer 日志，正确性未独立验证；训练结束后清理等待发布的进程。'}
 finally:
  for cls,p,log in procs:
   if p.poll() is None:p.terminate()
   try:p.wait(timeout=5)
   except subprocess.TimeoutExpired:p.kill();p.wait()
   log.close()
def run_kangaroo():
 exe=RUNTIME/'kangaroo/examples.exe';started=time.perf_counter()
 p=subprocess.run([str(exe),'1'],cwd=RUNTIME/'kangaroo/run',capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=120)
 output=p.stdout+p.stderr;(RUNTIME/'kangaroo.log').write_text(output,encoding='utf-8')
 if p.returncode:raise RuntimeError('Kangaroo 退出码 '+str(p.returncode)+': '+output[-1200:])
 plain=re.search(r'True prediction results:\s*([-\d.]+)',output);cipher=re.search(r'Ciphertext prediction result:\s*([-\d.]+)',output)
 if not plain or not cipher:raise RuntimeError('未取得明文与密文输出')
 return {'mode':'Kangaroo Windows 适配 · Iris 单次交互式密文推理','accuracy':None,'correctness':plain.group(1)==cipher.group(1),'plaintext_result':plain.group(1),'ciphertext_result':cipher.group(1),'duration_ms':round((time.perf_counter()-started)*1000,3),'note':'明密文一致性不是分类准确率；耗时为进程端到端墙钟时间，包含密钥与模型初始化。'}

def run_visualfl():
 def request(path,body=None):
  req=urllib.request.Request('http://127.0.0.1:8000'+path, data=json.dumps(body).encode('utf-8') if body is not None else None, headers={'Content-Type':'application/json'})
  with urllib.request.urlopen(req,timeout=15) as r:return json.load(r)
 config={'name':'平台演示-Iris','dataset':'Iris','model':'lr','client_count':3,'rounds':5,'local_steps':10,'distribution':'iid','learning_rate':.1,'attack':'None','defense':'Mean'}
 job=request('/api/runs',config);rid=job['id'];deadline=time.monotonic()+180
 while time.monotonic()<deadline:
  job=request('/api/runs/'+rid)
  if job['status']=='completed':
   m=job['metrics']
   return {'mode':'VisualFL / FedAvg / Iris / PyTorch CPU','accuracy':round(m['accuracy']*100,2),'duration_ms':round(m['duration_ms'],3),'loss_final':m.get('loss'),'correctness':None,'run_id':rid,'rounds':m.get('round'),'note':'真实联邦训练，无攻击、Mean 聚合、3 个客户端、5 轮；准确率来自 VisualFL 测试集，不是隐私安全或可验证计算证明。'}
  if job['status'] in ('failed','cancelled','interrupted'):raise RuntimeError(job.get('error') or job['status'])
  time.sleep(1)
 raise RuntimeError('VisualFL 训练超时，任务可能仍在运行，请在 VisualFL 查看：'+rid)

def worker(project):
 try:
  if project=='tee':
   env=os.environ.copy();env['PYTHONIOENCODING']='utf-8'
   p=subprocess.run([sys.executable,str(ROOT/'adapters/logistic_baseline.py')],cwd=ROOT,capture_output=True,text=True,encoding='utf-8',env=env,timeout=60)
   if p.returncode:raise RuntimeError(p.stderr[-1500:])
   result=json.loads(p.stdout)
  elif project=='visualfl':result=run_visualfl()
  elif project=='kangaroo':result=run_kangaroo()
  elif project=='sgboost':
   if not JAVA:raise RuntimeError('Java 未找到')
   result=run_sgboost()
  else:raise RuntimeError('当前项目尚未完成运行适配')
  RESULTS[project]={'state':'completed','timestamp':time.strftime('%Y-%m-%d %H:%M:%S'),'result':result}
 except Exception as e:RESULTS[project]={'state':'failed','error':str(e)}
 finally:
  (RUNTIME/'experiment-results.json').write_text(json.dumps(RESULTS,ensure_ascii=False,indent=2),encoding='utf-8');LOCK.release()
def start(project):
 if project not in ('sgboost','tee','kangaroo','visualfl'):return False,'未接入运行适配器'
 if not LOCK.acquire(blocking=False):return False,'已有实验运行中，请稍后重试'
 RESULTS[project]={'state':'running'};threading.Thread(target=worker,args=(project,),daemon=True).start();return True,'已启动'
