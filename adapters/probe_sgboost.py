from pathlib import Path
import subprocess,time,json
root=Path(__file__).resolve().parents[1];runtime=root/'.runtime';java=Path('C:/Users/cunyuan/.jdks/ms-17.0.15/bin/java.exe')
procs=[]
try:
 for cls in ['cloud.CloudServiceProvider','dataowner.DataOrganizer','dataowner.DataOwner']:
  log=open(runtime/(cls+'.log'),'wb');p=subprocess.Popen([str(java),'-cp',str(runtime/'SGBoost-local.jar'),cls],cwd=root,stdout=log,stderr=subprocess.STDOUT);procs.append((cls,p,log));time.sleep(2)
 deadline=time.monotonic()+60
 while time.monotonic()<deadline:
  if any(p.poll() not in (None,0) for _,p,_ in procs):break
  time.sleep(1)
 for cls,p,log in procs:print(cls,'exit',p.poll())
finally:
 for cls,p,log in procs:
  if p.poll() is None:p.terminate()
  try:p.wait(timeout=5)
  except subprocess.TimeoutExpired:p.kill()
  log.close()
