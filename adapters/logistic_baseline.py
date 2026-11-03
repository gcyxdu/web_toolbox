from pathlib import Path
import time,json
import numpy as np
from sklearn.model_selection import train_test_split

def run():
 start=time.perf_counter();root=Path(__file__).resolve().parents[1]
 path=root/'modules/seccom-tee/SGX/RMT_V/Xy_test_Breast.csv'
 data=np.loadtxt(path,delimiter=',');x=data[:,:-1];y=data[:,-1]
 if not set(np.unique(y)).issubset({0.,1.}):raise ValueError('Expected binary labels in final column')
 xt,xv,yt,yv=train_test_split(x,y,test_size=.3,random_state=42,stratify=y)
 xt=np.column_stack([np.ones(len(xt)),xt]);xv=np.column_stack([np.ones(len(xv)),xv]);w=np.zeros(xt.shape[1]);loss=[];loss_history=[]
 def record(epoch):
  p=1/(1+np.exp(-np.clip(xt@w,-40,40)))
  value=float(-np.mean(yt*np.log(p+1e-12)+(1-yt)*np.log(1-p+1e-12)))
  loss.append(value);loss_history.append({'iteration':epoch,'loss':value})
 train_start=time.perf_counter();record(0)
 for epoch in range(1,601):
  p=1/(1+np.exp(-np.clip(xt@w,-40,40)));w-=.2*(xt.T@(p-yt)/len(yt))
  if epoch%60==0:record(epoch)
 train_ms=(time.perf_counter()-train_start)*1000
 infer_start=time.perf_counter();probability=1/(1+np.exp(-np.clip(xv@w,-40,40)));prediction=(probability>=.5).astype(int);infer_ms=(time.perf_counter()-infer_start)*1000
 reference=np.array([int(sum(float(a)*float(b) for a,b in zip(row,w))>=0) for row in xv]);agreement_count=int(np.sum(prediction==reference));agreement=bool(np.array_equal(prediction,reference));correct=int(np.sum(prediction==yv))
 tn=int(np.sum((yv==0)&(prediction==0)));fp=int(np.sum((yv==0)&(prediction==1)));fn=int(np.sum((yv==1)&(prediction==0)));tp=int(np.sum((yv==1)&(prediction==1)))
 precision=tp/(tp+fp) if tp+fp else 0.;recall=tp/(tp+fn) if tp+fn else 0.;f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else 0.
 return {'mode':'CPU 普通执行环境功能对照（非 SGX）','accuracy':round(correct/len(yv)*100,2),'correct':correct,'samples':len(yv),'train_samples':len(yt),'correctness':agreement,
  'precision':round(precision*100,3),'recall':round(recall*100,3),'f1':round(f1*100,3),'confusion_matrix':[[tn,fp],[fn,tp]],'prediction_agreement_count':agreement_count,
  'predictions':[{'sample':i+1,'truth':int(t),'prediction':int(p),'reference':int(r),'probability':round(float(q),6)} for i,(t,p,r,q) in enumerate(zip(yv,prediction,reference,probability))],
  'training_ms':round(train_ms,3),'inference_ms':round(infer_ms,3),'duration_ms':round((time.perf_counter()-start)*1000,3),'iterations':600,'loss':loss,'loss_history':loss_history,'loss_final':loss[-1],'dataset':str(path.relative_to(root)),
  'note':'原 Breast 数据固定分为 70% 训练、30% 留出测试；精确率、召回率和 F1 均针对标签 1。混淆矩阵行为真实标签、列为预测标签。实现一致性仅为向量化与逐项预测核对，不是 SGX 执行或可验证计算证明。'}
if __name__=='__main__':print(json.dumps(run(),ensure_ascii=False))
