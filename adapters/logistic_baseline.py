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
 xt=np.column_stack([np.ones(len(xt)),xt]);xv=np.column_stack([np.ones(len(xv)),xv]);w=np.zeros(xt.shape[1]);loss=[]
 train_start=time.perf_counter()
 for epoch in range(600):
  p=1/(1+np.exp(-np.clip(xt@w,-40,40)));w-=.2*(xt.T@(p-yt)/len(yt))
  if epoch%60==0:loss.append(float(-np.mean(yt*np.log(p+1e-12)+(1-yt)*np.log(1-p+1e-12))))
 train_ms=(time.perf_counter()-train_start)*1000
 infer_start=time.perf_counter();prediction=(xv@w>=0).astype(int);infer_ms=(time.perf_counter()-infer_start)*1000
 reference=np.array([int(sum(float(a)*float(b) for a,b in zip(row,w))>=0) for row in xv]);agreement=bool(np.array_equal(prediction,reference));correct=int(np.sum(prediction==yv))
 return {'mode':'CPU 普通执行环境功能对照（非 SGX）','accuracy':round(correct/len(yv)*100,2),'correct':correct,'samples':len(yv),'train_samples':len(yt),'correctness':agreement,'training_ms':round(train_ms,3),'inference_ms':round(infer_ms,3),'duration_ms':round((time.perf_counter()-start)*1000,3),'loss':loss,'dataset':str(path.relative_to(root)),'note':'使用原项目 Xy_test_Breast.csv 重新固定划分为 70% 训练、30% 留出测试；不等同原实验。正确性仅为向量化预测与逐项计算一致，不是可验证计算证明。'}
if __name__=='__main__':print(json.dumps(run(),ensure_ascii=False))
