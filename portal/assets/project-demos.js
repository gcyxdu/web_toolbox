const demoDefinitions = {
  sgboost: {title:'SGBoost', heading:'纵向协作与逐轮建树', phases:['数据协作','迭代建树','模型评估'], inputs:'Credit-4 · CSP / Organizer / DataOwner 三方协同训练。', scope:'评估准确率与训练计时来自 Organizer 日志；图中的小树表示训练轮次，不是导出的真实树结构。'},
  visualfl: {title:'VisualFL', heading:'客户端训练与全局模型聚合', phases:['客户端数据','模型聚合','全局评估'], inputs:'Iris · FedAvg · LR · 3 个客户端 · 5 轮。', scope:'客户端与样本数来自实测事件；流动连线为过程回放。当前没有接入隐私保护协议。'},
  tee: {title:'逻辑回归 CPU 对照（非 SGX）', heading:'损失收敛与预测核对', phases:['数据划分','梯度下降','预测验证'], inputs:'Breast · 训练/测试：70% / 30% · 600 次迭代 · CPU。', scope:'混淆矩阵来自留出测试集；实现核对是向量化与逐项预测对照，不能当作 SGX 或可验证计算证明。'},
  kangaroo: {title:'Kangaroo', heading:'明文基线与密态推理双通道', phases:['示例输入','密态计算','解密核对'], inputs:'Iris 决策树 · Microsoft SEAL · 明文基线 / 密态推理。', scope:'明文路径来自示例日志，仅用于解释基线；不表示服务器可看到密文查询的明文。端到端时间包含初始化。'}
};
function appendText(parent,tag,text,className){const el=document.createElement(tag);el.textContent=text;if(className)el.className=className;parent.append(el);return el}
function metricNumber(value,digits=3){return Number.isFinite(value)?value.toLocaleString('en-US',{maximumFractionDigits:digits,useGrouping:false}):'未记录'}
function metricTime(value){return value==null?'未记录':metricNumber(value)+' ms'}
function projectMetrics(id,result,frame){
  if(!result)return [];
  if(id==='sgboost'){
    const history=result.accuracy_history||[],index=frame?.kind==='boost'?frame.index:history.length-1;
    const current=history[index]??result.accuracy,gain=history.length&&index>=0?current-history[0]:null;
    return [['评估准确率',current==null?'未记录':metricNumber(current,2)+'%'],['较首轮变化',gain==null?'未记录':(gain>=0?'+':'')+metricNumber(gain,2)+' 个百分点'],['完成迭代',history.length?String(index+1)+' 轮':'未记录'],['训练日志计时',metricTime(result.duration_ms)]];
  }
  if(id==='visualfl'){
    const round=frame?.kind==='aggregate'?frame.record:null;
    return [['全局测试准确率',Number.isFinite(round?.accuracy??result.accuracy)?metricNumber(round?round.accuracy*100:result.accuracy,2)+'%':'未记录'],['全局测试损失',metricNumber(round?.loss??result.loss_final,4)],['已完成聚合',Number.isFinite(round?.round??result.rounds)?String(round?.round??result.rounds)+' 轮':'未记录'],['参与客户端',result.client_count==null?'未记录':String(result.client_count)+' 个']];
  }
  if(id==='tee')return [['精确率 · 标签 1',result.precision==null?'未记录':metricNumber(result.precision,2)+'%'],['召回率 · 标签 1',result.recall==null?'未记录':metricNumber(result.recall,2)+'%'],['F1 · 标签 1',result.f1==null?'未记录':metricNumber(result.f1,2)+'%'],['两种预测实现核对',result.prediction_agreement_count==null?'未记录':result.prediction_agreement_count+' / '+result.samples]];
  return [['明密文输出核对',result.correctness===true?'一致':result.correctness===false?'不一致':'未验证'],['输出绝对误差',metricNumber(result.absolute_error)],['扩展树节点',metricNumber(result.expanded_nodes,0)],['端到端时间',metricTime(result.duration_ms)]];
}
function buildDemoFrames(id,result){
  if(id==='sgboost')return [{kind:'prepare',phase:0,label:'数据参与方协作'},...(result?.accuracy_history||[]).map((_,index)=>({kind:'boost',phase:1,label:'第 '+(index+1)+' 轮建树记录',index})),{kind:'result',phase:2,label:'评估结果'}];
  if(id==='visualfl')return [{kind:'prepare',phase:0,label:'客户端数据划分'},...(result?.round_history||[]).map(record=>({kind:'aggregate',phase:1,label:'第 '+record.round+' 轮模型聚合',record})),{kind:'result',phase:2,label:'全局测试结果'}];
  if(id==='tee'){
    const history=result?.loss_history||[],indices=[Math.floor(history.length*.25),Math.floor(history.length*.6),history.length-1];
    return [{kind:'split',phase:0,label:'训练集与留出测试集'},...[...new Set(indices)].filter(i=>i>=0&&history[i]).map(index=>({kind:'loss',phase:1,index,label:'梯度下降 · 第 '+history[index].iteration+' 次迭代'})),{kind:'predict',phase:2,label:'留出测试集预测'},{kind:'verify',phase:2,label:'预测实现与混淆矩阵核对'}];
  }
  return [{kind:'prepare',phase:0,label:'同一示例查询'}, {kind:'cipher',phase:1,label:'SEAL 密态推理'}, {kind:'compare',phase:2,label:'解密输出与明文基线核对'}];
}
function createMetricCards(parent,items){parent.replaceChildren();items.forEach(([label,value])=>{const box=document.createElement('div');box.className='metric-box';appendText(box,'span',label);appendText(box,'strong',value);parent.append(box)})}
function svgElement(tag,attributes={},text){const node=document.createElementNS('http://www.w3.org/2000/svg',tag);Object.entries(attributes).forEach(([key,value])=>node.setAttribute(key,value));if(text!=null)node.textContent=text;return node}
function makeLineChart(values,label,{xValues,percent=false}={}){
  const wrap=document.createElement('div');wrap.className='measured-chart';appendText(wrap,'h3',label);
  if(!values?.length){appendText(wrap,'p','运行后显示实际记录。','empty-chart');return wrap}
  const svg=svgElement('svg',{viewBox:'0 0 600 215',role:'img','aria-label':label});
  const max=percent?100:Math.max(...values)*1.12||1,left=50,right=570,top=15,bottom=165;
  [0,.5,1].forEach(ratio=>{const y=bottom-ratio*(bottom-top);svg.append(svgElement('line',{x1:left,x2:right,y1:y,y2:y,stroke:'#edf1ee'}));svg.append(svgElement('text',{x:40,y:y+4,'text-anchor':'end',fill:'#8a9a90','font-size':12},metricNumber(max*ratio,percent?0:3)))});
  const points=values.map((value,i)=>[left+(right-left)*i/Math.max(1,values.length-1),bottom-value/max*(bottom-top)]);
  const line=svgElement('polyline',{points:points.map(p=>p.join(',')).join(' '),fill:'none',stroke:'#579777','stroke-width':2.2});svg.append(line);
  points.forEach(([x,y],i)=>{const dot=svgElement('circle',{cx:x,cy:y,r:3,fill:'#579777','data-chart-point':i});dot.append(svgElement('title',{},(xValues?.[i]??i+1)+': '+metricNumber(values[i],4)));svg.append(dot)});
  const tickIndices=[...new Set([0,Math.floor((values.length-1)/2),values.length-1])];tickIndices.forEach(i=>svg.append(svgElement('text',{x:points[i][0],y:190,'text-anchor':'middle',fill:'#8a9a90','font-size':12},String(xValues?.[i]??i+1))));
  const cursor=svgElement('circle',{cx:points.at(-1)[0],cy:points.at(-1)[1],r:5,fill:'#fff',stroke:'#367b58','stroke-width':2,class:'chart-cursor'});svg.append(cursor);wrap.append(svg);wrap._points=points;return wrap;
}
function makeConfusionMatrix(result){
  const wrap=document.createElement('div');wrap.className='confusion-panel';appendText(wrap,'h3','留出测试集 · 混淆矩阵');
  const table=document.createElement('table');table.className='confusion-table';const head=document.createElement('thead'),tr=document.createElement('tr');['真实 / 预测','预测 0','预测 1'].forEach(text=>appendText(tr,'th',text));head.append(tr);table.append(head);const body=document.createElement('tbody');
  [0,1].forEach(i=>{const row=document.createElement('tr');appendText(row,'th','真实 '+i);[0,1].forEach(j=>{const cell=appendText(row,'td',result?.confusion_matrix?.[i]?.[j]??'未记录');cell.dataset.measuredCount=result?.confusion_matrix?.[i]?.[j]??'未记录';cell.className=i===j?'matrix-correct':'matrix-error'});body.append(row)});table.append(body);wrap.append(table);return wrap;
}
function mountProjectDemo(container,id,result,frame,{playing=false}={}){
  container.replaceChildren();container.dataset.demo=id;container._demoResult=result;container._demoProject=id;container.classList.add('project-demo');
  if(id==='sgboost')mountBoost(container,result);
  else if(id==='visualfl')mountFederated(container,result);
  else if(id==='tee')mountRegression(container,result);
  else mountKangaroo(container,result);
  updateProjectDemo(container,frame,{playing});
}
function updateProjectDemo(container,frame,{playing=false}={}){
  const result=container._demoResult,id=container._demoProject;if(!id||!frame)return;
  container.dataset.playing=String(playing);container.dataset.phase=frame.phase;container.dataset.kind=frame.kind;
  if(id==='sgboost'){
    const count=frame.kind==='boost'?frame.index+1:frame.phase===2?(result?.accuracy_history?.length||0):0;
    container.querySelectorAll('[data-tree-round]').forEach(node=>{node.classList.toggle('tree-built',Number(node.dataset.treeRound)<count);node.classList.toggle('tree-current',Number(node.dataset.treeRound)===count-1)});
    container.querySelector('.boost-caption').textContent=count?'已记录 '+count+' 轮 · 评估准确率 '+metricNumber(result.accuracy_history[count-1],2)+'%':'三个角色协作，训练后记录逐轮评估结果';
  }else if(id==='visualfl'){
    const round=frame.kind==='aggregate'?frame.record.round:frame.phase===2?result?.rounds:0;
    container.querySelector('.global-round').textContent=(round??0)+' / '+(result?.rounds??5)+' 轮';
    container.querySelector('.global-status').textContent=frame.phase===0?'客户端数据':frame.kind==='aggregate'?'聚合记录回放':'全局评估';
    const accuracy=frame.kind==='aggregate'?frame.record.accuracy*100:frame.phase===2?result?.accuracy:null;
    container.querySelector('.global-accuracy').textContent=accuracy==null?(result?.algorithm??'FedAvg')+' · '+(result?.model??'lr').toUpperCase():'全局准确率 '+metricNumber(accuracy,2)+'%';
    container.querySelectorAll('.client-status').forEach(el=>{el.textContent=frame.phase===0?'数据保留在客户端':frame.kind==='aggregate'?'模型更新 → 聚合':'本轮参与完成'});
  }else if(id==='tee'){
    const history=result?.loss_history||[],index=frame.kind==='loss'?frame.index:frame.phase===2?history.length-1:-1;
    container.querySelector('.regression-iteration').textContent=index>=0?'迭代 '+history[index].iteration+' · 损失 '+metricNumber(history[index].loss,4):'固定随机划分 · CPU 功能对照';
    const chart=container.querySelector('.measured-chart');
    if(chart?._points){
      // Retain the canvas and reveal only the loss samples reached in this replay step.
      const shown=chart._points.slice(0,index+1);
      chart.querySelector('polyline').setAttribute('points',shown.map(p=>p.join(',')).join(' '));
      chart.querySelectorAll('[data-chart-point]').forEach(dot=>dot.setAttribute('visibility',Number(dot.dataset.chartPoint)<=index?'visible':'hidden'));
      const cursor=chart.querySelector('.chart-cursor');cursor.setAttribute('visibility',index>=0?'visible':'hidden');
      if(index>=0){cursor.style.transition='';const [x,y]=chart._points[index];cursor.setAttribute('cx',x);cursor.setAttribute('cy',y)}else{cursor.style.transition='none';const [x,y]=chart._points[0];cursor.setAttribute('cx',x);cursor.setAttribute('cy',y)}
      chart.querySelector('h3').textContent=index>=0?'训练损失 · 已记录到第 '+history[index].iteration+' 次更新':'训练损失 · 等待训练步骤';
    }
    container.querySelectorAll('[data-measured-count]').forEach(cell=>{cell.textContent=frame.phase>=2?cell.dataset.measuredCount:'—'});
    container.querySelector('.confusion-panel h3').textContent=frame.phase>=2?'留出测试集 · 混淆矩阵':'混淆矩阵 · 等待预测步骤';
    container.querySelector('.prediction-check').textContent=frame.kind==='verify'?result?.prediction_agreement_count!=null?'逐项预测 = 向量化预测 · '+result.prediction_agreement_count+'/'+result.samples:'尚未取得实现核对记录':frame.kind==='predict'?'留出测试集准确率 '+metricNumber(result?.accuracy,2)+'%':'仅使用训练集更新参数';
  }else{
    container.querySelector('.lane-plain .output-value').textContent=frame.phase>=1?result?.plaintext_result??'—':'—';
    container.querySelector('.lane-cipher .output-value').textContent=frame.phase===2?result?.ciphertext_result??'—':'—';
    container.querySelector('.comparison-result').textContent=frame.phase===2?result?.correctness===true?'两路输出一致 · 绝对误差 '+metricNumber(result.absolute_error):result?.correctness===false?'两路输出不一致':'尚无核对结果':'同一输入，经明文与密文两条路径计算';
  }
}
function mountBoost(parent,result){
  const lane=document.createElement('div');lane.className='boost-roles';
  [['DataOwner','数据参与方','本地数据与特征'],['Organizer','训练组织方','增益与分桶协同'],['CSP','计算协作方','加密梯度协同']].forEach(([en,title,desc],i)=>{const node=document.createElement('div');node.className='role-card';appendText(node,'span',en,'role-name');appendText(node,'strong',title);appendText(node,'p',desc);lane.append(node);if(i<2){const wire=document.createElement('div');wire.className='role-wire';wire.setAttribute('aria-hidden','true');lane.append(wire)}});parent.append(lane);
  const forest=document.createElement('div');forest.className='boost-forest';
  const history=result?.accuracy_history||[];
  history.forEach((accuracy,index)=>{const tile=document.createElement('div');tile.className='tree-tile';tile.dataset.treeRound=index;appendText(tile,'span','第 '+(index+1)+' 轮');const svg=svgElement('svg',{viewBox:'0 0 100 70','aria-hidden':'true'});svg.append(svgElement('path',{d:'M50 12V26M50 26L24 44M50 26L76 44M24 44L12 60M24 44L36 60M76 44L64 60M76 44L88 60',fill:'none',stroke:'currentColor','stroke-width':1.5}));[[50,12],[24,44],[76,44],[12,60],[36,60],[64,60],[88,60]].forEach(([x,y])=>svg.append(svgElement('circle',{cx:x,cy:y,r:3,fill:'currentColor'})));tile.append(svg);appendText(tile,'strong',metricNumber(accuracy,2)+'%');forest.append(tile)});
  if(!history.length)appendText(forest,'p','运行后展示实际迭代记录。');parent.append(forest);appendText(parent,'p','','boost-caption');
}
function makeDeviceIcon(kind){
  const svg=svgElement('svg',{viewBox:'0 0 28 28',fill:'none',stroke:'currentColor','stroke-width':1.5,'stroke-linecap':'round','stroke-linejoin':'round','aria-hidden':'true'});
  if(kind==='client'){
    svg.append(svgElement('rect',{x:3,y:4,width:22,height:16,rx:2}),svgElement('path',{d:'M3 16H25M10 24H18M14 20V24M7 8H14M7 11H11'}));
  }else{
    [4,11,18].forEach(y=>{svg.append(svgElement('rect',{x:4,y,width:20,height:5,rx:1.5}),svgElement('circle',{cx:20,cy:y+2.5,r:.6,fill:'currentColor'}))});
  }
  return svg;
}
function mountFederated(parent,result){
  const clients=result?.clients?.length?result.clients:Array.from({length:3},(_,i)=>({id:'client-'+String(i).padStart(2,'0'),samples:null,malicious:false}));
  const network=document.createElement('div');network.className='fl-network';
  const left=document.createElement('div');left.className='client-stack left-clients';const right=document.createElement('div');right.className='client-stack right-clients';
  clients.forEach((client,i)=>{const card=document.createElement('div');card.className='client-card'+(client.malicious?' malicious':'');const icon=appendText(card,'span','','client-icon');icon.append(makeDeviceIcon('client'));const text=document.createElement('div');appendText(text,'strong',client.id.replace('client-','Client '));appendText(text,'span',(client.malicious?'攻击客户端':'正常客户端')+' · '+(client.samples==null?'样本待记录':client.samples+' 个样本'),'client-data');appendText(text,'span','','client-status');card.append(text);(i<Math.ceil(clients.length/2)?left:right).append(card)});
  const server=document.createElement('div');server.className='global-server';const icon=appendText(server,'span','','server-icon');icon.append(makeDeviceIcon('server'));appendText(server,'strong','全局模型服务器');appendText(server,'span','','global-accuracy');appendText(server,'span','','global-round');appendText(server,'span','','global-status');
  network.append(left,server,right);parent.append(network);
  appendText(parent,'p',result?.train_samples!=null?'训练 '+result.train_samples+' 个样本 · 留出测试 '+result.test_samples+' 个样本':'Iris · 3 客户端 · 5 轮默认配置','network-dataset');
}
function mountRegression(parent,result){
  const split=document.createElement('div');split.className='data-split';const train=appendText(split,'span',result?.train_samples!=null?'训练集 '+result.train_samples:'训练集 70%','train-split');const test=appendText(split,'span',result?.samples!=null?'测试集 '+result.samples:'测试集 30%','test-split');train.style.flex=result?.train_samples||70;test.style.flex=result?.samples||30;parent.append(split);appendText(parent,'p','','regression-iteration');
  const grid=document.createElement('div');grid.className='regression-grid';grid.append(makeLineChart(result?.loss,'训练损失收敛',{xValues:result?.loss_history?.map(r=>r.iteration)}),makeConfusionMatrix(result));parent.append(grid);appendText(parent,'p','','prediction-check');
}
function mountKangaroo(parent,result){
  const dual=document.createElement('div');dual.className='kangaroo-dual';
  ['plain','cipher'].forEach(type=>{const lane=document.createElement('div');lane.className='inference-lane lane-'+type;appendText(lane,'strong',type==='plain'?'明文基线':'密态推理','lane-title');const pipeline=document.createElement('div');pipeline.className='inference-pipeline';
    const labels=type==='plain'?(result?.reference_path?.length?result.reference_path.map(p=>'节点 '+p.node):['明文决策树']):['密文向量','安全比较','路径求和'];
    labels.forEach((label,i)=>{const node=document.createElement('div');node.className='inference-node';appendText(node,'span',label);if(type==='plain'&&result?.reference_path?.[i])appendText(node,'small','x='+result.reference_path[i].input+' · y='+result.reference_path[i].threshold);pipeline.append(node);if(i<labels.length-1){const wire=document.createElement('i');wire.className='pipeline-wire';pipeline.append(wire)}});lane.append(pipeline);const output=document.createElement('div');output.className='lane-output';appendText(output,'span',type==='plain'?'明文输出':'解密输出');appendText(output,'strong','—','output-value');lane.append(output);dual.append(lane)});parent.append(dual);appendText(parent,'p','','comparison-result');
  if(result?.expanded_nodes!=null)appendText(parent,'p','扩展树 '+result.expanded_nodes+' 个节点 · 其中虚拟节点 '+result.virtual_nodes,'tree-padding');
}
function renderProjectEvidence(parent,id,result){
  parent.replaceChildren();if(!result)return;
  const grid=document.createElement('div');grid.className='evidence-grid';
  if(id==='sgboost'){grid.append(makeLineChart(result.accuracy_history,'逐轮评估准确率（%）',{percent:true}));appendText(parent,'p',result.wall_ms!=null?'训练日志 '+metricTime(result.duration_ms)+' · 进程端到端 '+metricTime(result.wall_ms):'训练时间读取原项目日志。','timing-detail')}
  if(id==='visualfl'){
    const rounds=result.round_history||[];grid.append(makeLineChart(rounds.map(r=>r.accuracy*100),'全局测试准确率（%）',{xValues:rounds.map(r=>r.round),percent:true}),makeLineChart(rounds.map(r=>r.loss),'全局测试损失',{xValues:rounds.map(r=>r.round)}));
    appendText(parent,'p','各轮累计计算 '+metricTime(result.round_compute_total_ms)+' · 末轮训练与评估 '+metricTime(result.duration_ms),'timing-detail');
  }
  if(id==='tee'){
    grid.append(makeLineChart(result.loss,'训练损失收敛',{xValues:result.loss_history?.map(r=>r.iteration)}),makeConfusionMatrix(result));
    appendText(parent,'p','留出测试准确率 '+metricNumber(result.accuracy,2)+'% · CPU 训练 '+metricTime(result.training_ms)+' · '+result.samples+' 个样本推理 '+metricTime(result.inference_ms),'timing-detail');
  }
  if(id==='kangaroo'){
    const outputs=document.createElement('div');outputs.className='verified-outputs';appendText(outputs,'span','明文输出');appendText(outputs,'strong',result.plaintext_result??'—');appendText(outputs,'span','密文输出');appendText(outputs,'strong',result.ciphertext_result??'—');grid.append(outputs);
    appendText(parent,'p','明文基线计时 '+metricTime(result.plaintext_ms)+' · 完整密态示例端到端 '+metricTime(result.duration_ms)+'。','timing-detail');
  }
  parent.append(grid);
}
