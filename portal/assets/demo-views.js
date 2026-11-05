const roleDefinitions={
 sgboost:{title:'SGBoost',nodes:['数据参与方','组织方','CSP'],labels:['① 数据与特征准备','② 协同训练','③ 训练结果返回'],inputs:'原项目 Credit-4 数据与默认训练配置。三个 Java 进程协同执行。',scope:'准确率和训练时间读取 Organizer 日志；正确性尚未独立验证。'},
 visualfl:{title:'VisualFL',nodes:['三个客户端','聚合服务器','评估节点'],labels:['① 本地更新汇聚','② 聚合模型下发','③ 留出测试集评估'],inputs:'Iris 数据集，3 个客户端，FedAvg，5 轮，无攻击。',scope:'当前为普通执行环境的联邦学习实验，不表示具备隐私协议保护。'},
 tee:{title:'逻辑回归 CPU 功能对照',nodes:['数据与固定划分','CPU 训练','预测与核对'],labels:['① 训练数据','② 训练后模型','③ 留出数据与对照'],inputs:'RMT_V 的 Breast 数据重新划分为训练和留出测试集。',scope:'非 SGX：未执行原 TEE 协议。正确性只表示向量化与逐项预测一致。'},
 kangaroo:{title:'Kangaroo',nodes:['查询客户端','密文推理','明密文核对'],labels:['① 密文输入','② 密文预测结果','③ 明文基线结果'],inputs:'Iris 模型与原示例的单个输入，Windows 适配版本。',scope:'该演示是在同一进程中的角色逻辑示意，不表示跨机部署；输出一致性不是分类准确率。'}
};
let protocolSequence=0;
function mountRoleDiagram(parent,id,stage){
 const data=roleDefinitions[id],ns='http://www.w3.org/2000/svg';
 const markerId='protocol-arrow-'+(++protocolSequence);
 const svg=document.createElementNS(ns,'svg');svg.setAttribute('viewBox','0 0 640 320');svg.setAttribute('role','img');svg.setAttribute('aria-label',data.title+'角色与流程示意');svg.classList.add('protocol-diagram');
 function el(tag,attrs,text){const node=document.createElementNS(ns,tag);for(const [k,v]of Object.entries(attrs))node.setAttribute(k,v);if(text)node.textContent=text;return node}
 const defs=el('defs',{});const marker=el('marker',{id:markerId,viewBox:'0 0 10 10',refX:8,refY:5,markerWidth:6,markerHeight:6,orient:'auto-start-reverse'});marker.append(el('path',{d:'M 0 0 L 10 5 L 0 10 z',fill:'#64748B'}));defs.append(marker);svg.append(defs);
 const upward={d:'M 145 227 L 290 92',x:184,y:148,angle:-43};
 const downward={d:'M 350 100 L 495 236',x:438,y:150,angle:43};
 const back={d:'M 295 112 L 155 245',x:251,y:200,angle:-43};
 const baseline={d:'M 165 263 L 475 263',x:320,y:291,angle:0};
 const edges=id==='visualfl'?[upward,back,downward]:id==='sgboost'?[upward,downward,back]:[upward,downward,baseline];
 edges.forEach((e,i)=>{svg.append(el('path',{d:e.d,fill:'none',stroke:i===stage?'#2563EB':'#CBD5E1','stroke-width':1.6,'data-flow-index':i,'stroke-dasharray':i===1?'6 5':'','marker-end':'url(#'+markerId+')',class:i===stage?'flow-active':''}));svg.append(el('text',{x:e.x,y:e.y,transform:`rotate(${e.angle} ${e.x} ${e.y})`,'text-anchor':'middle','data-edge-label':i,fill:i===stage?'#1E3A5F':'#64748B','font-size':14},data.labels[i]))});
 const positions=[[112,248],[320,65],[528,248]];positions.forEach(([x,y],i)=>{const g=el('g',{transform:`translate(${x} ${y})`,'data-node-index':i,class:i===stage?'protocol-node node-active':'protocol-node'});g.append(el('rect',{'data-node-background':'',x:-40,y:-32,width:80,height:64,rx:10,fill:i===stage?'#EFF6FF':'#F8FAFC',stroke:i===stage?'#93C5FD':'#E2E8F0'}));
 if(i===0){g.append(el('circle',{cx:-8,cy:-10,r:7,fill:'#94A3B8'}));g.append(el('path',{d:'M -23 14 Q -21 -1 -8 -1 Q 5 -1 7 14',fill:'#CBD5E1'}));g.append(el('circle',{cx:12,cy:-8,r:6,fill:'#94A3B8'}));g.append(el('path',{d:'M 4 14 Q 6 2 13 1 Q 24 2 25 14',fill:'#E2E8F0'}))}
 else{[-16,-2,12].forEach(dy=>{g.append(el('rect',{x:-22,y:dy-4,width:44,height:10,rx:2,fill:'#94A3B8'}));g.append(el('circle',{cx:13,cy:dy+1,r:1.5,fill:'#fff'}))})}
 g.append(el('text',{x:0,y:52,'text-anchor':'middle',fill:'#334155','font-size':13},data.nodes[i]));svg.append(g)});parent.append(svg);
 const mobileRoles={sgboost:['数据参与方 → 组织方','组织方 ↔ CSP','组织方 → 数据参与方'],visualfl:['客户端 → 聚合服务器','聚合服务器 → 客户端','聚合服务器 → 评估节点'],tee:['训练数据 → CPU','训练模型 → 预测','留出数据 → 核对'],kangaroo:['查询客户端 → 密文推理','密文推理 → 核对','明文基线 → 核对']};
 const compact=document.createElement('ol');compact.className='protocol-mobile';compact.setAttribute('aria-label',data.title+'流程');
 data.labels.forEach((label,i)=>{const row=document.createElement('li');row.className=i===stage?'active':'';row.dataset.mobileStage=i;appendText(row,'b',String(i+1).padStart(2,'0'));const text=document.createElement('div');appendText(text,'strong',mobileRoles[id][i]);appendText(text,'span',label.slice(2));row.append(text);compact.append(row)});parent.append(compact); delete parent.dataset.protocolStage; updateRoleDiagram(parent,stage)
}

// Keep the diagram mounted; only its highlights change between steps.
function updateRoleDiagram(parent, stage) {
  if (parent.dataset.protocolStage === String(stage)) return;
  parent.dataset.protocolStage = stage;
  parent.querySelectorAll('[data-flow-index]').forEach(path => {const active = Number(path.dataset.flowIndex) === stage; path.classList.toggle('flow-active', active); path.setAttribute('stroke', active ? '#2563EB' : '#CBD5E1')});
  parent.querySelectorAll('[data-edge-label]').forEach(text => {text.setAttribute('fill', Number(text.dataset.edgeLabel) === stage ? '#1E3A5F' : '#64748B')});
  const project = parent.dataset.project;
  const activeNode = project === 'sgboost' ? [0,1,0][stage] : stage;
  parent.querySelectorAll('[data-node-index]').forEach(node => {const active = Number(node.dataset.nodeIndex) === activeNode; node.classList.toggle('node-active', active); const background = node.querySelector('[data-node-background]'); background.setAttribute('fill', active ? '#EFF6FF' : '#F8FAFC'); background.setAttribute('stroke', active ? '#93C5FD' : '#E2E8F0')});
  parent.querySelectorAll('[data-mobile-stage]').forEach(row => row.classList.toggle('active', Number(row.dataset.mobileStage) === stage));
}

let demoView = 'experiment';
let playbackRate = 1.75;
const demoViewNames = {experiment:'实验过程', roles:'角色交互'};
function viewDefinition(id){return demoView==='roles'?{...demoDefinitions[id],heading:'角色交互与数据流',phases:roleDefinitions[id].labels.map(label=>label.slice(2))}:demoDefinitions[id]}
function viewFrames(id,result){return demoView==='roles'?roleDefinitions[id].labels.map((label,phase)=>({kind:'role',phase,label:label.slice(2)})):buildDemoFrames(id,result)}
function mountDemoView(parent,id,result,frame,{playing=false}={}){
  parent.replaceChildren();parent.dataset.view=demoView;parent.dataset.project=id;
  if(demoView==='roles'){parent.classList.remove('project-demo');mountRoleDiagram(parent,id,frame.phase);parent.dataset.playing=String(playing)}
  else mountProjectDemo(parent,id,result,frame,{playing});
}
function updateDemoView(parent,frame,{playing=false}={}){
  if(demoView==='roles'){updateRoleDiagram(parent,frame.phase);parent.dataset.playing=String(playing)}
  else updateProjectDemo(parent,frame,{playing});
}
function refreshViewButtons(){document.querySelectorAll('[data-demo-view]').forEach(button=>{const active=button.dataset.demoView===demoView;button.setAttribute('aria-selected',String(active));button.tabIndex=active?0:-1})}
function chooseDemoView(view){
  if(view===demoView)return;
  demoView=view;refreshViewButtons();renderCurrentProject();
  if(replayDialog.open){const phase=replayFrames[replayIndex]?.phase??0;stopReplay();replayFrames=viewFrames(replayProject,replayResult);replayIndex=Math.max(0,replayFrames.findIndex(frame=>frame.phase===phase));document.getElementById('replay-content').replaceChildren();replayCopyKey='';refreshReplayPhases();showReplay()}
}
function applyPlaybackRate(){
  const style=document.documentElement.style;
  style.setProperty('--packet-fast',1800/playbackRate+'ms');style.setProperty('--packet-network',2800/playbackRate+'ms');style.setProperty('--packet-role',3600/playbackRate+'ms');
}
document.querySelectorAll('[data-demo-view]').forEach(button=>{
  button.onclick=()=>chooseDemoView(button.dataset.demoView);
  button.onkeydown=event=>{if(['ArrowLeft','ArrowRight','Home','End'].includes(event.key)){event.preventDefault();event.stopPropagation();const view=event.key==='Home'?'experiment':event.key==='End'?'roles':demoView==='experiment'?'roles':'experiment';chooseDemoView(view);button.closest('.animation-switch').querySelector('[data-demo-view="'+view+'"]').focus()}};
});
document.getElementById('playback-rate').onchange=event=>{playbackRate=Number(event.target.value);applyPlaybackRate();if(replayPlaying){clearInterval(replayTimer);scheduleReplay()}};
applyPlaybackRate();refreshViewButtons();
