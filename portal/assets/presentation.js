let replayTimer = null, replayIndex = 0, replayPlaying = false, replayProject = 'sgboost';
let replaySceneKey = ''; 
const replayProjects=['sgboost','visualfl','tee','kangaroo'];
const replayInfo={
 sgboost:{title:'SGBoost',nodes:['数据参与方','组织方','CSP'],labels:['① 数据与特征准备','② 协同训练','③ 训练结果返回'],inputs:'原项目 Credit-4 数据与默认训练配置。三个 Java 进程协同执行。',scope:'准确率和训练时间读取 Organizer 日志；正确性尚未独立验证。'},
 visualfl:{title:'VisualFL',nodes:['三个客户端','聚合服务器','评估节点'],labels:['① 本地更新汇聚','② 聚合模型下发','③ 留出测试集评估'],inputs:'Iris 数据集，3 个客户端，FedAvg，5 轮，无攻击。',scope:'当前为普通执行环境的联邦学习实验，不表示具备隐私协议保护。'},
 tee:{title:'逻辑回归 CPU 功能对照',nodes:['数据与固定划分','CPU 训练','预测与核对'],labels:['① 训练数据','② 训练后模型','③ 留出数据与对照'],inputs:'RMT_V 的 Breast 数据重新划分为训练和留出测试集。',scope:'非 SGX：未执行原 TEE 协议。正确性只表示向量化与逐项预测一致。'},
 kangaroo:{title:'Kangaroo',nodes:['查询客户端','密文推理','明密文核对'],labels:['① 密文输入','② 密文预测结果','③ 明文基线结果'],inputs:'Iris 模型与原示例的单个输入，Windows 适配版本。',scope:'该演示是在同一进程中的角色逻辑示意，不表示跨机部署；输出一致性不是分类准确率。'}
};
function appendText(parent,tag,text,className){const el=document.createElement(tag);el.textContent=text;if(className)el.className=className;parent.append(el);return el}
let protocolSequence=0;
function drawProtocol(parent,id,stage){
 const data=replayInfo[id],ns='http://www.w3.org/2000/svg';
 const markerId='protocol-arrow-'+(++protocolSequence);
 const svg=document.createElementNS(ns,'svg');svg.setAttribute('viewBox','0 0 640 320');svg.setAttribute('role','img');svg.setAttribute('aria-label',data.title+'角色与流程示意');svg.classList.add('protocol-diagram');
 function el(tag,attrs,text){const node=document.createElementNS(ns,tag);for(const [k,v]of Object.entries(attrs))node.setAttribute(k,v);if(text)node.textContent=text;return node}
 const defs=el('defs',{});const marker=el('marker',{id:markerId,viewBox:'0 0 10 10',refX:8,refY:5,markerWidth:6,markerHeight:6,orient:'auto-start-reverse'});marker.append(el('path',{d:'M 0 0 L 10 5 L 0 10 z',fill:'#6c8d79'}));defs.append(marker);svg.append(defs);
 const upward={d:'M 145 227 L 290 92',x:184,y:148,angle:-43};
 const downward={d:'M 350 100 L 495 236',x:438,y:150,angle:43};
 const back={d:'M 295 112 L 155 245',x:251,y:200,angle:-43};
 const baseline={d:'M 165 263 L 475 263',x:320,y:291,angle:0};
 const edges=id==='visualfl'?[upward,back,downward]:id==='sgboost'?[upward,downward,back]:[upward,downward,baseline];
 edges.forEach((e,i)=>{svg.append(el('path',{d:e.d,fill:'none',stroke:i===stage?'#397957':'#c8d6cc','stroke-width':1.6,'data-flow-index':i,'stroke-dasharray':i===1?'6 5':'','marker-end':'url(#'+markerId+')',class:i===stage?'flow-active':''}));svg.append(el('text',{x:e.x,y:e.y,transform:`rotate(${e.angle} ${e.x} ${e.y})`,'text-anchor':'middle','data-edge-label':i,fill:i===stage?'#35684b':'#99a99d','font-size':14},data.labels[i]))});
 const positions=[[112,248],[320,65],[528,248]];positions.forEach(([x,y],i)=>{const g=el('g',{transform:`translate(${x} ${y})`,'data-node-index':i,class:i===stage?'protocol-node node-active':'protocol-node'});g.append(el('rect',{'data-node-background':'',x:-40,y:-32,width:80,height:64,rx:10,fill:i===stage?'#edf6ef':'#f8faf8',stroke:i===stage?'#86b296':'#dfe7e0'}));
 if(i===0){g.append(el('circle',{cx:-8,cy:-10,r:7,fill:'#87aa92'}));g.append(el('path',{d:'M -23 14 Q -21 -1 -8 -1 Q 5 -1 7 14',fill:'#b5ccb9'}));g.append(el('circle',{cx:12,cy:-8,r:6,fill:'#b2cab7'}));g.append(el('path',{d:'M 4 14 Q 6 2 13 1 Q 24 2 25 14',fill:'#d1e0d3'}))}
 else{[-16,-2,12].forEach(dy=>{g.append(el('rect',{x:-22,y:dy-4,width:44,height:10,rx:2,fill:'#8eac96'}));g.append(el('circle',{cx:13,cy:dy+1,r:1.5,fill:'#fff'}))})}
 g.append(el('text',{x:0,y:52,'text-anchor':'middle',fill:'#496b55','font-size':13},data.nodes[i]));svg.append(g)});parent.append(svg);
 const mobileRoles={sgboost:['数据参与方 → 组织方','组织方 ↔ CSP','组织方 → 数据参与方'],visualfl:['客户端 → 聚合服务器','聚合服务器 → 客户端','聚合服务器 → 评估节点'],tee:['训练数据 → CPU','训练模型 → 预测','留出数据 → 核对'],kangaroo:['查询客户端 → 密文推理','密文推理 → 核对','明文基线 → 核对']};
 const compact=document.createElement('ol');compact.className='protocol-mobile';compact.setAttribute('aria-label',data.title+'流程');
 data.labels.forEach((label,i)=>{const row=document.createElement('li');row.className=i===stage?'active':'';row.dataset.mobileStage=i;appendText(row,'b',String(i+1).padStart(2,'0'));const text=document.createElement('div');appendText(text,'strong',mobileRoles[id][i]);appendText(text,'span',label.slice(2));row.append(text);compact.append(row)});parent.append(compact); delete parent.dataset.protocolStage; updateProtocolStage(parent,stage)
}

// Keep the diagram mounted; only its highlights change between steps.
function updateProtocolStage(parent, stage) {
  if (parent.dataset.protocolStage === String(stage)) return;
  parent.dataset.protocolStage = stage;
  parent.querySelectorAll('[data-flow-index]').forEach(path => {const active = Number(path.dataset.flowIndex) === stage; path.classList.toggle('flow-active', active); path.setAttribute('stroke', active ? '#397957' : '#c8d6cc')});
  parent.querySelectorAll('[data-edge-label]').forEach(text => {text.setAttribute('fill', Number(text.dataset.edgeLabel) === stage ? '#35684b' : '#99a99d')});
  const project = parent.dataset.project || (parent.id === 'detail-protocol' ? activeProject : replayProject);
  const activeNode = project === 'sgboost' ? [0,1,0][stage] : stage;
  parent.querySelectorAll('[data-node-index]').forEach(node => {const active = Number(node.dataset.nodeIndex) === activeNode; node.classList.toggle('node-active', active); const background = node.querySelector('[data-node-background]'); background.setAttribute('fill', active ? '#edf6ef' : '#f8faf8'); background.setAttribute('stroke', active ? '#86b296' : '#dfe7e0')});
  parent.querySelectorAll('[data-mobile-stage]').forEach(row => row.classList.toggle('active', Number(row.dataset.mobileStage) === stage));
}
function showReplay() {
  const stage = replayIndex, info = replayInfo[replayProject], job = experimentData[replayProject], result = job?.result;
  document.getElementById('replay-title').textContent = info.title;
  document.getElementById('replay-position').textContent = (stage + 1) + ' / 3';
  document.querySelectorAll('[data-stage]').forEach(el => {const active = Number(el.dataset.stage) === stage; el.classList.toggle('active', active); if (active) el.setAttribute('aria-current', 'step'); else el.removeAttribute('aria-current')});
  const content = document.getElementById('replay-content');
  let diagram = content.querySelector('.replay-diagram');
  if (!diagram || diagram.dataset.project !== replayProject) {
    content.replaceChildren(); diagram = document.createElement('div'); diagram.className = 'replay-diagram'; diagram.dataset.project = replayProject; drawProtocol(diagram, replayProject, stage); content.append(diagram);
    const copy = document.createElement('div'); copy.className = 'replay-copy'; copy.setAttribute('aria-live', 'polite'); content.append(copy); replaySceneKey = '';
  }
  updateProtocolStage(diagram, stage);
  const key = replayProject + stage + JSON.stringify(job);
  if (key !== replaySceneKey) {
    replaySceneKey = key;
    const copy = content.querySelector('.replay-copy'); copy.replaceChildren();
    appendText(copy,'h3',['数据与配置','运行记录','结果与验证'][stage]);
    if (stage === 0) appendText(copy,'p',info.inputs);
    else if (stage === 1) {
      appendText(copy,'p',job?.state === 'completed' ? '完成时间：' + job.timestamp : job?.state === 'running' ? '当前实验正在运行。' : '尚无完成记录。');
      if (result?.mode) appendText(copy,'p',result.mode);
    } else if (result && job?.state === 'completed') {
      const stats = document.createElement('div'); stats.className = 'replay-result';
      const first = appendText(stats,'div',result.accuracy != null ? result.accuracy + '%' : result.correctness === true ? '输出一致' : '未验证','replay-stat');
      appendText(first,'span',result.accuracy != null ? '测试准确率' : replayProject === 'tee' ? '两种预测核对' : '明密文对照');
      const second = appendText(stats,'div',result.duration_ms + ' ms','replay-stat'); appendText(second,'span','耗时'); copy.append(stats);
      if (replayProject === 'kangaroo') appendText(copy,'p','明文输出 ' + result.plaintext_result + ' · 密文输出 ' + result.ciphertext_result);
      if (replayProject === 'tee') appendText(copy,'p','留出测试集：' + result.correct + ' / ' + result.samples + ' 个预测正确');
      appendText(copy,'p',info.scope);
    } else appendText(copy,'p',job?.state === 'failed' ? '运行失败：' + job.error : '尚无已完成的实验结果。');
  }
  document.getElementById('replay-prev').disabled = stage === 0;
  document.getElementById('replay-next').disabled = stage === 2;
  document.getElementById('replay-play').textContent = replayPlaying ? '暂停' : '播放';
}
function stopReplay() {clearInterval(replayTimer); replayTimer = null; replayPlaying = false}
function playReplay() {
  stopReplay(); if (replayIndex === 2) replayIndex = 0; replayPlaying = true; showReplay();
  replayTimer = setInterval(() => {if (replayIndex < 2) replayIndex++; if (replayIndex === 2) stopReplay(); showReplay()}, 4200);
}
const replayDialog = document.getElementById('presentation');
function openProjectReplay(id) {
  stopReplay(); replayProject = id; replayIndex = 0; showReplay(); replayDialog.showModal();
  replayDialog.focus({preventScroll:true});
}
document.getElementById('start-presentation').onclick = () => openProjectReplay(activeProject);
document.getElementById('close-presentation').onclick = () => replayDialog.close();
replayDialog.addEventListener('close', stopReplay);
document.getElementById('replay-prev').onclick = () => {stopReplay(); replayIndex = Math.max(0,replayIndex-1); showReplay()};
document.getElementById('replay-next').onclick = () => {stopReplay(); replayIndex = Math.min(2,replayIndex+1); showReplay()};
document.getElementById('replay-play').onclick = () => {if (replayPlaying) {stopReplay(); showReplay()} else playReplay()};
replayDialog.addEventListener('keydown', event => {
  if (event.key === 'ArrowRight' || event.key === 'ArrowLeft') {event.preventDefault(); stopReplay(); replayIndex = Math.min(2,Math.max(0,replayIndex + (event.key === 'ArrowRight' ? 1 : -1))); showReplay()}
});
// Pointer clicks do not leave a caret or a persistent focus ring on the controls.
// Tab, Enter and Space retain normal keyboard focus and activation behavior.
document.querySelectorAll('.replay-controls button').forEach(button => {
  button.addEventListener('pointerdown', event => {if (event.pointerType === 'mouse' && event.button === 0) event.preventDefault()});
  button.addEventListener('click', event => {if (event.detail > 0) button.blur()});
});
document.addEventListener('visibilitychange', () => {if (document.hidden && replayPlaying) {stopReplay(); showReplay()}});
