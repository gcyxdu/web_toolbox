let replayTimer = null, replayIndex = 0, replayPlaying = false;
let replayProject = 'sgboost', replayResult = null, replayFrames = [], replayCopyKey = '';
const replayDialog = document.getElementById('presentation');
function showReplay() {
  const frame = replayFrames[replayIndex], definition = viewDefinition(replayProject);
  if (!frame) return;
  document.getElementById('replay-title').textContent = definition.title + ' · ' + demoViewNames[demoView];
  document.getElementById('replay-position').textContent = (replayIndex + 1) + ' / ' + replayFrames.length;
  document.querySelectorAll('[data-stage]').forEach(el => {const active = Number(el.dataset.stage) === frame.phase; el.classList.toggle('active', active); if (active) el.setAttribute('aria-current','step'); else el.removeAttribute('aria-current')});
  const content = document.getElementById('replay-content');
  let canvas = content.querySelector('.replay-demo');
  if (!canvas || canvas.dataset.project !== replayProject || canvas.dataset.view !== demoView) {
    content.replaceChildren(); canvas = document.createElement('div'); canvas.className = 'replay-demo'; content.append(canvas);
    mountDemoView(canvas,replayProject,replayResult,frame,{playing:replayPlaying});
    const copy = document.createElement('div'); copy.className = 'replay-copy'; copy.setAttribute('aria-live','polite'); content.append(copy); replayCopyKey = '';
  } else updateDemoView(canvas,frame,{playing:replayPlaying});
  const key = demoView + replayProject + ':' + replayIndex;
  if (key !== replayCopyKey) {
    replayCopyKey = key;
    const copy = content.querySelector('.replay-copy'); copy.replaceChildren(); appendText(copy,'h3',frame.label);
    if (frame.phase === 0) appendText(copy,'p',definition.inputs);
    else if (replayResult) {
      if (frame.kind === 'aggregate' || frame.kind === 'boost' || frame.phase === 2) {
        const metrics = document.createElement('div'); metrics.className = 'replay-metrics';
        createMetricCards(metrics,projectMetrics(replayProject,replayResult,frame)); copy.append(metrics);
      }
      if (frame.kind === 'loss') {const record = replayResult.loss_history[frame.index]; appendText(copy,'p','第 ' + record.iteration + ' 次参数更新后的训练损失：' + metricNumber(record.loss,6))}
      if (frame.phase === 2) appendText(copy,'p',demoView==='roles'?roleDefinitions[replayProject].scope:definition.scope);
    } else appendText(copy,'p','尚无该项目的已完成记录。运行实验后可回放实际指标。');
  }
  document.getElementById('replay-prev').disabled = replayIndex === 0;
  document.getElementById('replay-next').disabled = replayIndex === replayFrames.length-1;
  document.getElementById('replay-play').textContent = replayPlaying ? '暂停' : '播放';
}
function stopReplay() {clearInterval(replayTimer); replayTimer = null; replayPlaying = false}
function playReplay() {
  stopReplay(); if (replayIndex === replayFrames.length-1) replayIndex = 0;
  replayPlaying = true; showReplay();
  scheduleReplay();
}
function scheduleReplay(){replayTimer=setInterval(()=>{if(replayIndex<replayFrames.length-1)replayIndex++;if(replayIndex===replayFrames.length-1)stopReplay();showReplay()},4200/playbackRate)}
function refreshReplayPhases(){viewDefinition(replayProject).phases.forEach((label,i)=>{document.querySelector('[data-stage="'+i+'"] span').textContent=label})}
async function openProjectReplay(id) {
  await readExperiments(); stopReplay(); replayProject = id; replayResult = experimentData[id]?.state === 'completed' ? experimentData[id].result : null;
  replayFrames = viewFrames(id,replayResult); replayIndex = 0; replayCopyKey = '';
  const content = document.getElementById('replay-content'); content.replaceChildren();
  refreshReplayPhases();
  showReplay(); if (!replayDialog.open) replayDialog.showModal(); replayDialog.focus({preventScroll:true});
}
document.getElementById('start-presentation').onclick = () => openProjectReplay(activeProject);
document.getElementById('close-presentation').onclick = () => replayDialog.close();
replayDialog.addEventListener('close',stopReplay);
document.getElementById('replay-prev').onclick = () => {stopReplay(); replayIndex = Math.max(0,replayIndex-1); showReplay()};
document.getElementById('replay-next').onclick = () => {stopReplay(); replayIndex = Math.min(replayFrames.length-1,replayIndex+1); showReplay()};
document.getElementById('replay-play').onclick = () => {if (replayPlaying) {stopReplay(); showReplay()} else playReplay()};
replayDialog.addEventListener('keydown',event => {if (!event.target.closest('.animation-switch,select') && (event.key === 'ArrowRight' || event.key === 'ArrowLeft')) {event.preventDefault(); stopReplay(); replayIndex = Math.min(replayFrames.length-1,Math.max(0,replayIndex+(event.key === 'ArrowRight'?1:-1))); showReplay()}});
document.querySelectorAll('.replay-controls button').forEach(button => {
  button.addEventListener('pointerdown',event => {if (event.pointerType === 'mouse' && event.button === 0) event.preventDefault()});
  button.addEventListener('click',event => {if (event.detail > 0) button.blur()});
});
document.addEventListener('visibilitychange',() => {if (document.hidden && replayPlaying) {stopReplay(); showReplay()}});
