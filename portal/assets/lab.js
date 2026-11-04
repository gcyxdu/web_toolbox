let statusData = null;
let activeProject = 'sgboost';
let activeView = 'overview';
let experimentData = {};
let lastMetricKey = '';
let lastProtocolKey = '';
let requestPending = false;
let localRunError = '';
let experimentReadError = false;
const projectOrder = ['sgboost', 'visualfl', 'tee', 'kangaroo'];
let expandedProjects = new Set();
try {expandedProjects = new Set(JSON.parse(sessionStorage.getItem('toolbox-expanded-projects') || '[]').filter(id => projectOrder.includes(id)))} catch {}
function updateNavigation() {
  document.querySelectorAll('.nav-project').forEach(group => {
    const id=group.dataset.project, selected=id===activeProject, expanded=expandedProjects.has(id);
    group.classList.toggle('active',selected);group.classList.toggle('expanded',expanded);group.querySelector('.project-link').setAttribute('aria-expanded',String(expanded));
    group.querySelectorAll('.nav-children a').forEach(link=>{if(selected&&link.dataset.view===activeView)link.setAttribute('aria-current','page');else link.removeAttribute('aria-current')});
  });
}
const viewLabels = {overview: '项目概览', results: '实验结果', environment: '环境状态'};
const descriptions = {
  sgboost: {title: 'SGBoost', menu: 'SGBoost', description: '纵向联邦树模型训练', run: '运行 SGBoost 训练', help: '运行 SGBoost.jar，启动 CSP、组织方和数据方三个进程，完成 Credit-4 训练。'},
  visualfl: {title: 'VisualFL', menu: 'VisualFL', description: '联邦学习可视化实验台', run: '运行 Iris 联邦训练', help: '点击“运行 Iris 联邦训练”执行默认配置；在 VisualFL 实验台可调整数据集、模型、聚合方法与客户端参数。'},
  tee: {title: 'TEE 逻辑回归', menu: 'TEE 逻辑回归', description: '当前运行：CPU 功能对照（非 SGX）', run: '运行 CPU 对照', help: '点击“运行 CPU 对照”，执行 Breast 数据划分、600 次梯度下降及留出集预测。'},
  kangaroo: {title: 'Kangaroo', menu: 'Kangaroo', description: '隐私保护决策树推理', run: '运行 Iris 密文推理', help: '点击“运行 Iris 密文推理”，加载模型，执行密文计算并对照明文输出。'}
};
function buildNavigation() {
  const nav = document.getElementById('project-nav');
  projectOrder.forEach(id => {
    const group = document.createElement('div'); group.className = 'nav-project'; group.dataset.project = id;
    const link = document.createElement('button'); link.type='button'; link.className='project-link'; link.setAttribute('aria-controls','nav-children-'+id);
    link.onclick=()=>{if(expandedProjects.has(id))expandedProjects.delete(id);else expandedProjects.add(id);try{sessionStorage.setItem('toolbox-expanded-projects',JSON.stringify([...expandedProjects]))}catch{};updateNavigation();if(id!==activeProject)location.hash=id+'/overview'};
    const label = document.createElement('span'); label.textContent = descriptions[id].menu;
    const arrow = document.createElement('span'); arrow.className = 'nav-chevron'; arrow.textContent = '›'; arrow.setAttribute('aria-hidden', 'true');
    link.append(label, arrow); group.append(link);
    const children = document.createElement('div'); children.className = 'nav-children'; children.id='nav-children-'+id;
    Object.entries(viewLabels).forEach(([view, title]) => {const child = document.createElement('a'); child.href = '#' + id + '/' + view; child.textContent = title; child.dataset.view = view; children.append(child)});
    group.append(children); nav.append(group);
  });
}
function applyRoute() {
  const [project, view] = location.hash.slice(1).split('/');
  const nextProject = projectOrder.includes(project) ? project : 'sgboost';
  const nextView = Object.hasOwn(viewLabels, view) ? view : 'overview';
  if (activeProject !== nextProject) {lastMetricKey = ''; localRunError = ''}
  activeProject = nextProject; activeView = nextView;
  const data = descriptions[activeProject];
  document.title = data.title + ' · 数据安全融合';
  document.getElementById('detail-title').textContent = data.title;
  document.getElementById('detail-desc').textContent = data.description;
  document.getElementById('run-experiment').textContent = data.run;
  document.getElementById('project-config').textContent = demoDefinitions[activeProject].inputs;
  document.getElementById('detail-help').textContent = data.help;
  document.getElementById('detail-link').classList.toggle('hidden', activeProject !== 'visualfl');
  updateNavigation();
  document.querySelectorAll('[data-tab]').forEach(tab => {const selected = tab.dataset.tab === activeView; tab.setAttribute('aria-selected', String(selected)); tab.tabIndex = selected ? 0 : -1});
  Object.keys(viewLabels).forEach(view => {document.getElementById('view-' + view).hidden = view !== activeView});
  renderCurrentProject(); renderEnvironment();
}
function renderEnvironment() {
  const box = document.getElementById('env-list'); box.replaceChildren();
  if (!statusData) {box.textContent = '环境检测暂不可用，请刷新检测。'; return}
  const s = statusData;
  const items = {
    sgboost: [['Java 运行环境', s.sgboost_java ? '已检测到' : '未检测到'], ['SGBoost.jar', s.sgboost_jar ? '已找到' : '未找到'], ['运行方式', '本机三个 Java 进程']],
    visualfl: [['VisualFL 服务', s.visualfl_listening ? '健康检查通过' : '未通过健康检查'], ['独立 Python 环境', s.visualfl_environment ? '已配置' : '未配置'], ['运行方式', 'PyTorch CPU']],
    tee: [['RMT_V 源码目录', s.rmt_v_source ? '已找到' : '未找到'], ['原项目 App 目录', s.rmt_v_app ? '已找到' : '缺失'], ['当前运行方式', 'CPU 功能对照（非 SGX）']],
    kangaroo: [['Kangaroo 可执行程序', s.kangaroo_executable ? '已编译' : '未构建'], ['模型与实验', 'Iris 单次推理'], ['运行方式', 'Windows 适配版本']]
  }[activeProject];
  items.forEach(([label, value]) => {const row = document.createElement('div'); row.className = 'env-row'; appendText(row, 'span', label); appendText(row, 'strong', value); box.append(row)});
}
async function checkStatus() {
  const button = document.getElementById('refresh'); button.disabled = true;
  try {const response = await fetch('/api/status', {cache:'no-store'}); if (!response.ok) throw Error(); statusData = await response.json()}
  catch {statusData = null}
  finally {button.disabled = false; renderEnvironment()}
}
function renderMetrics(result) {
  const key = activeProject + JSON.stringify(result); if (key === lastMetricKey) return; lastMetricKey = key;
  createMetricCards(document.getElementById('detail-metrics'),projectMetrics(activeProject,result));
  renderProjectEvidence(document.getElementById('detail-chart'),activeProject,result);
}
function renderCurrentProject() {
  const job = experimentData[activeProject], result = job?.result;
  const busy = requestPending || Object.values(experimentData).some(x => x.state === 'running');
  const running = job?.state === 'running';
  const state = document.getElementById('run-state'); state.classList.toggle('running', running);
  document.getElementById('run-state-text').textContent = localRunError || (experimentReadError ? '运行记录读取失败，请稍后重试' : running ? '实验正在执行，等待真实结果' : job?.state === 'completed' ? '实验已完成' : job?.state === 'failed' ? '实验失败：' + job.error : busy ? '另一个项目正在运行，请稍候' : '尚未运行实验');
  document.getElementById('run-experiment').disabled = busy;
  const diagram = document.getElementById('detail-protocol');
  const key = demoView + activeProject + JSON.stringify(result);
  const frames = viewFrames(activeProject,result);
  const frame = running ? {kind:'running',phase:1} : job?.state === 'completed' ? frames.at(-1) : frames[0];
  document.getElementById('demo-heading').textContent = viewDefinition(activeProject).heading;
  if (lastProtocolKey !== key) {mountDemoView(diagram,activeProject,result,frame,{playing:running}); lastProtocolKey = key} else updateDemoView(diagram,frame,{playing:running});
  renderMetrics(result);
  document.getElementById('result-time').textContent = job?.timestamp || '';
  const resultNote=document.getElementById('result-note');resultNote.hidden=job?.state==='completed';resultNote.textContent=job?.state==='completed'?'':running?'实验正在运行…':job?.state==='failed'?'运行失败：'+job.error:'尚无运行结果。';
  document.getElementById('experiment-output').textContent = result ? JSON.stringify(result,null,2) : job?.error || (running ? '实验运行中…' : '尚无运行输出。');
}
async function readExperiments() {
  try {const response = await fetch('/api/experiments', {cache:'no-store'}); if (!response.ok) throw Error(); experimentData = await response.json(); experimentReadError = false}
  catch {experimentReadError = true}
  renderCurrentProject();
}
document.getElementById('run-experiment').onclick = async () => {
  const project = activeProject; requestPending = true; localRunError = ''; renderCurrentProject();
  try {
    const response = await fetch('/api/run/' + project, {method:'POST'}); const data = await response.json();
    if (!response.ok || !data.ok) throw Error(data.message || '实验启动失败');
    await readExperiments();
    if (activeProject === project) location.hash = project + '/results';
  } catch (error) {if (activeProject === project) localRunError = error.message}
  finally {requestPending = false; renderCurrentProject()}
};
document.getElementById('refresh').onclick = checkStatus;
document.querySelectorAll('[data-tab]').forEach(tab => {
  tab.onclick = () => {location.hash = activeProject + '/' + tab.dataset.tab};
  tab.onkeydown = event => {const keys = Object.keys(viewLabels), i = keys.indexOf(activeView); let next; if (event.key === 'ArrowRight') next = (i+1)%3; if (event.key === 'ArrowLeft') next = (i+2)%3; if (event.key === 'Home') next = 0; if (event.key === 'End') next = 2; if (next != null) {event.preventDefault(); location.hash = activeProject + '/' + keys[next]; document.getElementById('tab-' + keys[next]).focus()}};
});
window.addEventListener('hashchange', applyRoute);
buildNavigation(); applyRoute(); checkStatus(); readExperiments(); setInterval(readExperiments, 2000);
