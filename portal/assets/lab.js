let statusData = null;
let activeProject = 'sgboost';
let activeView = 'overview';
let experimentData = {};
let lastMetricKey = '';
let lastProtocolProject = '';
let requestPending = false;
let localRunError = '';
let experimentReadError = false;
const projectOrder = ['sgboost', 'visualfl', 'tee', 'kangaroo'];
const viewLabels = {overview: '项目概览', results: '实验结果', environment: '环境状态'};
const descriptions = {
  sgboost: {title: 'SGBoost', menu: 'SGBoost', description: '纵向联邦树模型训练', run: '运行 SGBoost 训练', help: '使用原项目 JAR 与 Credit-4 示例数据，启动 CSP、组织方和数据方三个 Java 进程。已适配本机数据路径，准确率与训练耗时读取 Organizer 日志；运行结束后清理进程。'},
  visualfl: {title: 'VisualFL', menu: 'VisualFL', description: '联邦学习可视化实验台', run: '运行 Iris 联邦训练', help: '使用独立 Python 环境与 PyTorch CPU。默认运行 Iris、3 个客户端、5 轮 FedAvg 联邦训练；完整配置和曲线可在 VisualFL 实验台查看。当前实验没有接入隐私保护协议。'},
  tee: {title: 'TEE 逻辑回归', menu: 'TEE 逻辑回归', description: '当前运行：CPU 功能对照（非 SGX）', run: '运行 CPU 对照', help: '原 SGX/RMT_V 构建脚本引用的 App 目录缺失，真实 TEE 执行还需要兼容的 Linux、SGX SDK、SGX SSL 和运行环境。当前脚本仅使用原目录 Breast 数据重新固定划分训练集和测试集，执行普通 CPU 逻辑回归；不是原 SGX 协议复现。'},
  kangaroo: {title: 'Kangaroo', menu: 'Kangaroo', description: '隐私保护决策树推理', run: '运行 Iris 密文推理', help: '使用 Microsoft SEAL 4.1.2 与 GCC 构建的 Windows 适配版本，执行 correctness 目录的 Iris 单次交互式密文推理。将密文输出与明文输出比较；该结果是单个示例的一致性，不能当作分类准确率。'}
};
function buildNavigation() {
  const nav = document.getElementById('project-nav');
  projectOrder.forEach(id => {
    const group = document.createElement('div'); group.className = 'nav-project'; group.dataset.project = id;
    const link = document.createElement('a'); link.className = 'project-link'; link.href = '#' + id + '/overview';
    const label = document.createElement('span'); label.textContent = descriptions[id].menu;
    const arrow = document.createElement('span'); arrow.className = 'nav-chevron'; arrow.textContent = '›'; arrow.setAttribute('aria-hidden', 'true');
    link.append(label, arrow); group.append(link);
    const children = document.createElement('div'); children.className = 'nav-children';
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
  document.getElementById('project-config').textContent = replayInfo[activeProject].inputs;
  document.getElementById('detail-help').textContent = data.help;
  document.getElementById('detail-link').classList.toggle('hidden', activeProject !== 'visualfl');
  document.querySelectorAll('.nav-project').forEach(group => {
    const selected = group.dataset.project === activeProject;
    group.classList.toggle('active', selected);
    group.querySelector('.project-link').setAttribute('aria-expanded', String(selected));
    group.querySelectorAll('.nav-children a').forEach(link => {if (selected && link.dataset.view === activeView) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current')});
  });
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
  const box = document.getElementById('detail-metrics'), chart = document.getElementById('detail-chart'); box.replaceChildren(); chart.replaceChildren();
  if (!result) return;
  const items = [['准确率', result.accuracy != null ? result.accuracy + '%' : '不适用'], ['正确性', result.correctness === true ? '输出一致' : result.correctness === false ? '输出不同' : '未独立验证'], ['耗时', result.duration_ms != null ? result.duration_ms + ' ms' : '—']];
  items.forEach(([label,value]) => {const el = document.createElement('div'); el.className = 'metric-box'; appendText(el, 'span', label); appendText(el, 'strong', value); box.append(el)});
  const values = result.loss || result.accuracy_history;
  if (values && values.length > 1) {
    appendText(chart, 'h3', result.loss ? '训练损失（采样记录）' : '迭代准确率（%）');
    const max = Math.max(...values), min = Math.min(...values);
    const ns = 'http://www.w3.org/2000/svg', svg = document.createElementNS(ns, 'svg'); svg.setAttribute('viewBox', '0 0 500 120'); svg.classList.add('result-chart'); svg.setAttribute('role','img'); svg.setAttribute('aria-label', result.loss ? '训练损失曲线' : '迭代准确率曲线');
    const line = document.createElementNS(ns, 'polyline'); line.setAttribute('points', values.map((v,i) => `${15 + i*470/(values.length-1)},${100 - (v-min)*80/(max-min || 1)}`).join(' ')); line.setAttribute('fill','none'); line.setAttribute('stroke','#679578'); line.setAttribute('stroke-width','2'); svg.append(line); chart.append(svg);
  }
}
function renderCurrentProject() {
  const job = experimentData[activeProject], result = job?.result;
  const busy = requestPending || Object.values(experimentData).some(x => x.state === 'running');
  const running = job?.state === 'running';
  const state = document.getElementById('run-state'); state.classList.toggle('running', running);
  document.getElementById('run-state-text').textContent = localRunError || (experimentReadError ? '运行记录读取失败，请稍后重试' : running ? '实验正在执行，等待真实结果' : job?.state === 'completed' ? '实验已完成' : job?.state === 'failed' ? '实验失败：' + job.error : busy ? '另一个项目正在运行，请稍候' : '尚未运行实验');
  document.getElementById('run-experiment').disabled = busy;
  const diagram = document.getElementById('detail-protocol'), stage = running ? 1 : job?.state === 'completed' ? 2 : 0;
  if (lastProtocolProject !== activeProject) {diagram.replaceChildren(); drawProtocol(diagram, activeProject, stage); lastProtocolProject = activeProject} else updateProtocolStage(diagram, stage);
  renderMetrics(result);
  document.getElementById('result-time').textContent = job?.timestamp || '';
  document.getElementById('result-note').textContent = result?.note || (running ? '当前实验正在执行，完成后显示实际结果。' : job?.state === 'failed' ? '运行失败：' + job.error : '尚无运行结果。');
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
  } catch (error) {localRunError = error.message}
  finally {requestPending = false; renderCurrentProject()}
};
document.getElementById('refresh').onclick = checkStatus;
document.querySelectorAll('[data-tab]').forEach(tab => {
  tab.onclick = () => {location.hash = activeProject + '/' + tab.dataset.tab};
  tab.onkeydown = event => {const keys = Object.keys(viewLabels), i = keys.indexOf(activeView); let next; if (event.key === 'ArrowRight') next = (i+1)%3; if (event.key === 'ArrowLeft') next = (i+2)%3; if (event.key === 'Home') next = 0; if (event.key === 'End') next = 2; if (next != null) {event.preventDefault(); location.hash = activeProject + '/' + keys[next]; document.getElementById('tab-' + keys[next]).focus()}};
});
window.addEventListener('hashchange', applyRoute);
buildNavigation(); applyRoute(); checkStatus(); readExperiments(); setInterval(readExperiments, 2000);
