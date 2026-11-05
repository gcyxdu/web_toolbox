let statusData = null;
let activeProject = '';
let activeView = 'overview';
let routeKind = 'home';
let experimentData = {};
let lastMetricKey = '';
let lastProtocolKey = '';
let requestPending = false;
let localRunError = '';
let experimentReadError = false;
let archiveLoaded = '';
const projectOrder = ['sgboost', 'visualfl', 'tee', 'kangaroo'];
const archiveIds = ['byte', 'ttsdc', 'seccom-tee', 'pqcp'];
const archiveNames = {byte: 'byte', ttsdc: 'TTSDC', 'seccom-tee': 'seccom-tee', pqcp: 'PQCP'};
const viewLabels = {overview: '概览', results: '结果', environment: '环境'};
const preferredDemoView = {sgboost: 'roles', visualfl: 'experiment', tee: 'experiment', kangaroo: 'experiment'};
let archiveOpen = true;
try { archiveOpen = sessionStorage.getItem('portal-archive-open') !== '0'; } catch {}

const navItems = [
  {id: 'sgboost', name: 'SGBoost', sub: '纵向联邦树 · 训练演示'},
  {id: 'visualfl', name: 'VisualFL', sub: '联邦可视化 · 训练演示'},
  {id: 'tee', name: 'TEE 逻辑回归', sub: '当前 CPU 对照', badge: '非 SGX'},
  {id: 'kangaroo', name: 'Kangaroo', sub: '密文决策树推理'},
  {id: 'desen', name: '脱敏工具集', sub: '多模态脱敏'}
];

const descriptions = {
  sgboost: {
    title: 'SGBoost',
    description: '纵向联邦树 · Credit-4 训练演示',
    run: '运行训练',
    help: '运行 SGBoost.jar，启动 CSP、组织方和数据方三个进程，完成 Credit-4 训练。默认轮次偏少，日志里的评估准确率只说明通路是否跑通。'
  },
  visualfl: {
    title: 'VisualFL',
    description: '联邦可视化 · 明文在线 FL',
    run: '运行训练',
    help: '执行 Iris、FedAvg、逻辑回归、3 个客户端、5 轮的默认配置。这是明文在线联邦学习，没有接入隐私协议。实验台可另开调整参数。'
  },
  tee: {
    title: 'TEE 逻辑回归',
    description: '当前 CPU 对照 · 非 SGX',
    run: '运行 CPU 对照',
    help: '在普通 CPU 上执行 Breast 数据划分、600 次梯度下降及留出集预测。非 SGX，不是原 TEE 协议的运行结果。'
  },
  kangaroo: {
    title: 'Kangaroo',
    description: '密文决策树推理 · Iris 明密文双通道核对',
    run: '运行实验',
    help: '加载 Iris 决策树，执行密文计算并对照明文输出。单次一致只说明通道核对，不是分类准确率。'
  }
};

/* 配置只展示适配器里的固定演示参数，不能在页面上改写成另一次实验。 */
const configSchemas = {
  sgboost: {
    desc: '带标签参数 · 默认少迭代仅作通路演示',
    fields: [
      ['数据集', 'Credit-4（纵向划分）'],
      ['参与角色', 'CSP · Organizer · DataOwner'],
      ['迭代轮次', '少迭代（演示默认）', '演示默认轮次偏少，准确率不可作最优宣传'],
      ['运行形态', '本机 Java 多进程协作', null, true]
    ]
  },
  visualfl: {
    desc: '带标签参数 · 明文在线联邦学习',
    fields: [
      ['数据集', 'Iris'],
      ['模型 / 聚合', 'LR · FedAvg'],
      ['规模', '3 个客户端 · 5 轮 · 无攻击'],
      ['隐私协议', '未接入', '明文在线 FL，无隐私协议', true]
    ]
  },
  tee: {
    desc: '带标签参数 · 当前只跑 CPU 对照',
    fields: [
      ['数据集', 'Breast'],
      ['划分', '训练约 70% / 留出约 30%'],
      ['迭代', '600 次梯度下降'],
      ['运行方式', 'CPU 功能对照（非 SGX）', '未执行 SGX，也不是原 TEE 协议结果', true]
    ]
  },
  kangaroo: {
    desc: '带标签参数 · 分步演示不提交新实验',
    fields: [
      ['数据集', 'Iris'],
      ['推理模式', '明密文双通道核对', '密文通道基于 SEAL；结果仅作一致性核对'],
      ['示例参数', '1（原项目 Iris 交互示例）', '命令参数与仓库适配器一致，不是分类测试集'],
      ['输出解读', '一致性核对 · 非分类准确率', null, true]
    ]
  }
};

const boundaryCopy = {
  sgboost: {
    kind: 'warning',
    lead: '诚实边界：',
    text: '默认少迭代配置下的准确率仅反映通路是否跑通，不得当作最优模型效果宣传。需要充分训练后再记录指标。训练准确率与验证准确率没有分开记录，Organizer 日志中的评估准确率只出现在「结果」。'
  },
  visualfl: {
    kind: 'info',
    lead: '诚实边界：',
    text: '明文在线 FL，无隐私协议接入。全局测试准确率与损失只有跑完才显示，缺测为「未记录」。'
  },
  tee: {
    kind: 'warning',
    lead: '诚实边界：',
    text: '非 SGX / CPU 对照。梯度下降在普通 CPU 上执行，不代表 SGX 或原 TEE 协议已运行。'
  },
  kangaroo: {
    kind: 'warning',
    lead: '诚实边界：',
    text: '单次示例上明文与密文预测一致，只说明通道核对通过，不得写成分类准确率，也不能外推为模型整体表现。'
  }
};

const envBoundary = {
  sgboost: {kind: 'info', lead: '', text: '只报告本机 JDK 与 JAR 是否存在。CSP / Organizer 进程未做在线探测，缺测保持「未探测」。'},
  visualfl: {kind: 'info', lead: '', text: '明文在线 FL，无隐私协议接入。健康检查未通过时不标成服务在线。'},
  tee: {kind: 'warning', lead: '非 SGX / CPU 对照：', text: '源码目录存在也不表示 SGX 已运行。原 App 目录缺失时，不能按 TEE 协议执行。'},
  kangaroo: {kind: 'warning', lead: '', text: '可执行程序是否编译只说明示例能不能启动。单次明密文一致不得写成分类准确率。'}
};

const WARN_ICON = '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><circle cx="8" cy="8" r="6.5" stroke="#D97706" stroke-width="1.4"/><path d="M8 5V8.5" stroke="#D97706" stroke-width="1.4" stroke-linecap="round"/><circle cx="8" cy="11" r="0.8" fill="#D97706"/></svg>';
const INFO_ICON = '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><circle cx="8" cy="8" r="6.5" stroke="#2563EB" stroke-width="1.4"/><path d="M8 5V8.5" stroke="#2563EB" stroke-width="1.4" stroke-linecap="round"/><circle cx="8" cy="11" r="0.8" fill="#2563EB"/></svg>';

function fillCallout(el, copy) {
  if (!el || !copy) return;
  el.className = 'callout' + (copy.kind === 'info' ? ' info' : '') + (el.id === 'module-banner' ? ' module-banner' : '');
  el.replaceChildren();
  const icon = document.createElement('div');
  icon.className = 'icon';
  icon.innerHTML = copy.kind === 'info' ? INFO_ICON : WARN_ICON;
  const body = document.createElement('div');
  body.className = 'body';
  if (copy.lead) appendText(body, 'strong', copy.lead);
  body.append(document.createTextNode(copy.text));
  el.append(icon, body);
}

function buildNavigation() {
  const nav = document.getElementById('project-nav');
  nav.replaceChildren();
  navItems.forEach(item => {
    const link = document.createElement('a');
    link.className = 'nav-item';
    link.dataset.project = item.id;
    link.href = item.id === 'desen' ? '#desen' : '#' + item.id + '/overview';
    appendText(link, 'span', item.name, 'name');
    appendText(link, 'span', item.sub, 'sub');
    if (item.badge) appendText(link, 'span', item.badge, 'badge-inline');
    nav.append(link);
  });
}

function updateNavigation() {
  document.querySelectorAll('#project-nav .nav-item').forEach(link => {
    const on = (routeKind === 'lab' && link.dataset.project === activeProject) || (routeKind === 'desen' && link.dataset.project === 'desen');
    link.classList.toggle('active', on);
    if (on) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  });
  document.querySelectorAll('.archive-item').forEach(link => {
    const on = routeKind === 'archive' && link.dataset.archive === activeArchive;
    if (on) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  });
  const open = archiveOpen || routeKind === 'archive';
  document.getElementById('archive-list').hidden = !open;
  const toggle = document.getElementById('archive-toggle');
  toggle.classList.toggle('is-open', open);
  toggle.setAttribute('aria-expanded', String(open));
}

let activeArchive = '';
function parseRoute() {
  const raw = location.hash.replace(/^#/, '');
  if (!raw || raw === 'home') return {kind: 'home'};
  const [head, rest] = raw.split('/');
  if (head === 'desen') return {kind: 'desen'};
  if (head === 'archive') return {kind: 'archive', id: archiveIds.includes(rest) ? rest : ''};
  if (projectOrder.includes(head)) return {kind: 'lab', id: head, view: Object.hasOwn(viewLabels, rest) ? rest : 'overview'};
  return {kind: 'home'};
}

function showFrame(kind) {
  document.getElementById('empty-state').hidden = kind !== 'home';
  document.getElementById('lab-frame').hidden = kind !== 'lab';
  document.getElementById('desen-frame').hidden = kind !== 'desen';
  document.getElementById('archive-frame').hidden = kind !== 'archive';
}

function renderConfig(id) {
  const schema = configSchemas[id];
  document.getElementById('config-desc').textContent = schema.desc;
  const box = document.getElementById('project-config');
  box.replaceChildren();
  schema.fields.forEach(([label, value, hint, muted]) => {
    const field = document.createElement('div');
    field.className = 'field';
    appendText(field, 'label', label);
    appendText(field, 'div', value, 'control' + (muted ? ' muted' : ''));
    if (hint) appendText(field, 'p', hint, 'hint');
    box.append(field);
  });
}

function previewItems(id, result) {
  if (id === 'kangaroo') {
    return [
      ['明文通道预测', result?.plaintext_result ?? '未记录'],
      ['密文通道预测', result?.ciphertext_result ?? '未记录'],
      ['明密文一致性', result?.correctness === true ? '一致' : result?.correctness === false ? '不一致' : '未记录'],
      ['分类准确率', '不适用 · 未评测']
    ];
  }
  if (id === 'sgboost') {
    const rounds = result?.iterations ?? result?.accuracy_history?.length;
    return [
      ['训练准确率', '未记录'],
      ['验证准确率', '未记录'],
      ['完成轮次', rounds ? String(rounds) + ' 轮' : '未记录'],
      ['耗时', metricTime(result?.duration_ms)]
    ];
  }
  if (id === 'visualfl') {
    return [
      ['全局测试准确率', result?.accuracy == null ? '未记录' : metricNumber(result.accuracy, 2) + '%'],
      ['全局测试损失', result?.loss_final == null ? '未记录' : metricNumber(result.loss_final, 4)],
      ['完成轮次', result?.rounds == null ? '未记录' : String(result.rounds) + ' 轮'],
      ['耗时', metricTime(result?.duration_ms)]
    ];
  }
  return [
    ['留出准确率', result?.accuracy == null ? '未记录' : metricNumber(result.accuracy, 2) + '%'],
    ['精确率', result?.precision == null ? '未记录' : metricNumber(result.precision, 2) + '%'],
    ['召回率', result?.recall == null ? '未记录' : metricNumber(result.recall, 2) + '%'],
    ['F1', result?.f1 == null ? '未记录' : metricNumber(result.f1, 2) + '%']
  ];
}

function paintPreview(id, result) {
  createMetricCards(document.getElementById('preview-metrics'), previewItems(id, result));
  const note = document.getElementById('preview-note');
  note.textContent = id === 'sgboost'
    ? '训练准确率与验证准确率未分别记录。评估准确率若已写入日志，只在「结果」页按原名展示。'
    : id === 'kangaroo'
      ? '分类准确率格固定为「不适用 · 未评测」，不把单次核对换算成准确率。'
      : '缺测显示「未记录」，不补造数字。';
  document.getElementById('preview-more').href = '#' + id + '/results';
}

function probeLabel(value, yes, no) {
  if (!statusData) return '未探测';
  return value ? yes : no;
}

function paintEnvPreview() {
  const card = document.getElementById('env-preview-card');
  card.hidden = activeProject !== 'sgboost';
  if (activeProject !== 'sgboost') return;
  const items = [
    ['JDK', probeLabel(statusData?.sgboost_java, '已检测到', '未检测到')],
    ['CSP 进程', '未探测'],
    ['Organizer', '未探测']
  ];
  createMetricCards(document.getElementById('env-preview'), items);
  fillCallout(document.getElementById('env-preview-callout'), {
    kind: 'info',
    lead: '',
    text: '真实指标须来自本机训练日志。JDK 按本机探测显示；CSP 与 Organizer 进程未探测，不标成在线。缺测一律「未记录」。'
  });
}

function flowSvg(label, inner) {
  return '<svg class="flow-svg" viewBox="0 0 560 220" fill="none" role="img" aria-label="' + label + '">' + inner + '</svg>';
}
function flowNode(x, y, w, h, title, sub, hot) {
  const fill = hot ? '#EFF6FF' : '#F8FAFC';
  const stroke = hot ? '#64748B' : '#94A3B8';
  const titleFill = hot ? '#1E3A5F' : '#334155';
  const cx = x + w / 2;
  return '<rect x="' + x + '" y="' + y + '" width="' + w + '" height="' + h + '" rx="8" fill="' + fill + '" stroke="' + stroke + '" stroke-width="1.5"/>' +
    '<text x="' + cx + '" y="' + (y + 22) + '" text-anchor="middle" fill="' + titleFill + '" font-size="12" font-weight="600">' + title + '</text>' +
    '<text x="' + cx + '" y="' + (y + 40) + '" text-anchor="middle" fill="#64748B" font-size="10">' + sub + '</text>';
}
const flowBlueprints = {
  kangaroo: {
    experiment: {
      desc: '实验过程 · 明密文双通道核对（非分类评测）',
      svg: flowSvg('Kangaroo 实验过程流程图',
        flowNode(16, 84, 108, 52, '加载模型', '决策树参数', false) +
        '<path d="M124 110 H140" stroke="#94A3B8" stroke-width="1.5"/>' +
        flowNode(140, 84, 110, 52, '明文推理', 'Iris 样本通道', false) +
        '<path d="M250 110 H274 V42 H300" stroke="#94A3B8" stroke-width="1.5" fill="none"/>' +
        '<path d="M274 110 V178 H300" stroke="#94A3B8" stroke-width="1.5" fill="none"/>' +
        flowNode(300, 16, 118, 52, '密文推理', 'SEAL 同态通道', true) +
        flowNode(300, 152, 118, 52, '明文对照', '同一样本', false) +
        '<path d="M418 42 H432 V110" stroke="#94A3B8" stroke-width="1.5" fill="none"/>' +
        '<path d="M418 178 H432 V110" stroke="#94A3B8" stroke-width="1.5" fill="none"/>' +
        '<path d="M432 110 H448" stroke="#94A3B8" stroke-width="1.5"/>' +
        flowNode(448, 84, 100, 52, '一致性核对', '非准确率指标', false))
    },
    roles: {
      desc: '角色交互 · 同一进程内的逻辑示意',
      svg: flowSvg('Kangaroo 角色交互',
        flowNode(24, 78, 140, 52, '查询输入', '示例参数 1', false) +
        '<path d="M164 104 H196" stroke="#94A3B8" stroke-width="1.5"/>' +
        flowNode(196, 78, 150, 52, '密文推理', 'SEAL 通道', true) +
        '<path d="M346 104 H378" stroke="#94A3B8" stroke-width="1.5"/>' +
        flowNode(378, 78, 158, 52, '明密文核对', '非分类准确率', false))
    }
  },
  sgboost: {
    experiment: {
      desc: '实验过程 · 少迭代训练通路',
      svg: flowSvg('SGBoost 实验过程',
        flowNode(20, 78, 140, 52, '装载 Credit-4', '纵向特征划分', false) +
        '<path d="M160 104 H196" stroke="#94A3B8" stroke-width="1.5"/>' +
        flowNode(196, 78, 160, 52, '少迭代建树', '演示默认轮次', true) +
        '<path d="M356 104 H392" stroke="#94A3B8" stroke-width="1.5"/>' +
        flowNode(392, 78, 148, 52, '写入评估日志', '非最优宣传', false))
    },
    roles: {
      desc: '角色交互 · CSP / Organizer / DataOwner',
      svg: flowSvg('SGBoost 角色交互流程图',
        flowNode(20, 24, 120, 56, 'Organizer', '协调训练轮次', true) +
        flowNode(220, 24, 120, 56, 'CSP', '密码服务方', false) +
        flowNode(420, 24, 120, 56, 'DataOwner', '特征方 × N', false) +
        '<path d="M140 52 H220" stroke="#94A3B8" stroke-width="1.5"/>' +
        '<path d="M340 52 H420" stroke="#94A3B8" stroke-width="1.5"/>' +
        '<path d="M80 80 V120" stroke="#94A3B8" stroke-width="1.5"/>' +
        '<path d="M280 80 V120" stroke="#94A3B8" stroke-width="1.5"/>' +
        '<path d="M480 80 V120" stroke="#94A3B8" stroke-width="1.5"/>' +
        '<rect x="80" y="120" width="400" height="72" rx="10" fill="#F8FAFC" stroke="#64748B" stroke-width="1.5"/>' +
        '<text x="280" y="148" text-anchor="middle" fill="#334155" font-size="13" font-weight="600">纵向联邦树 · Credit-4 训练演示</text>' +
        '<text x="280" y="168" text-anchor="middle" fill="#64748B" font-size="11">各方本地特征不出域 · 聚合分裂信息完成建树</text>')
    }
  },
  visualfl: {
    experiment: {
      desc: '实验过程 · 明文在线联邦学习',
      svg: flowSvg('VisualFL 实验过程',
        flowNode(16, 78, 150, 52, '客户端本地训练', '数据留在本地', false) +
        '<path d="M166 104 H198" stroke="#94A3B8" stroke-width="1.5"/>' +
        flowNode(198, 78, 150, 52, 'FedAvg 聚合', '明文模型更新', true) +
        '<path d="M348 104 H380" stroke="#94A3B8" stroke-width="1.5"/>' +
        flowNode(380, 78, 164, 52, '留出测试', '无隐私协议', false))
    },
    roles: {
      desc: '角色交互 · 客户端与聚合服务器',
      svg: flowSvg('VisualFL 角色交互',
        flowNode(24, 78, 150, 52, '三个客户端', '本地数据不出示意范围', false) +
        '<path d="M174 104 H206" stroke="#94A3B8" stroke-width="1.5"/>' +
        flowNode(206, 78, 150, 52, '聚合服务器', '明文在线 FL', true) +
        '<path d="M356 104 H388" stroke="#94A3B8" stroke-width="1.5"/>' +
        flowNode(388, 78, 148, 52, '评估节点', '全局测试集', false))
    }
  },
  tee: {
    experiment: {
      desc: '实验过程 · CPU 功能对照（非 SGX）',
      svg: flowSvg('TEE 逻辑回归 CPU 对照',
        flowNode(16, 78, 150, 52, '固定划分', 'Breast 训练 / 留出', false) +
        '<path d="M166 104 H198" stroke="#94A3B8" stroke-width="1.5"/>' +
        flowNode(198, 78, 160, 52, 'CPU 梯度下降', '非 SGX', true) +
        '<path d="M358 104 H390" stroke="#94A3B8" stroke-width="1.5"/>' +
        flowNode(390, 78, 154, 52, '留出预测', '实现核对', false))
    },
    roles: {
      desc: '角色交互 · 数据、CPU 训练与核对',
      svg: flowSvg('CPU 对照角色',
        flowNode(20, 78, 150, 52, '训练数据', '普通执行环境', false) +
        '<path d="M170 104 H202" stroke="#94A3B8" stroke-width="1.5"/>' +
        flowNode(202, 78, 150, 52, 'CPU 训练', '非 SGX', true) +
        '<path d="M352 104 H384" stroke="#94A3B8" stroke-width="1.5"/>' +
        flowNode(384, 78, 156, 52, '预测核对', '不是 TEE 证明', false))
    }
  }
};

function paintBlueprint() {
  const spec = flowBlueprints[activeProject][demoView] || flowBlueprints[activeProject].experiment;
  document.getElementById('flow-desc').textContent = spec.desc;
  document.getElementById('flow-blueprint').innerHTML = spec.svg;
}

function setBadge(el, textEl, kind, text) {
  el.className = 'status-badge ' + kind;
  textEl.textContent = text;
}

function renderEnvironment() {
  if (routeKind === 'desen') { renderDesenStatus(); return; }
  if (routeKind !== 'lab') return;
  const box = document.getElementById('env-list');
  box.replaceChildren();
  if (!statusData) {
    box.textContent = '环境检测暂不可用，请刷新检测。未探测项不标成在线。';
  } else {
    const s = statusData;
    const items = {
      sgboost: [['Java 运行环境', s.sgboost_java ? '已检测到' : '未检测到'], ['SGBoost.jar', s.sgboost_jar ? '已找到' : '未找到'], ['CSP / Organizer 进程', '未探测'], ['运行方式', '本机三个 Java 进程']],
      visualfl: [['VisualFL 服务', s.visualfl_listening ? '健康检查通过' : '未通过健康检查'], ['独立 Python 环境', s.visualfl_environment ? '已配置' : '未配置'], ['隐私协议', '未接入'], ['运行方式', 'PyTorch CPU · 明文在线 FL']],
      tee: [['RMT_V 源码目录', s.rmt_v_source ? '已找到' : '未找到'], ['原项目 App 目录', s.rmt_v_app ? '已找到' : '缺失'], ['当前运行方式', 'CPU 功能对照（非 SGX）']],
      kangaroo: [['Kangaroo 可执行程序', s.kangaroo_executable ? '已编译' : '未构建'], ['模型与实验', 'Iris 单次推理'], ['运行方式', '本机适配版本'], ['分类准确率', '不适用 · 未评测']]
    }[activeProject];
    items.forEach(([label, value]) => {
      const row = document.createElement('div');
      row.className = 'env-row';
      appendText(row, 'span', label);
      appendText(row, 'strong', value);
      box.append(row);
    });
  }
  fillCallout(document.getElementById('env-callout'), envBoundary[activeProject]);
  paintEnvPreview();
}

function desenWord(key) {
  if (!statusData || !Object.hasOwn(statusData, key)) return '未探测';
  return statusData[key] ? '服务在线' : '离线';
}
function renderDesenStatus() {
  const benchText = desenWord('desen_workbench');
  const evalText = desenWord('desen_eval');
  const badgeKind = benchText === '服务在线' ? 'done' : 'offline';
  setBadge(document.getElementById('desen-status'), document.getElementById('desen-status-text'), badgeKind, benchText);
  const benchEl = document.getElementById('desen-bench-state');
  const evalEl = document.getElementById('desen-eval-state');
  benchEl.textContent = benchText;
  evalEl.textContent = evalText;
  benchEl.classList.toggle('is-missing', benchText !== '服务在线');
  evalEl.classList.toggle('is-missing', evalText !== '服务在线');
}

function renderMetrics(result) {
  const items = result ? projectMetrics(activeProject, result) : previewItems(activeProject, null);
  const key = activeProject + JSON.stringify(items);
  if (key === lastMetricKey) return;
  lastMetricKey = key;
  createMetricCards(document.getElementById('detail-metrics'), items);
  renderProjectEvidence(document.getElementById('detail-chart'), activeProject, result);
}

function renderCurrentProject() {
  if (routeKind !== 'lab') return;
  const job = experimentData[activeProject];
  const result = job?.result;
  const busy = requestPending || Object.values(experimentData).some(x => x.state === 'running');
  const running = job?.state === 'running';
  let kind = 'idle';
  let badge = '未运行';
  let detail = '';
  if (localRunError) { kind = 'fail'; badge = '失败'; detail = localRunError; }
  else if (experimentReadError) { kind = 'fail'; badge = '失败'; detail = '运行记录读取失败，请稍后重试'; }
  else if (running) { kind = 'running'; badge = '运行中'; detail = '实验正在执行，等待真实结果'; }
  else if (job?.state === 'completed') { kind = 'done'; badge = '已完成'; }
  else if (job?.state === 'failed') { kind = 'fail'; badge = '失败'; detail = job.error || '实验失败'; }
  else if (busy) { detail = '另一个项目正在运行，请稍候'; }
  setBadge(document.getElementById('run-state'), document.getElementById('run-state-text'), kind, badge);
  const detailEl = document.getElementById('run-detail');
  detailEl.hidden = !detail;
  detailEl.textContent = detail;
  document.getElementById('run-experiment').disabled = busy;
  document.getElementById('tee-flag').hidden = activeProject !== 'tee';
  document.getElementById('module-banner').hidden = true;
  fillCallout(document.getElementById('overview-callout'), boundaryCopy[activeProject]);
  fillCallout(document.getElementById('results-callout'), boundaryCopy[activeProject]);
  paintBlueprint();
  paintPreview(activeProject, result);
  const diagram = document.getElementById('detail-protocol');
  const live = document.getElementById('live-demo');
  const showLive = running || job?.state === 'completed';
  live.hidden = !showLive;
  const key = demoView + activeProject + JSON.stringify(result);
  const frames = viewFrames(activeProject, result);
  const frame = running ? {kind: 'running', phase: 1} : job?.state === 'completed' ? frames.at(-1) : frames[0];
  document.getElementById('demo-heading').textContent = showLive ? '实测过程 · ' + viewDefinition(activeProject).heading : viewDefinition(activeProject).heading;
  if (showLive) {
    if (lastProtocolKey !== key) { mountDemoView(diagram, activeProject, result, frame, {playing: running}); lastProtocolKey = key; }
    else updateDemoView(diagram, frame, {playing: running});
  } else if (lastProtocolKey !== 'idle-' + key) {
    mountDemoView(diagram, activeProject, result, frame, {playing: false});
    lastProtocolKey = 'idle-' + key;
  }
  renderMetrics(result);
  document.getElementById('result-time').textContent = job?.timestamp || '';
  const resultNote = document.getElementById('result-note');
  if (job?.state === 'completed' && result?.note) {
    resultNote.hidden = false;
    resultNote.textContent = result.note;
  } else if (running) {
    resultNote.hidden = false;
    resultNote.textContent = '实验正在运行…';
  } else if (job?.state === 'failed') {
    resultNote.hidden = false;
    resultNote.textContent = '运行失败：' + (job.error || '');
  } else if (!result) {
    resultNote.hidden = false;
    resultNote.textContent = '尚无运行结果。缺测指标显示「未记录」。';
  } else resultNote.hidden = true;
  document.getElementById('experiment-output').textContent = result ? JSON.stringify(result, null, 2) : job?.error || (running ? '实验运行中…' : '尚无运行输出。');
  renderEnvironment();
}

function applyRoute() {
  const route = parseRoute();
  routeKind = route.kind;
  if (route.kind === 'lab') {
    if (activeProject !== route.id) {
      lastMetricKey = '';
      localRunError = '';
      lastProtocolKey = '';
      demoView = preferredDemoView[route.id] || 'experiment';
      refreshViewButtons();
    }
    activeProject = route.id;
    activeView = route.view;
    const data = descriptions[activeProject];
    document.title = data.title + ' · 数据安全融合';
    document.getElementById('detail-title').textContent = data.title;
    document.getElementById('detail-desc').textContent = data.description;
    document.getElementById('run-label').textContent = data.run;
    renderConfig(activeProject);
    document.getElementById('detail-help').textContent = data.help;
    document.getElementById('detail-link').classList.toggle('hidden', activeProject !== 'visualfl');
    document.querySelectorAll('[data-tab]').forEach(tab => {
      const selected = tab.dataset.tab === activeView;
      tab.setAttribute('aria-selected', String(selected));
      tab.tabIndex = selected ? 0 : -1;
    });
    Object.keys(viewLabels).forEach(view => { document.getElementById('view-' + view).hidden = view !== activeView; });
    renderCurrentProject();
  } else if (route.kind === 'desen') {
    document.title = '脱敏工具集 · 数据安全融合';
    renderDesenStatus();
  } else if (route.kind === 'archive') {
    activeArchive = route.id;
    document.title = (archiveNames[route.id] || '代码归档') + ' · 数据安全融合';
    renderArchive(route.id);
  } else {
    activeArchive = '';
    document.title = '数据安全融合';
  }
  if (route.kind !== 'archive') activeArchive = route.kind === 'archive' ? route.id : '';
  showFrame(route.kind);
  updateNavigation();
}

async function checkStatus() {
  const button = document.getElementById('refresh');
  button.disabled = true;
  try {
    const response = await fetch('/api/status', {cache: 'no-store'});
    if (!response.ok) throw Error();
    statusData = await response.json();
  } catch { statusData = null; }
  finally {
    button.disabled = false;
    if (routeKind === 'lab') renderEnvironment();
    if (routeKind === 'desen') renderDesenStatus();
  }
}

async function readExperiments() {
  try {
    const response = await fetch('/api/experiments', {cache: 'no-store'});
    if (!response.ok) throw Error();
    experimentData = await response.json();
    experimentReadError = false;
  } catch { experimentReadError = true; }
  renderCurrentProject();
}

function openWorkbench() {
  const panel = document.getElementById('workbench-panel');
  const frame = document.getElementById('workbench-frame');
  panel.hidden = false;
  if (!frame.getAttribute('src')) frame.src = 'http://127.0.0.1:8352/';
  panel.scrollIntoView({block: 'nearest'});
}

async function renderArchive(id) {
  const landing = document.getElementById('archive-landing');
  const browser = document.getElementById('archive-browser');
  const title = document.getElementById('archive-title');
  if (!id) {
    title.textContent = '代码归档';
    document.getElementById('archive-desc').textContent = '未验证仓库，仅供阅读源码，不与五个主入口平级。';
    landing.hidden = false;
    browser.hidden = true;
    archiveLoaded = '';
    return;
  }
  title.textContent = archiveNames[id];
  document.getElementById('archive-desc').textContent = '未验证 · 归档。这里只打开仓库文件，不运行训练或推理。';
  landing.hidden = true;
  browser.hidden = false;
  if (archiveLoaded === id) return;
  archiveLoaded = id;
  const tree = document.getElementById('archive-tree');
  const nameEl = document.getElementById('archive-file');
  const codeEl = document.getElementById('archive-pre');
  tree.replaceChildren();
  nameEl.textContent = archiveNames[id];
  codeEl.textContent = '正在读取…';
  async function list(path) {
    const response = await fetch('/api/list?id=' + encodeURIComponent(id) + '&path=' + encodeURIComponent(path));
    if (!response.ok) throw Error('list');
    return response.json();
  }
  async function openFile(path) {
    nameEl.textContent = archiveNames[id] + ' / ' + path;
    codeEl.textContent = '';
    const response = await fetch('/api/file?id=' + encodeURIComponent(id) + '&path=' + encodeURIComponent(path));
    codeEl.textContent = await response.text();
    tree.querySelectorAll('.file').forEach(node => node.classList.toggle('is-on', node.dataset.path === path));
  }
  async function mount(parent, path, depth) {
    const data = await list(path);
    data.dirs.forEach(dir => {
      const row = document.createElement('button');
      row.type = 'button';
      row.className = 'dir';
      row.style.paddingLeft = (12 + depth * 14) + 'px';
      row.textContent = dir;
      const kids = document.createElement('div');
      kids.hidden = true;
      let loaded = false;
      row.onclick = async () => {
        kids.hidden = !kids.hidden;
        if (!loaded) {
          loaded = true;
          try { await mount(kids, path ? path + '/' + dir : dir, depth + 1); }
          catch { kids.textContent = '无法读取'; }
        }
      };
      parent.append(row, kids);
    });
    data.files.forEach(file => {
      const row = document.createElement('button');
      row.type = 'button';
      row.className = 'file';
      row.style.paddingLeft = (12 + depth * 14) + 'px';
      row.textContent = file;
      row.dataset.path = path ? path + '/' + file : file;
      row.onclick = () => openFile(row.dataset.path);
      parent.append(row);
    });
    return data;
  }
  try {
    const data = await mount(tree, '', 0);
    const prefer = ['README.md', 'README', 'readme.md', 'CMakeLists.txt', 'Makefile'];
    const hit = prefer.find(name => data.files.includes(name));
    if (hit) await openFile(hit);
    else if (data.files[0]) await openFile(data.files[0]);
    else codeEl.textContent = '这个目录下没有可显示的文本文件。';
  } catch {
    codeEl.textContent = '源码服务未启动，请从门户入口重新打开。';
  }
}

document.getElementById('run-experiment').onclick = async () => {
  const project = activeProject;
  requestPending = true;
  localRunError = '';
  renderCurrentProject();
  try {
    const response = await fetch('/api/run/' + project, {method: 'POST'});
    const data = await response.json();
    if (!response.ok || !data.ok) throw Error(data.message || '实验启动失败');
    await readExperiments();
    if (activeProject === project && routeKind === 'lab') location.hash = project + '/results';
  } catch (error) {
    if (activeProject === project) localRunError = error.message;
  } finally {
    requestPending = false;
    renderCurrentProject();
  }
};
document.getElementById('refresh').onclick = checkStatus;
document.getElementById('open-workbench').onclick = openWorkbench;
document.getElementById('open-workbench-hero').onclick = openWorkbench;
document.getElementById('archive-toggle').onclick = () => {
  archiveOpen = !(archiveOpen || routeKind === 'archive');
  try { sessionStorage.setItem('portal-archive-open', archiveOpen ? '1' : '0'); } catch {}
  updateNavigation();
};
document.querySelectorAll('[data-tab]').forEach(tab => {
  tab.onclick = () => { location.hash = activeProject + '/' + tab.dataset.tab; };
  tab.onkeydown = event => {
    const keys = Object.keys(viewLabels);
    const i = keys.indexOf(activeView);
    let next;
    if (event.key === 'ArrowRight') next = (i + 1) % 3;
    if (event.key === 'ArrowLeft') next = (i + 2) % 3;
    if (event.key === 'Home') next = 0;
    if (event.key === 'End') next = 2;
    if (next != null) {
      event.preventDefault();
      location.hash = activeProject + '/' + keys[next];
      document.getElementById('tab-' + keys[next]).focus();
    }
  };
});
window.addEventListener('hashchange', applyRoute);
buildNavigation();
applyRoute();
checkStatus();
readExperiments();
setInterval(readExperiments, 2000);
