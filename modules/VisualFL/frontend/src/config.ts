import type {
  ClientConfig,
  ExperimentConfig,
  Projection,
  RunEvent,
  MetricPoint,
  DataPreview,
} from './types';

export const clientId = (index: number) => `client-${String(index).padStart(2, '0')}`;
export const emptyClient = (id: string): ClientConfig => ({
  id,
  learning_rate: null,
  local_steps: null,
  malicious: false,
  attack_params: {},
});

export function createConfig(): ExperimentConfig {
  return {
    name: 'MNIST / LeNet-5 实验',
    backend: 'flpoison',
    dataset: 'MNIST',
    model: 'LeNet5',
    test_size: 1 / 7,
    algorithm: 'FedAvg',
    client_count: 12,
    participation: 1,
    rounds: 20,
    local_steps: 10,
    learning_rate: 0.1,
    batch_size: 32,
    distribution: 'dirichlet',
    alpha: 0.7,
    seed: 42,
    attack: 'Gaussian',
    attack_start: 5,
    attack_end: null,
    attack_params: {},
    defense: 'NormClipping',
    defense_params: {},
    clients: Array.from({ length: 12 }, (_, i) => ({
      ...emptyClient(clientId(i)),
      malicious: i === 2 || i === 7,
    })),
  };
}

export function resizeClients(config: ExperimentConfig, count: number): ExperimentConfig {
  const nextCount = Math.max(2, Math.min(40, Math.round(count)));
  return {
    ...config,
    client_count: nextCount,
    clients: Array.from({ length: nextCount }, (_, i) => {
      const old = config.clients.find((c) => c.id === clientId(i));
      return old ? { ...old, attack_params: { ...old.attack_params } } : emptyClient(clientId(i));
    }),
  };
}

export function normalizeConfig(input: Partial<ExperimentConfig>): ExperimentConfig {
  const base = createConfig();
  const clients = input.clients ?? [];
  return resizeClients(
    { ...base, ...input, model: input.model ?? 'lr', backend: 'flpoison', clients },
    input.client_count ?? base.client_count,
  );
}

export function updateClient(
  config: ExperimentConfig,
  id: string,
  patch: Partial<ClientConfig>,
): ExperimentConfig {
  return {
    ...config,
    clients: config.clients.map((c) =>
      c.id === id
        ? { ...c, ...patch, attack_params: { ...c.attack_params, ...patch.attack_params } }
        : c,
    ),
  };
}

export function projectEvents(
  events: Pick<RunEvent, 'seq' | 'type' | 'payload'>[],
  cursor = Infinity,
): Projection {
  const projection: Projection = {
    metrics: [],
    clients: {},
    round: 0,
    phase: '等待运行',
    data: null,
  };
  for (const event of events) {
    if (event.seq > cursor) break;
    const p = event.payload;
    if (event.type === 'data_prepared') projection.data = p as unknown as DataPreview;
    if (event.type === 'round_started') {
      projection.layersift = undefined;
      projection.round = p.round ?? 0;
      projection.phase = '本地训练';
      for (const id of Object.keys(projection.clients))
        projection.clients[id] = { state: 'idle', round: p.round, attack_active: false };
    }
    if (event.type === 'client_started' && p.client_id) {
      projection.clients[p.client_id] = {
        ...projection.clients[p.client_id],
        state: 'training',
        round: p.round,
      };
    }
    if (event.type === 'client_completed' && p.client_id) {
      projection.clients[p.client_id] = {
        ...projection.clients[p.client_id],
        ...p,
        state: 'uploaded',
      };
    }
    if (event.type === 'aggregation_started') projection.phase = '服务端聚合';
    if (event.type === 'aggregation_completed') {
      projection.phase = '全局评估';
      projection.layersift = p.layersift;
      for (const item of p.clients ?? [])
        if (item.client_id) {
          projection.clients[item.client_id] = {
            ...projection.clients[item.client_id],
            ...item,
            state: 'aggregated',
          };
        }
    }
    if (event.type === 'round_completed') {
      projection.round = p.round ?? 0;
      projection.metrics.push(p as MetricPoint);
      projection.phase = '本轮完成';
    }
    if (event.type === 'run_completed') projection.phase = '训练完成';
    if (event.type === 'run_cancelled') projection.phase = '已取消';
    if (event.type === 'run_failed') projection.phase = '运行失败';
    if (event.type === 'run_interrupted') projection.phase = '任务中断';
    if (['run_completed', 'run_cancelled', 'run_failed', 'run_interrupted'].includes(event.type)) {
      for (const client of Object.values(projection.clients)) {
        if (client.state === 'training' || client.state === 'uploaded') client.state = 'idle';
      }
    }
  }
  return projection;
}

export const statusNames: Record<string, string> = {
  queued: '准备中',
  running: '训练中',
  cancelling: '正在停止',
  completed: '已完成',
  failed: '失败',
  cancelled: '已取消',
  interrupted: '已中断',
};
export const isActive = (status?: string) =>
  ['queued', 'running', 'cancelling'].includes(status ?? '');
export const percent = (n?: number) =>
  typeof n === 'number' ? `${(n * 100).toFixed(1)}%` : '待运行';

export function downloadJson(value: unknown, name: string) {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' }),
  );
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export const modelNames = {
  lr: '线性分类器',
  LeNet5: 'LeNet-5',
  ResNet20: 'ResNet-20',
  ResNet18: 'ResNet-18',
  ResNet50: 'ResNet-50',
};
