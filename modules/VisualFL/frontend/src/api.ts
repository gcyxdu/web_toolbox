import type { Catalog, DataPreview, ExperimentConfig, Run, RunEvent, Scenario } from './types';
import type { SystemInfo, DatasetDetails } from './types';

export async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...options?.headers },
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: '服务暂时无法连接' }));
    const detail: unknown = error.detail;
    const message = Array.isArray(detail)
      ? detail
          .map(
            (item: { loc?: string[]; msg?: string }) =>
              `${item.loc?.slice(1).join('.') ?? ''}: ${item.msg}`,
          )
          .join('；')
      : String(detail ?? '请求失败');
    throw new Error(message);
  }
  return response.json() as Promise<T>;
}
export const api = {
  system: () => request<SystemInfo>('/system'),
  dataset: (config: ExperimentConfig) =>
    request<DatasetDetails>(
      `/datasets/${config.dataset}?seed=${config.seed}&test_size=${config.test_size ?? 0.2}`,
    ),
  catalog: () => request<Catalog>('/catalog'),
  scenarios: () => request<Scenario[]>('/scenarios'),
  preview: (config: ExperimentConfig) =>
    request<DataPreview>('/preview', { method: 'POST', body: JSON.stringify(config) }),
  runs: () => request<Run[]>('/runs'),
  run: (id: string) => request<Run>(`/runs/${id}`),
  events: (id: string, after = 0) => request<RunEvent[]>(`/runs/${id}/events?after=${after}`),
  start: (config: ExperimentConfig) =>
    request<Run>('/runs', { method: 'POST', body: JSON.stringify(config) }),
  cancel: (id: string) => request<Run>(`/runs/${id}/cancel`, { method: 'POST' }),
  delete: (id: string) =>
    request<{ id: string; deleted: boolean }>(`/runs/${id}`, { method: 'DELETE' }),
  restore: (id: string) => request<Run>(`/runs/${id}/restore`, { method: 'POST' }),
};
