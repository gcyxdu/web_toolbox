export type Attack = 'None' | 'Gaussian' | 'SignFlipping' | 'BadNets';
export type Defense = 'Mean' | 'Median' | 'TrimmedMean' | 'NormClipping' | 'Krum' | 'LayerSift';
export type Model = 'lr' | 'LeNet5' | 'ResNet20' | 'ResNet18' | 'ResNet50';
export type Backend = 'numpy' | 'flpoison';
export interface ClientConfig {
  id: string;
  learning_rate: number | null;
  local_steps: number | null;
  malicious: boolean;
  attack_params: Record<string, number>;
}
export interface ExperimentConfig {
  name: string;
  backend: Backend;
  dataset: 'CIFAR10' | 'CIFAR100' | 'MNIST' | 'Digits' | 'Iris' | 'Wine';
  model: Model;
  test_size: number;
  algorithm: 'FedAvg' | 'FedSGD' | 'FedOpt';
  client_count: number;
  participation: number;
  rounds: number;
  local_steps: number;
  learning_rate: number;
  batch_size: number;
  distribution: 'iid' | 'dirichlet';
  alpha: number;
  seed: number;
  attack: Attack;
  attack_start: number;
  attack_end: number | null;
  attack_params: Record<string, number>;
  defense: Defense;
  defense_params: Record<string, number>;
  clients: ClientConfig[];
}
export interface ParameterField {
  key: string;
  label: string;
  default: number;
  min: number;
  max: number;
  step: number;
}
export interface Method {
  id: string;
  name: string;
  description: string;
  fields: ParameterField[];
  models?: Model[];
  presets?: Partial<Record<Model, string[]>>;
  projection_dimensions?: Partial<Record<ExperimentConfig['dataset'], number>>;
}
export interface EngineInfo {
  id: Backend;
  name: string;
  available: boolean;
  description: string;
  reason?: string;
  algorithms: string[];
  source: string;
}
export interface Catalog {
  attacks: Method[];
  defenses: Method[];
  backends: EngineInfo[];
  datasets: DatasetInfo[];
  models: {
    id: Model;
    name: string;
    datasets: ExperimentConfig['dataset'][];
    description: string;
  }[];
}
export interface DatasetInfo {
  id: ExperimentConfig['dataset'];
  name: string;
  samples: number;
  features: number;
  classes: number;
  kind: 'image' | 'table';
  shape: number[];
  pixel_max?: number;
  channels?: number;
  train_samples?: number;
  test_samples?: number;
  backdoor: boolean;
  source: string;
}
export interface DatasetDetails extends DatasetInfo {
  class_names: string[];
  feature_names: string[];
  train_samples: number;
  test_samples: number;
  train_histogram: number[];
  test_histogram: number[];
  examples: { index: number; label: number; split: 'train' | 'test'; values: number[] }[];
}
export interface MetricPoint {
  round: number;
  accuracy: number;
  loss: number;
  asr?: number;
  duration_ms?: number;
  attack_count?: number;
  participants?: number;
  source?: string;
}
export interface ClientDatum {
  id?: string;
  client_id?: string;
  learning_rate?: number;
  local_steps?: number;
  malicious?: boolean;
  samples?: number;
  histogram?: number[];
  update_norm?: number;
  original_norm?: number;
  clip_ratio?: number;
  clipped_norm?: number;
  weight?: number;
  selected?: boolean;
  score?: number;
  attack_active?: boolean;
  train_loss?: number;
  native_train_loss?: number;
  duration_ms?: number;
}
export interface DataPreview {
  train_samples: number;
  test_samples: number;
  partition_hash: string;
  classes: number;
  clients: ClientDatum[];
}
export interface EventPayload extends Partial<MetricPoint>, ClientDatum {
  clients?: ClientDatum[];
  client_ids?: string[];
  method?: string;
  backend?: string;
  error?: string;
  layersift?: LayerSiftReport;
  [key: string]: unknown;
}
export interface LayerSiftReport {
  mode: 'plaintext';
  selector: string;
  layers: { label: string; module: string; parameters: number }[];
  selected_dimensions: number;
  full_dimensions: number;
  parameter_ratio: number;
  projection_dimension: number;
  byzantine_budget: number;
  selected_count: number;
  participant_count: number;
  round: number;
}
export interface RunEvent {
  seq: number;
  type: string;
  payload: EventPayload;
  timestamp?: string;
  run_id?: string;
}
export type RunStatus =
  'queued' | 'running' | 'cancelling' | 'completed' | 'failed' | 'cancelled' | 'interrupted';
export interface Run {
  id: string;
  name: string;
  status: RunStatus;
  config: ExperimentConfig;
  metrics: Partial<MetricPoint>;
  created_at: string;
  updated_at: string;
  error: string | null;
}
export interface Scenario {
  id: string;
  title: string;
  description: string;
  config: Partial<ExperimentConfig>;
}
export interface ClientRuntime extends ClientDatum {
  state: 'idle' | 'training' | 'uploaded' | 'aggregated';
  round?: number;
}
export interface Projection {
  metrics: MetricPoint[];
  clients: Record<string, ClientRuntime>;
  round: number;
  phase: string;
  data: DataPreview | null;
  layersift?: LayerSiftReport;
}

export interface SystemInfo {
  observed_at: string;
  cpu: { name: string; logical_cores: number };
  memory: { total_bytes: number; available_bytes: number };
  gpus: { name: string; memory_bytes: number | null; driver?: string; source?: string }[];
  runtime: {
    os: string;
    architecture: string;
    python: string;
    numpy: string | null;
    torch: string | null;
  };
  training: { device: string; gpu_in_use: boolean; note: string };
}
