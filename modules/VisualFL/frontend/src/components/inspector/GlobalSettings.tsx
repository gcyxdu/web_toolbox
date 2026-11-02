import { TextField } from '@radix-ui/themes';
import { resizeClients, modelNames } from '../../config';
import { NumberField, SelectField } from '../forms/Fields';
import type { Catalog, ExperimentConfig } from '../../types';

export default function GlobalSettings({
  config,
  catalog,
  onChange,
  disabled,
}: {
  config: ExperimentConfig;
  catalog: Catalog;
  onChange: (config: ExperimentConfig) => void;
  disabled: boolean;
}) {
  const change = (patch: Partial<ExperimentConfig>) => onChange({ ...config, ...patch });
  const backend = catalog.backends.find((engine) => engine.id === 'flpoison');
  const dataset = catalog.datasets.find((item) => item.id === config.dataset);
  const defense = catalog.defenses.find((method) => method.id === config.defense);
  const maxClients = Math.min(
    40,
    Math.floor(
      ((dataset?.samples ?? 1797) -
        Math.ceil((dataset?.samples ?? 1797) * (config.test_size ?? 0.2))) /
        8,
    ),
  );
  return (
    <div className="settings-content">
      <section className="settings-section">
        <h3>训练参数</h3>
        <div className="field">
          <label htmlFor="experiment-name">实验名称</label>
          <TextField.Root
            id="experiment-name"
            value={config.name}
            disabled={disabled}
            maxLength={80}
            onChange={(e) => change({ name: e.target.value })}
          />
        </div>
        <SelectField
          label="训练模型"
          value={config.model ?? 'lr'}
          disabled={disabled}
          options={(catalog.models ?? []).map((model) => ({
            value: model.id,
            label: modelNames[model.id] ?? model.name,
            disabled:
              !model.datasets.includes(config.dataset) ||
              (defense?.models ? !defense.models.includes(model.id) : false),
          }))}
          onChange={(value) => change({ model: value as ExperimentConfig['model'] })}
        />
        <div className="model-detail">随机初始化 · 本机训练</div>
        <div className="field-grid">
          <SelectField
            label="联邦算法"
            value={config.algorithm}
            disabled={disabled}
            options={(backend?.algorithms ?? ['FedAvg']).map((value) => ({ value, label: value }))}
            onChange={(value) => change({ algorithm: value as ExperimentConfig['algorithm'] })}
          />
          <NumberField
            label="客户端数量"
            value={config.client_count}
            min={2}
            max={maxClients}
            disabled={disabled}
            onChange={(value) => onChange(resizeClients(config, value))}
          />
        </div>
        <div className="field-grid">
          <NumberField
            label="通信轮数"
            value={config.rounds}
            min={1}
            max={200}
            disabled={disabled}
            onChange={(rounds) => change({ rounds })}
          />
          <NumberField
            label="参与比例"
            value={config.participation}
            min={0.2}
            max={1}
            step={0.1}
            disabled={disabled}
            onChange={(participation) => change({ participation })}
          />
        </div>
      </section>
      <section className="settings-section">
        <h3>本地训练默认值</h3>
        <div className="field-grid">
          <NumberField
            label="学习率"
            value={config.learning_rate}
            min={0.001}
            max={1}
            step={0.01}
            disabled={disabled}
            onChange={(learning_rate) => change({ learning_rate })}
          />
          <NumberField
            label="本地更新步数"
            value={config.algorithm === 'FedSGD' ? 1 : config.local_steps}
            min={1}
            max={50}
            disabled={disabled || config.algorithm === 'FedSGD'}
            onChange={(local_steps) => change({ local_steps })}
          />
        </div>
        <div className="field-grid">
          <NumberField
            label="Batch size"
            value={config.batch_size}
            min={8}
            max={256}
            step={8}
            disabled={disabled}
            onChange={(batch_size) => change({ batch_size })}
          />
          <NumberField
            label="随机种子"
            value={config.seed}
            min={0}
            max={2147483647}
            disabled={disabled}
            onChange={(seed) => change({ seed })}
          />
        </div>
        <p className="field-note">每步更新一个 minibatch。FedSGD 固定为一步。</p>
      </section>
    </div>
  );
}
