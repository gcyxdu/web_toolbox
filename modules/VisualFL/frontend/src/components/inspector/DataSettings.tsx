import { NumberField, SelectField } from '../forms/Fields';
import { useState } from 'react';
import { Button } from '@radix-ui/themes';
import { resizeClients } from '../../config';
import DatasetDialog from '../datasets/DatasetDialog';
import type { Catalog, ExperimentConfig } from '../../types';

export default function DataSettings({
  config,
  onChange,
  disabled,
  catalog,
}: {
  config: ExperimentConfig;
  onChange: (value: ExperimentConfig) => void;
  disabled: boolean;
  catalog: Catalog;
}) {
  const [details, setDetails] = useState(false);
  const change = (patch: Partial<ExperimentConfig>) => {
    const next = { ...config, ...patch };
    const metadata = catalog.datasets.find((item) => item.id === next.dataset);
    if (next.attack === 'BadNets' && metadata) {
      if ((next.attack_params.target_label ?? 0) >= metadata.classes) {
        next.attack_params = { ...next.attack_params, target_label: 0 };
      }
      next.clients = next.clients.map((client) => {
        if ((client.attack_params.target_label ?? 0) < metadata.classes) return client;
        const { target_label: _target, ...rest } = client.attack_params;
        return { ...client, attack_params: rest };
      });
    }
    const capacity = Math.min(
      40,
      Math.floor(
        ((metadata?.samples ?? 1797) -
          Math.ceil((metadata?.samples ?? 1797) * (next.test_size ?? 0.2))) /
          8,
      ),
    );
    onChange(resizeClients(next, Math.min(next.client_count, capacity)));
  };
  return (
    <div className="settings-content">
      <section className="settings-section">
        <h3>数据集</h3>
        <SelectField
          label="训练数据集"
          value={config.dataset}
          disabled={disabled}
          options={catalog.datasets.map((item) => ({
            value: item.id,
            label: item.name,
            disabled: config.defense === 'LayerSift' && item.kind !== 'image',
          }))}
          onChange={(value) =>
            change({
              dataset: value as ExperimentConfig['dataset'],
              test_size: value === 'MNIST' ? 1 / 7 : value.startsWith('CIFAR') ? 1 / 6 : 0.2,
              ...(['Iris', 'Wine'].includes(value) ? { model: 'lr' as const } : {}),
              ...(!['Digits', 'MNIST', 'CIFAR10', 'CIFAR100'].includes(value) &&
              config.attack === 'BadNets'
                ? {
                    attack: 'None' as const,
                    attack_params: {},
                    clients: config.clients.map((c) => ({ ...c, attack_params: {} })),
                  }
                : {}),
            })
          }
        />
        <Button
          variant="outline"
          className="dataset-details-button"
          onClick={() => setDetails(true)}
        >
          查看数据与样本
        </Button>
        {['MNIST', 'CIFAR10', 'CIFAR100'].includes(config.dataset) ? (
          <div className="field">
            <label>训练 / 测试划分</label>
            <span className="dataset-split">
              {config.dataset === 'MNIST' ? '60,000' : '50,000'} / 10,000
            </span>
          </div>
        ) : (
          <NumberField
            label="测试集比例"
            value={config.test_size ?? 0.2}
            min={0.1}
            max={0.4}
            step={0.05}
            disabled={disabled}
            onChange={(test_size) => change({ test_size })}
          />
        )}
        <SelectField
          label="划分方式"
          value={config.distribution}
          disabled={disabled}
          options={[
            { value: 'iid', label: 'IID / 均匀随机' },
            { value: 'dirichlet', label: 'Non-IID / Dirichlet' },
          ]}
          onChange={(value) => change({ distribution: value as ExperimentConfig['distribution'] })}
        />
        {config.distribution === 'dirichlet' && (
          <NumberField
            label="Dirichlet α"
            value={config.alpha}
            min={0.05}
            max={100}
            step={0.05}
            disabled={disabled}
            onChange={(alpha) => change({ alpha })}
            hint="较小的 α 通常带来更强的数据异构"
          />
        )}
      </section>
      <DatasetDialog open={details} onOpenChange={setDetails} config={config} />
    </div>
  );
}
