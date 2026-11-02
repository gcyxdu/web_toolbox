import { ArrowCounterClockwise } from '@phosphor-icons/react';
import { useEffect, useState } from 'react';
import ClientDevice from '../icons/ClientDevice';
import { api } from '../../api';
import { Button, Switch } from '@radix-ui/themes';
import { updateClient } from '../../config';
import { MethodFields, NumberField } from '../forms/Fields';
import type { Catalog, ClientDatum, ExperimentConfig, ClientRuntime } from '../../types';

const classNameCache = new Map<string, Promise<string[]>>();

export default function ClientSettings({
  id,
  config,
  catalog,
  onChange,
  disabled,
  data,
  runtime,
}: {
  id: string;
  config: ExperimentConfig;
  catalog: Catalog;
  onChange: (value: ExperimentConfig) => void;
  disabled: boolean;
  data?: ClientDatum;
  runtime?: ClientRuntime;
}) {
  const [classNames, setClassNames] = useState<string[]>([]);
  useEffect(() => {
    let disposed = false;
    setClassNames([]);
    if (!classNameCache.has(config.dataset)) {
      const request = api.dataset(config).then((details) => details.class_names);
      classNameCache.set(config.dataset, request);
      void request.catch(() => classNameCache.delete(config.dataset));
    }
    void classNameCache
      .get(config.dataset)!
      .then((names) => {
        if (!disposed) setClassNames(names);
      })
      .catch(() => undefined);
    return () => {
      disposed = true;
    };
  }, [config.dataset]);
  const client = config.clients.find((item) => item.id === id);
  if (!client) return <p className="empty-copy">该节点已移除。</p>;
  const effectiveRate = client.learning_rate ?? config.learning_rate;
  const effectiveSteps =
    config.algorithm === 'FedSGD' ? 1 : (client.local_steps ?? config.local_steps);
  const attack = catalog.attacks.find((method) => method.id === config.attack);
  const histogram = data?.histogram ?? [];
  const totalSamples = data?.samples ?? histogram.reduce((sum, count) => sum + count, 0);
  const maxCount = Math.max(...histogram, 1);
  const coveredClasses = histogram.filter((count) => count > 0).length;
  const bins = histogram
    .map((count, index) => {
      const name = classNames[index];
      return {
        label: name && !/^\d+$/.test(name) ? name : `类别 ${index}`,
        count,
        share: totalSamples ? (count / totalSamples) * 100 : 0,
      };
    })
    .sort((a, b) => b.count - a.count);
  return (
    <div className="settings-content">
      {
        <section className="settings-section">
          <div className="section-label">
            <h3>本地训练</h3>
            {!disabled && (
              <Button
                size="1"
                variant="ghost"
                title="让此客户端的学习率和更新步数跟随全局设置"
                onClick={() =>
                  onChange(updateClient(config, id, { learning_rate: null, local_steps: null }))
                }
              >
                <ArrowCounterClockwise />
                使用全局参数
              </Button>
            )}
          </div>
          <p className="client-parameter-mode">
            学习率：{client.learning_rate === null ? '跟随全局' : '单独设置'} · 更新步数：
            {client.local_steps === null ? '跟随全局' : '单独设置'}
          </p>
          <div className="field-grid">
            <NumberField
              label="客户端学习率"
              value={effectiveRate}
              min={0.001}
              max={1}
              step={0.01}
              disabled={disabled}
              onChange={(learning_rate) => onChange(updateClient(config, id, { learning_rate }))}
              hint={client.learning_rate === null ? '继承全局默认值' : '仅此客户端生效'}
            />
            <NumberField
              label="客户端更新步数"
              value={effectiveSteps}
              min={1}
              max={50}
              disabled={disabled || config.algorithm === 'FedSGD'}
              onChange={(local_steps) => onChange(updateClient(config, id, { local_steps }))}
              hint={client.local_steps === null ? '继承全局默认值' : '仅此客户端生效'}
            />
          </div>
        </section>
      }
      {
        <section className="settings-section">
          <h3>节点角色</h3>
          <label className="switch-row">
            <span>
              <ClientDevice size={27} malicious />
              设为恶意客户端
            </span>
            <Switch
              aria-label="设为恶意客户端"
              checked={client.malicious}
              disabled={disabled}
              onCheckedChange={(malicious) => {
                const next = updateClient(config, id, { malicious });
                onChange(
                  malicious && config.attack === 'None' ? { ...next, attack: 'Gaussian' } : next,
                );
              }}
            />
          </label>
          {client.malicious && config.attack !== 'None' && (
            <>
              <p className="field-note">{attack?.name} / 可单独设置攻击参数</p>
              <MethodFields
                classes={catalog.datasets.find((item) => item.id === config.dataset)?.classes ?? 10}
                method={attack}
                values={client.attack_params}
                inherited={config.attack_params}
                disabled={disabled}
                onChange={(key, value) =>
                  onChange(updateClient(config, id, { attack_params: { [key]: value } }))
                }
              />
            </>
          )}
        </section>
      }
      {
        <section className="settings-section">
          <div className="section-label">
            <h3>各类别样本分布</h3>
          </div>
          {data?.histogram ? (
            <>
              <div className="distribution-summary">
                <span>
                  总样本 <strong>{totalSamples.toLocaleString()}</strong>
                </span>
                <span>
                  包含 <strong>{coveredClasses}</strong> / {histogram.length} 类
                </span>
              </div>
              <p className="distribution-caption">按样本数由多到少排列，长条表示样本更多。</p>
              <div className="distribution-table-heading">
                <span>类别</span>
                <span>样本数 / 占比</span>
              </div>
              <div
                className="client-distribution"
                role="list"
                aria-label="该客户端各类别样本数量和占比"
              >
                {bins.map(({ count, label, share }) => (
                  <div
                    key={label}
                    className="distribution-row"
                    role="listitem"
                    title={`${label}：${count} 个样本，占该客户端 ${share.toFixed(1)}%`}
                  >
                    <span className="distribution-label">{label}</span>
                    <span className="distribution-track">
                      <span style={{ width: `${(count / maxCount) * 100}%` }} />
                    </span>
                    <strong>{count}</strong>
                    <span className="distribution-share">{share.toFixed(1)}%</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <p className="empty-copy">正在准备数据划分</p>
          )}
        </section>
      }
      {runtime && (
        <section className="settings-section">
          <h3>运行观测</h3>
          <dl className="detail-list">
            {runtime.selected !== undefined && (
              <div>
                <dt>本轮筛选结果</dt>
                <dd>{runtime.selected ? '入选聚合' : '未入选'}</dd>
              </div>
            )}
            {runtime.score !== undefined && (
              <div>
                <dt>Multi-Krum 距离分数</dt>
                <dd className="mono">{runtime.score.toPrecision(5)}</dd>
              </div>
            )}
            <div>
              <dt>上传更新 L2 范数</dt>
              <dd className="mono">{runtime.update_norm?.toFixed(4) ?? '未上传'}</dd>
            </div>
            {runtime.clip_ratio !== undefined && (
              <div>
                <dt>裁剪保留比例</dt>
                <dd className="mono">{(runtime.clip_ratio * 100).toFixed(1)}%</dd>
              </div>
            )}
            {runtime.weight !== undefined && (
              <div>
                <dt>聚合权重</dt>
                <dd className="mono">{runtime.weight.toFixed(4)}</dd>
              </div>
            )}
            <div>
              <dt>攻击是否在当前轮执行</dt>
              <dd>{runtime.attack_active ? '是' : '否'}</dd>
            </div>
          </dl>
        </section>
      )}
    </div>
  );
}
