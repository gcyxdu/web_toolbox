import { Info } from '@phosphor-icons/react';
import { MethodFields, NumberField, SelectField } from '../forms/Fields';
import type { Catalog, ExperimentConfig } from '../../types';

export default function AttackSettings({
  config,
  catalog,
  onChange,
  disabled,
}: {
  config: ExperimentConfig;
  catalog: Catalog;
  onChange: (value: ExperimentConfig) => void;
  disabled: boolean;
}) {
  const change = (patch: Partial<ExperimentConfig>) => onChange({ ...config, ...patch });
  const attack = catalog.attacks.find((method) => method.id === config.attack);
  const defense = catalog.defenses.find((method) => method.id === config.defense);
  const malicious = config.clients.filter((client) => client.malicious);
  return (
    <div className="settings-content">
      <section className="settings-section">
        <h3>攻击方式</h3>
        <SelectField
          label="攻击方法"
          value={config.attack}
          disabled={disabled}
          options={catalog.attacks.map((method) => ({
            value: method.id,
            label:
              method.name +
              (method.id === 'BadNets' &&
              !['Digits', 'MNIST', 'CIFAR10', 'CIFAR100'].includes(config.dataset)
                ? '（仅图像）'
                : ''),
            disabled:
              method.id === 'BadNets' &&
              !['Digits', 'MNIST', 'CIFAR10', 'CIFAR100'].includes(config.dataset),
          }))}
          onChange={(value) =>
            change({
              attack: value as ExperimentConfig['attack'],
              attack_params: {},
              clients: config.clients.map((client) => ({ ...client, attack_params: {} })),
            })
          }
        />
        <p className="field-note">{attack?.description}</p>
        {config.attack !== 'None' && (
          <>
            <div className="field-grid">
              <NumberField
                label="开始轮次"
                value={config.attack_start}
                min={1}
                max={200}
                disabled={disabled}
                onChange={(attack_start) => change({ attack_start })}
              />
              <NumberField
                label="结束轮次"
                value={config.attack_end}
                min={1}
                max={200}
                disabled={disabled}
                placeholder="直到结束"
                onChange={(attack_end) => change({ attack_end })}
              />
            </div>
            {config.attack_end !== null && !disabled && (
              <button className="text-button" onClick={() => change({ attack_end: null })}>
                恢复持续攻击
              </button>
            )}
            <MethodFields
              classes={catalog.datasets.find((item) => item.id === config.dataset)?.classes ?? 10}
              method={attack}
              values={config.attack_params}
              disabled={disabled}
              onChange={(key, value) =>
                change({ attack_params: { ...config.attack_params, [key]: value } })
              }
            />
            <div className="info-note">
              <Info size={16} />
              <span>{malicious.length} 个攻击客户端。点击拓扑节点可修改角色和专属参数。</span>
            </div>
            {!malicious.length && (
              <p className="inline-warning">尚未选择攻击客户端，本次将不会执行投毒。</p>
            )}
          </>
        )}
      </section>
      <section className="settings-section">
        <h3>聚合与防御</h3>
        <SelectField
          label="聚合方法"
          value={config.defense}
          disabled={disabled}
          options={catalog.defenses.map((method) => ({
            value: method.id,
            label:
              method.name +
              (method.models && !method.models.includes(config.model)
                ? '（需 LeNet-5 / ResNet-18 / ResNet-20）'
                : ''),
            disabled: method.models ? !method.models.includes(config.model) : false,
          }))}
          onChange={(value) =>
            change({ defense: value as ExperimentConfig['defense'], defense_params: {} })
          }
        />
        <p className="field-note">{defense?.description}</p>
        {config.defense === 'LayerSift' && (
          <div className="layersift-preset" aria-label="LayerSift 默认配置">
            <span>固定层</span>
            <div className="layersift-layer-list">
              {defense?.presets?.[config.model]?.map((layer) => (
                <strong key={layer}>{layer}</strong>
              ))}
            </div>
            <dl className="detail-list">
              <div>
                <dt>投影维度</dt>
                <dd>{defense?.projection_dimensions?.[config.dataset]}</dd>
              </div>
              <div>
                <dt>筛选规则</dt>
                <dd>Multi-Krum</dd>
              </div>
              <div>
                <dt>数量上界 f</dt>
                <dd>
                  {Math.floor(
                    Math.max(2, Math.ceil(config.client_count * config.participation)) *
                      (config.defense_params.byzantine_ratio ?? 0.2),
                  )}
                </dd>
              </div>
            </dl>
          </div>
        )}
        <MethodFields
          classes={catalog.datasets.find((item) => item.id === config.dataset)?.classes ?? 10}
          method={defense}
          values={config.defense_params}
          disabled={disabled}
          onChange={(key, value) =>
            change({ defense_params: { ...config.defense_params, [key]: value } })
          }
        />
        <div className="info-note">
          <Info size={16} />
          <span>
            {config.defense === 'LayerSift'
              ? '筛选使用固定层，聚合使用入选客户端的完整更新。比例上界独立于客户端角色设置。'
              : '鲁棒聚合直接替换普通聚合。仅展示方法实际提供的处理信息。'}
          </span>
        </div>
      </section>
    </div>
  );
}
