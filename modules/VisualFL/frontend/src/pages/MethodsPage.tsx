import {
  ShieldCheck,
  ShieldWarning,
  WaveSine,
  ArrowsDownUp,
  Bug,
  IntersectThree,
  AlignCenterHorizontal,
  Funnel,
  Scissors,
  CrosshairSimple,
  Stack,
} from '@phosphor-icons/react';
import { Button } from '@radix-ui/themes';
import { createConfig } from '../config';
import type { Catalog, ExperimentConfig, Method } from '../types';

const methodIcons = {
  LayerSift: Stack,
  Gaussian: WaveSine,
  SignFlipping: ArrowsDownUp,
  BadNets: Bug,
  Mean: IntersectThree,
  Median: AlignCenterHorizontal,
  TrimmedMean: Funnel,
  NormClipping: Scissors,
  Krum: CrosshairSimple,
};

export default function MethodsPage({
  catalog,
  onUse,
}: {
  catalog: Catalog | null;
  onUse: (config: ExperimentConfig) => void;
}) {
  if (!catalog) return <div className="page-empty">正在连接本地服务…</div>;
  function apply(method: Method, kind: 'attack' | 'defense') {
    const config = createConfig();
    if (kind === 'attack') {
      config.attack = method.id as ExperimentConfig['attack'];
      config.defense = 'Mean';
      config.name = `${method.name} / 攻击实验`;
    } else {
      config.defense = method.id as ExperimentConfig['defense'];
      config.name = `${method.name} / 防御实验`;
    }
    onUse(config);
  }
  const groups = [
    {
      kind: 'attack' as const,
      title: '投毒攻击',
      Icon: ShieldWarning,
      methods: catalog.attacks.filter((item) => item.id !== 'None'),
    },
    { kind: 'defense' as const, title: '聚合与防御', Icon: ShieldCheck, methods: catalog.defenses },
  ];
  return (
    <section className="content-panel methods-panel">
      <div className="method-columns">
        {groups.map(({ kind, title, Icon, methods }) => (
          <section key={kind} className={`method-column method-column-${kind}`} aria-label={title}>
            <header className="method-column-heading">
              <span className="method-heading-icon">
                <Icon size={22} weight="duotone" />
              </span>
              <h2>{title}</h2>
              <span className="method-count">{methods.length} 项</span>
            </header>
            <div className="method-list">
              {methods.map((method) => {
                const MethodIcon = methodIcons[method.id as keyof typeof methodIcons] ?? Icon;
                return (
                  <article className="method-row" key={method.id}>
                    <span className="method-symbol">
                      <MethodIcon size={22} />
                    </span>
                    <div className="method-description">
                      <strong>{method.name}</strong>
                      <p>{method.description}</p>
                      {!!method.fields.length && (
                        <small>{method.fields.map((field) => field.label).join(' / ')}</small>
                      )}
                    </div>
                    <Button
                      className="method-apply"
                      variant="outline"
                      color="gray"
                      size="2"
                      onClick={() => apply(method, kind)}
                      aria-label={`配置${method.name}实验`}
                    >
                      配置实验
                    </Button>
                  </article>
                );
              })}
            </div>
          </section>
        ))}
      </div>
    </section>
  );
}
