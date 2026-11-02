import { Settings as SlidersHorizontal, Monitor as Desktop } from '../icons/EvaIcons';
import { LockSimple, X } from '@phosphor-icons/react';
import { IconButton } from '@radix-ui/themes';
import GlobalSettings from './GlobalSettings';
import DataSettings from './DataSettings';
import AttackSettings from './AttackSettings';
import ClientSettings from './ClientSettings';
import type { Catalog, DataPreview, ExperimentConfig, Projection } from '../../types';

interface Props {
  config: ExperimentConfig;
  catalog: Catalog | null;
  onChange: (value: ExperimentConfig) => void;
  selected: string;
  disabled: boolean;
  data: DataPreview | null;
  projection: Projection;
  onClose: () => void;
}
export default function Inspector({
  config,
  catalog,
  onChange,
  selected,
  disabled,
  data,
  projection,
  onClose,
}: Props) {
  const server = selected === 'server';
  return (
    <aside className={`inspector ${server ? 'inspector-server' : 'inspector-client'}`}>
      <div className="inspector-heading">
        <div>
          {server ? <SlidersHorizontal size={18} /> : <Desktop size={18} />}
          <strong>{server ? '实验配置' : `Client ${selected.split('-')[1]}`}</strong>
        </div>
        <IconButton
          variant="ghost"
          color="gray"
          size="1"
          aria-label="收起配置面板"
          onClick={onClose}
        >
          <X size={16} />
        </IconButton>
      </div>
      {disabled && (
        <div className="frozen-note">
          <LockSimple size={14} />
          历史运行配置（只读）
        </div>
      )}
      {!catalog ? (
        <div className="inspector-loading">正在连接配置服务…</div>
      ) : (
        <div className="inspector-scroll">
          {server ? (
            <div className="server-settings">
              <GlobalSettings
                config={config}
                catalog={catalog}
                onChange={onChange}
                disabled={disabled}
              />
              <DataSettings
                config={config}
                catalog={catalog}
                onChange={onChange}
                disabled={disabled}
              />
              <AttackSettings
                config={config}
                catalog={catalog}
                onChange={onChange}
                disabled={disabled}
              />
            </div>
          ) : (
            <ClientSettings
              key={selected}
              id={selected}
              config={config}
              catalog={catalog}
              onChange={onChange}
              disabled={disabled}
              data={data?.clients.find((item) => item.id === selected)}
              runtime={projection.clients[selected]}
            />
          )}
        </div>
      )}
    </aside>
  );
}
