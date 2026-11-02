import {
  Network as Graph,
  Grid as SquaresFour,
  History as ClockCounterClockwise,
  Compare as ChartLineUp,
  Plus,
} from '../icons/EvaIcons';
import { CaretDown, CaretRight, Cpu, SidebarSimple } from '@phosphor-icons/react';
import { Button, IconButton } from '@radix-ui/themes';
import { statusNames } from '../../config';
import { useStoredBoolean } from '../../hooks/useStoredBoolean';
import type { Run } from '../../types';

export type Page = 'workbench' | 'history' | 'compare' | 'methods';
interface Props {
  page: Page;
  onNavigate: (page: Page) => void;
  runs: Run[];
  onSelect: (run: Run) => void;
  onNew: () => void;
  selectedId?: string;
  connected: boolean;
  collapsed: boolean;
  onToggle: () => void;
  onHardware: () => void;
}
export default function Sidebar({
  page,
  onNavigate,
  runs,
  onSelect,
  onNew,
  selectedId,
  connected,
  collapsed,
  onToggle,
  onHardware,
}: Props) {
  const [recentOpen, setRecentOpen] = useStoredBoolean('visualfl.recent-open', true);
  return (
    <aside className="sidebar">
      <div className="sidebar-heading">
        <a className="brand" href="/" aria-label="VisualFL 首页">
          <span className="brand-mark">
            <img src="/favicon.svg" width="32" height="32" alt="" />
          </span>
          {!collapsed && (
            <span>
              Visual<span className="brand-light">FL</span>
            </span>
          )}
        </a>
        <IconButton
          className="sidebar-toggle"
          variant="ghost"
          color="gray"
          size="1"
          aria-label={collapsed ? '展开侧栏' : '收起侧栏'}
          aria-expanded={!collapsed}
          title={collapsed ? '展开侧栏' : '收起侧栏'}
          onClick={onToggle}
        >
          <SidebarSimple size={18} />
        </IconButton>
      </div>
      <Button
        className="new-experiment"
        variant="outline"
        color="gray"
        onClick={onNew}
        aria-label="新建实验"
        title="新建实验"
      >
        <Plus size={17} />
        {!collapsed && '新建实验'}
      </Button>
      <nav aria-label="主导航">
        {(
          [
            ['workbench', Graph, '实验台'],
            ['history', ClockCounterClockwise, '实验记录'],
            ['compare', ChartLineUp, '对比分析'],
            ['methods', SquaresFour, '方法库'],
          ] as const
        ).map(([id, Icon, label]) => (
          <button
            key={id}
            className={`nav-item ${page === id ? 'active' : ''}`}
            onClick={() => onNavigate(id)}
            aria-current={page === id ? 'page' : undefined}
            aria-label={label}
            title={collapsed ? label : undefined}
          >
            <Icon size={19} weight={page === id ? 'duotone' : 'regular'} />
            {!collapsed && <span>{label}</span>}
          </button>
        ))}
      </nav>
      {!collapsed && (
        <section className="recent-section">
          <button
            className="recent-toggle"
            aria-expanded={recentOpen}
            onClick={() => setRecentOpen(!recentOpen)}
          >
            <span>最近实验</span>
            {recentOpen ? <CaretDown size={15} /> : <CaretRight size={15} />}
          </button>
          {recentOpen && (
            <div className="recent-runs">
              {runs.slice(0, 5).map((run) => (
                <button
                  key={run.id}
                  className={`recent-run ${selectedId === run.id ? 'active' : ''}`}
                  onClick={() => onSelect(run)}
                  title={run.name}
                >
                  <span className={`run-state-dot ${run.status}`} />
                  <div>
                    <strong>{run.name}</strong>
                    <small>{statusNames[run.status]}</small>
                  </div>
                </button>
              ))}
              {!runs.length && <p className="recent-empty">暂无实验</p>}
            </div>
          )}
        </section>
      )}
      <div className="sidebar-footer">
        <button
          className="nav-item sidebar-hardware"
          onClick={onHardware}
          aria-label="查看本机配置"
          title={collapsed ? '本机配置' : undefined}
        >
          <Cpu size={19} />
          {!collapsed && <span>本机配置</span>}
        </button>
        <div
          className={`connection ${connected ? 'online' : 'offline'}`}
          title={connected ? '本地服务已连接' : '等待连接本地服务'}
        >
          <span className="status-dot" />
          {!collapsed && (connected ? '本地服务已连接' : '等待连接本地服务')}
        </div>
      </div>
    </aside>
  );
}
