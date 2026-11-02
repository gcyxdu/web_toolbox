import { useState } from 'react';
import { X } from '@phosphor-icons/react';
import { Button, Callout, IconButton } from '@radix-ui/themes';
import { useWorkbench } from './hooks/useWorkbench';
import { createConfig } from './config';
import Sidebar, { type Page } from './components/layout/Sidebar';
import SystemDialog from './components/layout/SystemDialog';
import { useStoredBoolean } from './hooks/useStoredBoolean';
import { useRecordActions } from './hooks/useRecordActions';
import WorkbenchPage from './pages/WorkbenchPage';
import HistoryPage from './pages/HistoryPage';
import ComparePage from './pages/ComparePage';
import MethodsPage from './pages/MethodsPage';
import type { ExperimentConfig, Run } from './types';

const names: Record<Page, string> = {
  workbench: '实验台',
  history: '实验记录',
  compare: '对比分析',
  methods: '方法库',
};
export default function App() {
  const work = useWorkbench();
  const [page, setPage] = useState<Page>('workbench');
  const [settings, setSettings] = useState(false);
  const [collapsed, setCollapsed] = useStoredBoolean(
    'visualfl.sidebar-collapsed',
    window.innerWidth < 1100,
  );
  const records = useRecordActions(work);
  const openRun = (run: Run) => {
    work.selectRun(run);
    setPage('workbench');
  };
  const clone = (config: ExperimentConfig) => {
    work.edit(config);
    setPage('workbench');
  };
  return (
    <div
      className={`app-shell page-${page} ${collapsed ? 'sidebar-collapsed' : ''} ${page === 'workbench' ? 'is-workbench' : ''}`}
    >
      <Sidebar
        collapsed={collapsed}
        page={page}
        onNavigate={setPage}
        runs={work.runs}
        onSelect={openRun}
        onNew={() => clone(createConfig())}
        selectedId={work.selectedRun?.id}
        connected={work.connected}
        onToggle={() => setCollapsed(!collapsed)}
        onHardware={() => setSettings(true)}
      />
      <div className="app-content">
        <main className="main-content" aria-label={names[page]}>
          {records.deleted && (
            <Callout.Root className="record-undo" size="1">
              <Callout.Text>已删除“{records.deleted.name}”</Callout.Text>
              <Button
                size="1"
                variant="ghost"
                loading={!!records.busy}
                onClick={() => void records.restore()}
              >
                撤销
              </Button>
              <IconButton
                size="1"
                variant="ghost"
                aria-label="关闭删除提示"
                onClick={records.dismiss}
              >
                <X size={14} />
              </IconButton>
            </Callout.Root>
          )}
          {work.error && (
            <Callout.Root color="red" size="1" className="global-error">
              <Callout.Text>{work.error}</Callout.Text>
              <IconButton
                size="1"
                variant="ghost"
                aria-label="关闭错误提示"
                onClick={() => work.setError('')}
              >
                <X size={14} />
              </IconButton>
            </Callout.Root>
          )}
          {page === 'workbench' && <WorkbenchPage work={work} />}
          {page === 'history' && (
            <HistoryPage
              runs={work.runs}
              onOpen={openRun}
              onClone={clone}
              onDelete={(run) => void records.remove(run)}
              deleting={records.busy}
            />
          )}
          {page === 'compare' && <ComparePage runs={work.runs} />}
          {page === 'methods' && <MethodsPage catalog={work.catalog} onUse={clone} />}
        </main>
      </div>
      <SystemDialog open={settings} onOpenChange={setSettings} />
    </div>
  );
}
