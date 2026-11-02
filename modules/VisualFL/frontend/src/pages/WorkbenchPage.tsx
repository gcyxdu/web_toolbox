import { useState } from 'react';
import { WarningCircle } from '@phosphor-icons/react';
import { Callout } from '@radix-ui/themes';
import Inspector from '../components/inspector/Inspector';
import Topology from '../components/topology/Topology';
import Metrics from '../components/metrics/Metrics';
import RunToolbar from '../components/workbench/RunToolbar';
import ReplayControls from '../components/workbench/ReplayControls';
import type { useWorkbench } from '../hooks/useWorkbench';

export default function WorkbenchPage({ work }: { work: ReturnType<typeof useWorkbench> }) {
  const [selected, setSelected] = useState('server');
  const [inspector, setInspector] = useState(() => window.innerWidth >= 1100);
  return (
    <div className="workbench-page">
      <RunToolbar
        work={work}
        onInspector={() => setInspector((value) => !value)}
      />
      {work.validationError && !work.selectedRun && (
        <Callout.Root color="amber" size="1">
          <Callout.Icon>
            <WarningCircle />
          </Callout.Icon>
          <Callout.Text>{work.validationError}</Callout.Text>
        </Callout.Root>
      )}
      {work.selectedRun?.error && (
        <Callout.Root color="red" size="1">
          <Callout.Icon>
            <WarningCircle />
          </Callout.Icon>
          <Callout.Text>{work.selectedRun.error}</Callout.Text>
        </Callout.Root>
      )}
      <div className={`workbench-grid ${inspector ? '' : 'inspector-hidden'}`}>
        <div className="workbench-main">
          <Topology
            config={work.config}
            data={work.data}
            projection={work.projection}
            selected={selected}
            onSelect={(id) => {
              setSelected(id);
              setInspector(true);
            }}
          />
          <ReplayControls work={work} />
          <Metrics projection={work.projection} events={work.visibleEvents} />
        </div>
        {inspector && (
          <Inspector
            config={work.config}
            catalog={work.catalog}
            onChange={work.setDraft}
            selected={work.config.clients.some((c) => c.id === selected) ? selected : 'server'}
            disabled={!!work.selectedRun}
            data={work.data}
            projection={work.projection}
            onClose={() => setInspector(false)}
          />
        )}
      </div>
    </div>
  );
}
