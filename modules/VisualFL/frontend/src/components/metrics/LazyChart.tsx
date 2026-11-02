import { lazy, Suspense } from 'react';
import type { ComponentProps } from 'react';
import type ChartComponent from './Chart';

const Chart = lazy(() => import('./Chart'));
export default function LazyChart(props: ComponentProps<typeof ChartComponent>) {
  return (
    <Suspense
      fallback={
        <div className="chart-empty">
          <span>正在准备图表…</span>
        </div>
      }
    >
      <Chart {...props} />
    </Suspense>
  );
}
