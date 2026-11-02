import { useEffect, useMemo, useRef, useState } from 'react';
import { Checkbox, Callout } from '@radix-ui/themes';
import { ChartLineUp } from '@phosphor-icons/react';
import { api } from '../api';
import { percent, projectEvents, modelNames } from '../config';
import Chart from '../components/metrics/LazyChart';
import type { ChartSeries } from '../components/metrics/Chart';
import type { Run, MetricPoint } from '../types';
import { chartColors } from '../components/metrics/chartColors';

export default function ComparePage({ runs }: { runs: Run[] }) {
  const eligible = runs.filter((run) => run.metrics.accuracy !== undefined);
  const [selected, setSelected] = useState<string[]>(() =>
    eligible.slice(0, 2).map((run) => run.id),
  );
  const [data, setData] = useState<Record<string, MetricPoint[]>>({});
  const [error, setError] = useState('');
  const initialized = useRef(eligible.length > 0);
  const selectedRuns = useMemo(
    () => eligible.filter((run) => selected.includes(run.id)),
    [runs, selected],
  );
  const revision = selectedRuns.map((run) => `${run.id}:${run.metrics.round ?? 0}`).join(',');
  useEffect(() => {
    let disposed = false;
    Promise.all(
      selected
        .filter((id) => eligible.some((run) => run.id === id))
        .map(async (id) => [id, projectEvents(await api.events(id)).metrics] as const),
    )
      .then((items) => {
        if (!disposed) {
          setData(Object.fromEntries(items));
          setError('');
        }
      })
      .catch((e) => {
        if (!disposed) setError(String(e));
      });
    return () => {
      disposed = true;
    };
  }, [selected.join(','), revision]);
  const availableIds = eligible.map((run) => run.id).join(',');
  useEffect(() => {
    setSelected((ids) => {
      const valid = ids.filter((id) => eligible.some((run) => run.id === id));
      if (!initialized.current && eligible.length) {
        initialized.current = true;
        return valid.length ? valid : eligible.slice(0, 2).map((run) => run.id);
      }
      return valid;
    });
  }, [availableIds]);
  const colors = chartColors(selectedRuns.length);
  const series: ChartSeries[] = selectedRuns.map((run, i) => ({
    name:
      selectedRuns.filter((item) => item.name === run.name).length > 1
        ? `${run.name} (${i + 1})`
        : run.name,
    metrics: data[run.id] ?? [],
    color: colors[i],
  }));
  return (
    <section className="content-panel compare-panel">
      {eligible.length ? (
        <>
          <div className="compare-picker">
            {eligible.map((run) => (
              <label key={run.id}>
                <Checkbox
                  checked={selected.includes(run.id)}
                  disabled={!selected.includes(run.id) && selected.length >= 4}
                  onCheckedChange={(checked) =>
                    setSelected((ids) =>
                      checked ? [...ids, run.id] : ids.filter((id) => id !== run.id),
                    )
                  }
                />
                <span>{run.name}</span>
                <strong className="mono">{percent(run.metrics.accuracy)}</strong>
              </label>
            ))}
          </div>
          {error && (
            <Callout.Root color="red">
              <Callout.Text>{error}</Callout.Text>
            </Callout.Root>
          )}
          <div className="comparison-charts">
            <div>
              <h3>全局测试准确率</h3>
              <Chart series={series} label="对比准确率" />
            </div>
            <div>
              <h3>测试损失</h3>
              <Chart series={series} kind="loss" label="对比损失" />
            </div>
          </div>
          <div className="table-scroll">
            <table className="runs-table">
              <thead>
                <tr>
                  <th>实验</th>
                  <th>模型 / 攻击 / 聚合</th>
                  <th>客户端 / 种子</th>
                  <th>学习率 / 步数</th>
                  <th>准确率</th>
                  <th>ASR</th>
                </tr>
              </thead>
              <tbody>
                {selectedRuns.map((run, i) => (
                  <tr key={run.id}>
                    <td>
                      <span className="series-key" style={{ backgroundColor: colors[i] }} />
                      {series[i].name}
                    </td>
                    <td>
                      {modelNames[run.config.model ?? 'lr']}
                      <small>
                        {run.config.attack} / {run.config.defense}
                      </small>
                    </td>
                    <td className="mono">
                      {run.config.client_count} / {run.config.seed}
                    </td>
                    <td className="mono">
                      {run.config.learning_rate} / {run.config.local_steps}
                    </td>
                    <td className="mono">{percent(run.metrics.accuracy)}</td>
                    <td className="mono">
                      {run.metrics.asr === undefined ? '不适用' : percent(run.metrics.asr)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      ) : (
        <div className="page-empty">
          <ChartLineUp size={42} weight="light" />
          <h3>先完成一次真实训练</h3>
          <p>建议比较基线、投毒和加入防御三个场景。</p>
        </div>
      )}
    </section>
  );
}
