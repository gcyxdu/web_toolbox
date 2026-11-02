import {
  ClockCounterClockwise,
  ArrowUpRight,
  Copy,
  DownloadSimple,
  Trash,
} from '@phosphor-icons/react';
import { Button, Badge } from '@radix-ui/themes';
import { isActive, percent, statusNames, modelNames } from '../config';
import type { ExperimentConfig, Run } from '../types';

export default function HistoryPage({
  runs,
  onOpen,
  onClone,
  onDelete,
  deleting,
}: {
  runs: Run[];
  onOpen: (run: Run) => void;
  onClone: (config: ExperimentConfig) => void;
  onDelete: (run: Run) => void;
  deleting: string;
}) {
  return (
    <section className="content-panel history-panel">
      {!runs.length ? (
        <div className="page-empty">
          <ClockCounterClockwise size={42} weight="light" />
          <h3>还没有实验记录</h3>
          <p>在工作台启动一次实验，完成后即可回放与比较。</p>
        </div>
      ) : (
        <div className="table-scroll">
          <table className="runs-table">
            <thead>
              <tr>
                <th>实验名称</th>
                <th>模型 / 方法</th>
                <th>进度</th>
                <th>测试准确率</th>
                <th>状态</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((run) => (
                <tr key={run.id}>
                  <td>
                    <button className="run-name-button" onClick={() => onOpen(run)}>
                      {run.name}
                    </button>
                    <small>
                      {new Date(run.created_at).toLocaleString('zh-CN', { hour12: false })}
                    </small>
                  </td>
                  <td>
                    {modelNames[run.config.model ?? 'lr']} / {run.config.defense}
                    <small>
                      {run.config.attack === 'None' ? '无攻击' : run.config.attack} /{' '}
                      {run.config.dataset}
                    </small>
                  </td>
                  <td className="mono">
                    {run.metrics.round ?? 0} / {run.config.rounds}
                  </td>
                  <td className="mono">{percent(run.metrics.accuracy)}</td>
                  <td>
                    <Badge
                      color={
                        run.status === 'completed'
                          ? 'teal'
                          : run.status === 'failed'
                            ? 'red'
                            : 'gray'
                      }
                      variant="soft"
                    >
                      {statusNames[run.status]}
                    </Badge>
                  </td>
                  <td>
                    <div className="table-actions">
                      <Button
                        size="1"
                        variant="ghost"
                        onClick={() => onOpen(run)}
                        aria-label={`打开 ${run.name}`}
                      >
                        <ArrowUpRight size={16} />
                      </Button>
                      <Button
                        size="1"
                        variant="ghost"
                        color="gray"
                        onClick={() => onClone(run.config)}
                        aria-label={`复制 ${run.name}`}
                      >
                        <Copy size={15} />
                      </Button>
                      <Button asChild size="1" variant="ghost" color="gray">
                        <a href={`/api/runs/${run.id}/export`} aria-label={`导出 ${run.name}`}>
                          <DownloadSimple size={15} />
                        </a>
                      </Button>
                      <Button
                        size="1"
                        variant="ghost"
                        color="red"
                        disabled={isActive(run.status) || deleting === run.id}
                        aria-label={`删除 ${run.name}`}
                        title={isActive(run.status) ? '请先停止运行' : '删除记录'}
                        onClick={() => onDelete(run)}
                      >
                        <Trash size={16} />
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
