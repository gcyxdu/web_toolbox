import { useEffect, useState } from 'react';
import { Button, Dialog } from '@radix-ui/themes';
import { api } from '../../api';
import type { DatasetDetails, ExperimentConfig } from '../../types';

export default function DatasetDialog({
  open,
  onOpenChange,
  config,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  config: ExperimentConfig;
}) {
  const [data, setData] = useState<DatasetDetails | null>(null);
  const [error, setError] = useState('');
  useEffect(() => {
    if (!open) return;
    let disposed = false;
    setData(null);
    setError('');
    api
      .dataset(config)
      .then((result) => {
        if (!disposed) setData(result);
      })
      .catch((e) => {
        if (!disposed) setError(String(e.message));
      });
    return () => {
      disposed = true;
    };
  }, [open, config.dataset, config.seed, config.test_size]);
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Content maxWidth="850px" className="dataset-dialog">
        <Dialog.Title>{data?.name ?? `${config.dataset} 数据集`}</Dialog.Title>
        <Dialog.Description className="sr-only">
          查看真实样本、类别和当前训练测试划分。
        </Dialog.Description>
        {error ? (
          <p role="alert">{error}</p>
        ) : !data ? (
          <p>正在读取数据集…</p>
        ) : (
          <>
            <div className="dataset-facts">
              <span>
                <strong>{data.samples.toLocaleString()}</strong> 样本
              </span>
              <span>
                <strong>{data.classes}</strong> 类别
              </span>
              <span>
                <strong>{data.features}</strong> 特征
              </span>
              <span>
                训练 <strong>{data.train_samples}</strong> / 测试{' '}
                <strong>{data.test_samples}</strong>
              </span>
            </div>
            <div className="dataset-distribution" aria-label="类别样本数">
              {data.train_histogram.map((count, i) => (
                <div key={i}>
                  <span title={data.class_names[i]}>{data.class_names[i]}</span>
                  <div>
                    <i style={{ flex: count }} />
                    <b style={{ flex: data.test_histogram[i] }} />
                  </div>
                  <span>
                    {count} / {data.test_histogram[i]}
                  </span>
                </div>
              ))}
            </div>
            <div className="dataset-legend">
              <i />
              训练集 <b />
              测试集
            </div>
            <h3>样本预览</h3>
            {data.kind === 'image' ? (
              <div className="digit-examples">
                {data.examples.map((sample) => (
                  <figure key={sample.index}>
                    <svg
                      viewBox={`0 0 ${data.shape[1]} ${data.shape[0]}`}
                      role="img"
                      aria-label={`类别 ${data.class_names[sample.label]}，${sample.split === 'train' ? '训练集' : '测试集'}样本`}
                      shapeRendering="crispEdges"
                    >
                      {Array.from({ length: data.shape[0] * data.shape[1] }, (_, i) => {
                        const scale = 255 / (data.pixel_max ?? 16);
                        const pixel = (channel: number) =>
                          Math.round(
                            sample.values[i + channel * data.shape[0] * data.shape[1]] * scale,
                          );
                        return (
                          <rect
                            key={i}
                            x={i % data.shape[1]}
                            y={Math.floor(i / data.shape[1])}
                            width="1"
                            height="1"
                            fill={
                              (data.channels ?? 1) === 3
                                ? `rgb(${pixel(0)} ${pixel(1)} ${pixel(2)})`
                                : `rgb(${pixel(0)} ${pixel(0)} ${pixel(0)})`
                            }
                          />
                        );
                      })}
                    </svg>
                    <figcaption>
                      {data.class_names[sample.label]} ·{' '}
                      {sample.split === 'train' ? '训练' : '测试'}
                    </figcaption>
                  </figure>
                ))}
              </div>
            ) : (
              <div className="dataset-sample-table">
                <table className="runs-table">
                  <thead>
                    <tr>
                      <th>类别</th>
                      <th>划分</th>
                      {data.feature_names.map((name) => (
                        <th key={name}>{name}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {data.examples.map((sample) => (
                      <tr key={sample.index}>
                        <td>{data.class_names[sample.label]}</td>
                        <td>{sample.split === 'train' ? '训练' : '测试'}</td>
                        {sample.values.map((value, i) => (
                          <td key={i}>{Number(value.toFixed(3))}</td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <p className="dataset-source">
              数据来源：{data.source.replace(/（[^）]*）/g, '').trim()}。
            </p>
          </>
        )}
        <div className="dialog-actions">
          <Dialog.Close>
            <Button>完成</Button>
          </Dialog.Close>
        </div>
      </Dialog.Content>
    </Dialog.Root>
  );
}
