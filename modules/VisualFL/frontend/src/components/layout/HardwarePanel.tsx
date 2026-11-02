import { useEffect, useState } from 'react';
import { Cpu, GraphicsCard, Memory, ArrowClockwise } from '@phosphor-icons/react';
import { Button } from '@radix-ui/themes';
import { api } from '../../api';
import type { SystemInfo } from '../../types';

const capacity = (bytes: number) => `${(bytes / 1024 ** 3).toFixed(1)} GB`;

export default function HardwarePanel() {
  const [info, setInfo] = useState<SystemInfo | null>(null);
  const [error, setError] = useState('');
  const [revision, setRevision] = useState(0);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let disposed = false;
    setLoading(true);
    api
      .system()
      .then((data) => {
        if (!disposed) {
          setInfo(data);
          setError('');
        }
      })
      .catch((e) => {
        if (!disposed) setError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => {
        if (!disposed) setLoading(false);
      });
    return () => {
      disposed = true;
    };
  }, [revision]);
  return (
    <div className="hardware-panel">
      <div className="hardware-actions">
        <span>本机硬件与当前训练环境</span>
        <Button
          size="2"
          variant="ghost"
          loading={loading}
          onClick={() => setRevision((value) => value + 1)}
        >
          <ArrowClockwise size={16} />
          刷新
        </Button>
      </div>
      {error && <p className="hardware-error">读取失败：{error}</p>}
      {!info ? (
        <div className="hardware-loading">
          {loading ? '正在读取 CPU、内存和显卡信息…' : '暂时无法读取运行环境。'}
        </div>
      ) : (
        <>
          <section className="hardware-item">
            <Cpu size={24} />
            <div>
              <h3>CPU</h3>
              <strong>{info.cpu.name}</strong>
              <p>{info.cpu.logical_cores} 个逻辑处理器</p>
            </div>
          </section>
          <section className="hardware-item">
            <Memory size={24} />
            <div>
              <h3>内存</h3>
              <strong>
                {info.memory.total_bytes
                  ? `${capacity(info.memory.available_bytes)} 可用 / ${capacity(info.memory.total_bytes)} 总量`
                  : '暂时无法读取'}
              </strong>
            </div>
          </section>
          <section className="hardware-item">
            <GraphicsCard size={24} />
            <div>
              <h3>GPU / 显卡</h3>
              {info.gpus.length ? (
                info.gpus.map((gpu, index) => (
                  <div className="gpu-entry" key={`${gpu.name}-${index}`}>
                    <strong>{gpu.name}</strong>
                    <p>
                      {gpu.memory_bytes ? `显存 ${capacity(gpu.memory_bytes)}` : '显存容量未获取'}
                      {gpu.driver ? `，驱动 ${gpu.driver}` : ''}
                    </p>
                  </div>
                ))
              ) : (
                <p>当前服务未获取到显卡信息。</p>
              )}
            </div>
          </section>
          <div className="training-device">
            <span>当前实际训练设备</span>
            <strong>{info.training.device.toUpperCase()}</strong>
          </div>
          <dl className="runtime-details">
            <div>
              <dt>操作系统</dt>
              <dd>{info.runtime.os}</dd>
            </div>
            <div>
              <dt>Python</dt>
              <dd>
                {info.runtime.python} / {info.runtime.architecture}
              </dd>
            </div>
            <div>
              <dt>NumPy</dt>
              <dd>{info.runtime.numpy ?? '未安装'}</dd>
            </div>
            <div>
              <dt>PyTorch</dt>
              <dd>{info.runtime.torch ?? '未安装'}</dd>
            </div>
          </dl>
        </>
      )}
    </div>
  );
}
