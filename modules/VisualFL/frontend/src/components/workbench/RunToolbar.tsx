import {
  Play,
  Stop,
  Copy,
  DownloadSimple,
  SlidersHorizontal,
  UploadSimple,
} from '@phosphor-icons/react';
import { Button } from '@radix-ui/themes';
import { useRef } from 'react';
import { api } from '../../api';
import { downloadJson, normalizeConfig, statusNames } from '../../config';
import type { useWorkbench } from '../../hooks/useWorkbench';
type Workbench = ReturnType<typeof useWorkbench>;

export default function RunToolbar({
  work,
  onInspector,
}: {
  work: Workbench;
  onInspector: () => void;
}) {
  const file = useRef<HTMLInputElement>(null);
  async function importConfig(selected?: File) {
    if (!selected) return;
    try {
      const parsed = JSON.parse(await selected.text());
      const next = normalizeConfig(parsed.config ?? parsed);
      await api.preview(next);
      work.edit(next);
    } catch (e) {
      work.setError(`配置无法导入：${e instanceof Error ? e.message : String(e)}`);
    }
    if (file.current) file.current.value = '';
  }
  return (
    <div className="run-toolbar">
      <div className="run-heading">
        <span className={`run-status run-status-${work.selectedRun?.status ?? 'draft'}`}>
          {work.selectedRun ? statusNames[work.selectedRun.status] : '配置实验'}
        </span>
        <strong title={work.config.name}>{work.config.name}</strong>
      </div>
      <div className="run-actions">
        <Button
          variant="ghost"
          color="gray"
          onClick={() => file.current?.click()}
          aria-label="导入配置"
        >
          <UploadSimple size={16} />
        </Button>
        <input
          type="file"
          ref={file}
          accept=".json,application/json"
          hidden
          onChange={(e) => void importConfig(e.target.files?.[0])}
        />
        {work.selectedRun ? (
          <Button variant="ghost" color="gray" asChild>
            <a href={`/api/runs/${work.selectedRun.id}/export`} aria-label="导出实验记录">
              <DownloadSimple size={16} />
            </a>
          </Button>
        ) : (
          <Button
            variant="ghost"
            color="gray"
            aria-label="导出配置"
            onClick={() =>
              downloadJson(
                { format: 'visualfl.config.v1', config: work.draft },
                'visualfl-config.json',
              )
            }
          >
            <DownloadSimple size={16} />
          </Button>
        )}
        <Button variant="soft" color="gray" aria-label="打开配置面板" onClick={onInspector}>
          <SlidersHorizontal size={16} />
        </Button>
        {work.active ? (
          <Button
            color="gray"
            variant="outline"
            disabled={work.selectedRun?.status === 'cancelling'}
            onClick={() => void work.cancel()}
          >
            <Stop size={14} weight="fill" />
            停止训练
          </Button>
        ) : work.selectedRun ? (
          <Button
            onClick={() =>
              work.edit({ ...work.config, name: `${work.config.name.slice(0, 70)} / 副本` })
            }
          >
            <Copy size={15} />
            复制配置
          </Button>
        ) : (
          <Button
            disabled={!work.connected || !!work.validationError || work.busy}
            loading={work.busy}
            onClick={() => void work.launch()}
          >
            <Play size={14} weight="fill" />
            启动实验
          </Button>
        )}
      </div>
    </div>
  );
}
