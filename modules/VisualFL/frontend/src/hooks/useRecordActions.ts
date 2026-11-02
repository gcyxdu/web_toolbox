import { useState } from 'react';
import { api } from '../api';
import type { Run } from '../types';
import type { useWorkbench } from './useWorkbench';

export function useRecordActions(work: ReturnType<typeof useWorkbench>) {
  const [deleted, setDeleted] = useState<Run | null>(null);
  const [busy, setBusy] = useState('');
  async function remove(run: Run) {
    setBusy(run.id);
    try {
      await api.delete(run.id);
      work.setRuns((items) => items.filter((item) => item.id !== run.id));
      if (work.selectedRun?.id === run.id) work.edit();
      setDeleted(run);
    } catch (e) {
      work.setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy('');
    }
  }
  async function restore() {
    if (!deleted) return;
    setBusy(deleted.id);
    try {
      const restored = await api.restore(deleted.id);
      work.setRuns((items) =>
        [restored, ...items.filter((item) => item.id !== restored.id)].sort((a, b) =>
          b.created_at.localeCompare(a.created_at),
        ),
      );
      setDeleted(null);
    } catch (e) {
      work.setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy('');
    }
  }
  return { deleted, busy, remove, restore, dismiss: () => setDeleted(null) };
}
