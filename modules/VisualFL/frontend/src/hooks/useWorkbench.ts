import { useEffect, useMemo, useRef, useState } from 'react';
import { api } from '../api';
import { createConfig, isActive, normalizeConfig, projectEvents } from '../config';
import { useService } from './useService';
import { useRunEvents } from './useRunEvents';
import { useReplay } from './useReplay';
import type { DataPreview, ExperimentConfig, Run } from '../types';

export function useWorkbench() {
  const [draft, setDraft] = useState<ExperimentConfig>(() => {
    try {
      const saved = localStorage.getItem('visualfl.draft.v1');
      return saved ? normalizeConfig(JSON.parse(saved)) : createConfig();
    } catch {
      return createConfig();
    }
  });
  const [selectedRun, setSelectedRun] = useState<Run | null>(null);
  const [preview, setPreview] = useState<DataPreview | null>(null);
  const [validationError, setValidationError] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const selectionVersion = useRef(0);
  const service = useService(setError);
  const { events, setEvents } = useRunEvents(
    selectedRun?.id,
    setSelectedRun,
    service.setRuns,
    setError,
  );
  const replay = useReplay(events, selectedRun?.id);
  useEffect(() => {
    let disposed = false;
    let saved: string | null = null;
    try {
      saved = localStorage.getItem('visualfl.selected-run.v1');
    } catch {
      /* Optional persistence. */
    }
    if (saved)
      api
        .run(saved)
        .then((run) => {
          if (!disposed && selectionVersion.current === 0) setSelectedRun(run);
        })
        .catch(() => {
          /* A removed run can be ignored without losing the draft. */
        });
    return () => {
      disposed = true;
    };
  }, []);
  useEffect(() => {
    if (selectedRun)
      try {
        localStorage.setItem('visualfl.selected-run.v1', selectedRun.id);
      } catch {
        /* Optional persistence. */
      }
  }, [selectedRun?.id]);
  useEffect(() => {
    try {
      localStorage.setItem('visualfl.draft.v1', JSON.stringify(draft));
    } catch {
      /* Storage can be disabled. */
    }
  }, [draft]);
  useEffect(() => {
    if (selectedRun) return;
    let disposed = false;
    setPreview(null);
    const timer = setTimeout(() => {
      api
        .preview(draft)
        .then((data) => {
          if (!disposed) {
            setPreview(data);
            setValidationError('');
          }
        })
        .catch((e) => {
          if (!disposed) setValidationError(String(e.message));
        });
    }, 350);
    return () => {
      disposed = true;
      clearTimeout(timer);
    };
  }, [draft, selectedRun?.id]);
  const projection = useMemo(() => projectEvents(replay.visibleEvents), [replay.visibleEvents]);
  const config = selectedRun?.config ?? draft;
  const data = selectedRun ? projection.data : preview;
  async function launch() {
    selectionVersion.current++;
    setBusy(true);
    setError('');
    try {
      const run = await api.start(draft);
      setSelectedRun(run);
      service.setRuns((old) => [run, ...old]);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  async function cancel() {
    if (!selectedRun) return;
    try {
      setSelectedRun(await api.cancel(selectedRun.id));
    } catch (e) {
      setError(String(e));
    }
  }
  function edit(next: ExperimentConfig = draft) {
    selectionVersion.current++;
    try {
      localStorage.removeItem('visualfl.selected-run.v1');
    } catch {
      /* Optional persistence. */
    }
    setSelectedRun(null);
    setEvents([]);
    setDraft(normalizeConfig(next));
    replay.setReplaying(false);
    replay.setPlaying(false);
  }
  function selectRun(run: Run) {
    selectionVersion.current++;
    setSelectedRun(run);
    setError('');
  }
  return {
    draft,
    setDraft,
    config,
    ...service,
    selectedRun,
    selectRun,
    events,
    ...replay,
    data,
    projection,
    validationError,
    error,
    setError,
    busy,
    launch,
    cancel,
    edit,
    active: isActive(selectedRun?.status),
  };
}
