import { useEffect, useState, type Dispatch, type SetStateAction } from 'react';
import { api } from '../api';
import { isActive } from '../config';
import type { Run, RunEvent } from '../types';

export function useRunEvents(
  runId: string | undefined,
  setRun: Dispatch<SetStateAction<Run | null>>,
  setRuns: Dispatch<SetStateAction<Run[]>>,
  setError: Dispatch<SetStateAction<string>>,
) {
  const [events, setEvents] = useState<RunEvent[]>([]);
  useEffect(() => {
    setEvents([]);
    if (!runId) return;
    let disposed = false,
      pending = false,
      finished = false,
      after = 0;
    const poll = async () => {
      if (pending || disposed || finished) return;
      pending = true;
      try {
        const [run, batch] = await Promise.all([api.run(runId), api.events(runId, after)]);
        if (!disposed) {
          setRun(run);
          if (batch.length) {
            after = batch[batch.length - 1].seq;
            setEvents((old) => [...old, ...batch]);
          }
          setRuns((old) =>
            [run, ...old.filter((r) => r.id !== run.id)].sort((a, b) =>
              b.created_at.localeCompare(a.created_at),
            ),
          );
          finished = !isActive(run.status) && batch.length === 0;
        }
      } catch (e) {
        if (!disposed) setError(String(e));
      } finally {
        pending = false;
      }
    };
    void poll();
    const timer = setInterval(() => void poll(), 650);
    return () => {
      disposed = true;
      clearInterval(timer);
    };
  }, [runId, setRun, setRuns, setError]);
  return { events, setEvents };
}
