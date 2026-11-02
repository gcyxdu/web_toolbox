import { useEffect, useState } from 'react';

export function useStoredBoolean(key: string, fallback: boolean) {
  const [value, setValue] = useState(() => {
    try {
      const saved = localStorage.getItem(key);
      return saved === null ? fallback : saved === 'true';
    } catch {
      return fallback;
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem(key, String(value));
    } catch {
      /* Optional preference. */
    }
  }, [key, value]);
  return [value, setValue] as const;
}
