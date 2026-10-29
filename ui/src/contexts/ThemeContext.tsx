import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';

export type Theme = 'light' | 'dark';

interface ThemeCtx {
  theme: Theme;
  toggle: () => void;
}

const Ctx = createContext<ThemeCtx>({ theme: 'light', toggle: () => {} });

function getInitialTheme(): Theme {
  try {
    const stored = localStorage.getItem('sr-theme') as Theme | null;
    if (stored === 'light' || stored === 'dark') return stored;
  } catch { /* storage unavailable */ }
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>(getInitialTheme);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem('sr-theme', theme); } catch { /* ignore */ }
  }, [theme]);

  // Apply immediately on mount to avoid flash
  useEffect(() => {
    document.documentElement.dataset.theme = getInitialTheme();
  }, []);

  const toggle = () => setTheme(t => (t === 'light' ? 'dark' : 'light'));

  return <Ctx.Provider value={{ theme, toggle }}>{children}</Ctx.Provider>;
}

export function useTheme(): ThemeCtx {
  return useContext(Ctx);
}
