"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";

import { DEFAULT_MODE, MODE_STORAGE_KEY, isMode, type Mode } from "@/lib/themes";

/**
 * ThemeProvider — wraps the whole app, owns the color-mode axis
 * (`data-mode` on <html>): light / dark.
 *
 * A single brand theme (Magneto, `data-theme="magneto"`) is applied at
 * build time by the boot script in `src/app/layout.tsx`, so by the time
 * this Provider mounts the page is already painted correctly. We just
 * read what's there and keep it in sync going forward.
 *
 * Persistence is localStorage only (device-scoped). A future
 * follow-up could mirror to `profiles.preferences` for cross-device
 * sync, but a per-device choice is also defensible — your phone may
 * deserve dark mode while your laptop stays light.
 */

interface ThemeContextValue {
  mode: Mode;
  setMode: (next: Mode) => void;
  toggleMode: () => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

function readInitialMode(): Mode {
  if (typeof window === "undefined") return DEFAULT_MODE;
  const fromAttr = document.documentElement.dataset.mode;
  if (isMode(fromAttr)) return fromAttr;
  try {
    const stored = localStorage.getItem(MODE_STORAGE_KEY);
    if (isMode(stored)) return stored;
  } catch {
    // localStorage can throw in private-browsing / sandboxed contexts.
  }
  return DEFAULT_MODE;
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [mode, setModeState] = useState<Mode>(readInitialMode);

  const setMode = useCallback((next: Mode) => {
    setModeState(next);
    if (typeof document !== "undefined") {
      document.documentElement.dataset.mode = next;
    }
    try {
      localStorage.setItem(MODE_STORAGE_KEY, next);
    } catch {
      // Same private-browsing edge case as above.
    }
  }, []);

  const toggleMode = useCallback(() => {
    setMode(mode === "dark" ? "light" : "dark");
  }, [mode, setMode]);

  // Sync from other tabs — change mode in tab A, tab B
  // catches up without a refresh.
  useEffect(() => {
    function onStorage(e: StorageEvent) {
      if (e.key === MODE_STORAGE_KEY) {
        if (isMode(e.newValue) && e.newValue !== mode) {
          setModeState(e.newValue);
          document.documentElement.dataset.mode = e.newValue;
        }
      }
    }
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, [mode]);

  return (
    <ThemeContext.Provider value={{ mode, setMode, toggleMode }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) {
    // Fallback for components rendered outside the provider — return
    // a no-op setter so callers don't crash. The boot script still
    // applied the right CSS attributes, so visually the page is fine.
    return {
      mode: DEFAULT_MODE,
      setMode: () => {},
      toggleMode: () => {},
    };
  }
  return ctx;
}
