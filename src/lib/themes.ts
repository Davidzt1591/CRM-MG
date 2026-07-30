/**
 * Single source of truth for the color-theme catalog.
 *
 * Magneto365IA uses a single brand identity — no accent themes.
 * The CSS variables live in `src/app/globals.css` under the
 * `html[data-theme="magneto"]` block. This module provides
 * backward-compatible metadata for the UI boot script and
 * settings picker, now collapsed to the single Magneto theme.
 *
 * Dark/light mode toggle still works via data-mode.
 */

export const THEME_IDS = ["magneto"] as const;

export type ThemeId = (typeof THEME_IDS)[number];

export const DEFAULT_THEME: ThemeId = "magneto";

export const STORAGE_KEY = "magneto.theme";

/**
 * MODE — the light/dark dimension, orthogonal to the single brand theme.
 */
export const MODES = ["light", "dark"] as const;

export type Mode = (typeof MODES)[number];

export const DEFAULT_MODE: Mode = "dark";

export const MODE_STORAGE_KEY = "magneto.mode";

export function isMode(value: unknown): value is Mode {
  return (
    typeof value === "string" && (MODES as ReadonlyArray<string>).includes(value)
  );
}

export interface ThemeMeta {
  id: ThemeId;
  name: string;
  tagline: string;
  swatch: string;
}

export const THEMES: ReadonlyArray<ThemeMeta> = [
  {
    id: "magneto",
    name: "Magneto",
    tagline: "Magneto365AI brand identity.",
    swatch: "#11a2dc",
  },
];

export function isThemeId(value: unknown): value is ThemeId {
  return (
    typeof value === "string" &&
    (THEME_IDS as ReadonlyArray<string>).includes(value)
  );
}
