import { describe, expect, it } from 'vitest';

import { DEFAULT_THEME, THEME_IDS, isThemeId } from './themes';

/**
 * Characterization + safety tests for the theme-ID catalog validator.
 *
 * FK-13 drops the `theme`/`setTheme` axis from the use-theme context
 * (the app ships a single brand theme — THEMES.length === 1). The
 * catalog validator `isThemeId` is the remaining guard that rejects
 * invalid stored values, so it gets explicit coverage here (previously
 * untested) as the safety net before refactoring consumer code.
 */
describe('theme catalog validation (isThemeId)', () => {
  it('accepts every ID declared in the THEME_IDS catalog', () => {
    for (const id of THEME_IDS) {
      expect(isThemeId(id)).toBe(true);
    }
  });

  it('rejects arbitrary unknown theme IDs', () => {
    // Not in the catalog — must be rejected so a corrupted
    // localStorage value can never become a bogus `data-theme`.
    expect(isThemeId('invalid')).toBe(false);
    expect(isThemeId('wacrm')).toBe(false);
    expect(isThemeId('dark')).toBe(false); // 'dark' is a *mode*, not a theme
    expect(isThemeId('magneto ')).toBe(false); // trailing whitespace
    expect(isThemeId('Magneto')).toBe(false); // wrong case
    expect(isThemeId('magneto-pro')).toBe(false); // near-miss
  });

  it('rejects non-string / empty values', () => {
    expect(isThemeId(null)).toBe(false);
    expect(isThemeId(undefined)).toBe(false);
    expect(isThemeId('')).toBe(false);
    expect(isThemeId(42)).toBe(false);
    expect(isThemeId({})).toBe(false);
  });

  it('DEFAULT_THEME is always a valid catalog member', () => {
    // The boot fallback must always pass the guard — otherwise the
    // data-theme attribute would silently break on first paint.
    expect(isThemeId(DEFAULT_THEME)).toBe(true);
  });
});
