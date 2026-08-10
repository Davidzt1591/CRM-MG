import { describe, expect, it } from 'vitest';
import config from '../../../vitest.config';

describe('vitest config — CI proof of completeness', () => {
  it('forbids test.only/describe.only so CI cannot green on a partial suite', () => {
    // Vitest uses `allowOnly` (default false); programmatically assert it is
    // set to false so CI cannot green on a partial suite via `.only`.
    expect(config.test?.allowOnly).toBe(false);
  });
});