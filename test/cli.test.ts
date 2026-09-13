import { describe, expect, it } from 'vitest';
import { buildProgram, run } from '../src/cli.js';
import { VERSION } from '../src/version.js';

describe('cli', () => {
  it('names the program chaperone with a description and version', () => {
    const program = buildProgram();

    expect(program.name()).toBe('chaperone');
    expect(program.description()).toMatch(/security scanner/i);
    expect(program.version()).toBe(VERSION);
  });

  it('includes chaperone in its help output', () => {
    const helpText = buildProgram().helpInformation();

    expect(helpText).toContain('chaperone');
  });

  it('prints help instead of throwing when invoked with no arguments', () => {
    expect(() => {
      run(['node', 'chaperone']);
    }).not.toThrow();
  });
});
