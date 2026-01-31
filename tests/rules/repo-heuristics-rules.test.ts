/**
 * Tests for Repository-level heuristic detection rules
 * Covers minified code, binaries, typosquatting, hidden files, credentials
 */

import { describe, it, expect } from 'vitest';
import { applyRule, matchFile } from '../../src/scanner/matcher';
import { repoHeuristicsRules } from '../../src/rules/repo-heuristics-rules';

function getRule(id: string) {
  const rule = repoHeuristicsRules.find((r) => r.id === id);
  if (!rule) throw new Error(`Rule not found: ${id}`);
  return rule;
}

function expectDetection(id: string, filePath: string, content: string) {
  const rule = getRule(id);
  expect(matchFile(filePath, rule.filePatterns)).toBe(true);
  const findings = applyRule(rule, filePath, content);
  expect(findings.length).toBeGreaterThan(0);
  return findings;
}

function expectNoDetection(id: string, filePath: string, content: string) {
  const rule = getRule(id);
  if (!matchFile(filePath, rule.filePatterns)) return;
  const findings = applyRule(rule, filePath, content);
  expect(findings).toHaveLength(0);
}

// ============================================
// Minified/obfuscated files
// ============================================

describe('repo-minified-source', () => {
  it('matches minified JS in src/', () => {
    const rule = getRule('repo-minified-source');
    expect(matchFile('src/bundle.min.js', rule.filePatterns)).toBe(true);
  });

  it('matches minified JS in lib/', () => {
    const rule = getRule('repo-minified-source');
    expect(matchFile('lib/util.min.js', rule.filePatterns)).toBe(true);
  });

  it('does not match minified JS in dist/', () => {
    const rule = getRule('repo-minified-source');
    expect(matchFile('dist/bundle.min.js', rule.filePatterns)).toBe(false);
  });
});

describe('repo-long-lines', () => {
  it('detects lines over 1000 characters', () => {
    const longLine = 'x'.repeat(1001);
    expectDetection('repo-long-lines', 'src/suspicious.js', longLine);
  });

  it('does not flag normal-length lines', () => {
    expectNoDetection(
      'repo-long-lines',
      'src/normal.js',
      'const x = 1;\nconst y = 2;\nconsole.log(x + y);'
    );
  });
});

// ============================================
// Binary and executable files
// ============================================

describe('repo-binary-blob', () => {
  it('matches .exe file', () => {
    const rule = getRule('repo-binary-blob');
    expect(matchFile('tools/helper.exe', rule.filePatterns)).toBe(true);
  });

  it('matches .dll file', () => {
    const rule = getRule('repo-binary-blob');
    expect(matchFile('lib/native.dll', rule.filePatterns)).toBe(true);
  });

  it('matches .so file', () => {
    const rule = getRule('repo-binary-blob');
    expect(matchFile('lib/native.so', rule.filePatterns)).toBe(true);
  });

  it('does not match .js file', () => {
    const rule = getRule('repo-binary-blob');
    expect(matchFile('src/index.js', rule.filePatterns)).toBe(false);
  });
});

// ============================================
// Typosquatting
// ============================================

describe('repo-similar-package-name', () => {
  it('detects lodash typosquat', () => {
    expectDetection(
      'repo-similar-package-name',
      'package.json',
      `{ "name": "lodash-utils" }`
    );
  });

  it('detects expresss typosquat', () => {
    expectDetection(
      'repo-similar-package-name',
      'package.json',
      `{ "name": "expresss" }`
    );
  });

  it('does not flag legitimate package name', () => {
    expectNoDetection(
      'repo-similar-package-name',
      'package.json',
      `{ "name": "my-cool-project" }`
    );
  });
});

// ============================================
// Suspicious file patterns
// ============================================

describe('repo-hidden-executable', () => {
  it('matches hidden .sh file', () => {
    const rule = getRule('repo-hidden-executable');
    expect(matchFile('.evil.sh', rule.filePatterns)).toBe(true);
  });

  it('matches hidden .py file', () => {
    const rule = getRule('repo-hidden-executable');
    expect(matchFile('.backdoor.py', rule.filePatterns)).toBe(true);
  });

  it('matches hidden .exe file', () => {
    const rule = getRule('repo-hidden-executable');
    expect(matchFile('.hidden.exe', rule.filePatterns)).toBe(true);
  });
});

describe('repo-double-extension', () => {
  it('matches .txt.exe double extension', () => {
    const rule = getRule('repo-double-extension');
    expect(matchFile('readme.txt.exe', rule.filePatterns)).toBe(true);
  });

  it('matches .pdf.exe', () => {
    const rule = getRule('repo-double-extension');
    expect(matchFile('document.pdf.exe', rule.filePatterns)).toBe(true);
  });

  it('matches .png.js', () => {
    const rule = getRule('repo-double-extension');
    expect(matchFile('image.png.js', rule.filePatterns)).toBe(true);
  });

  it('does not match normal single extension', () => {
    const rule = getRule('repo-double-extension');
    expect(matchFile('readme.txt', rule.filePatterns)).toBe(false);
  });
});

// ============================================
// Time-based execution
// ============================================

describe('repo-delayed-execution', () => {
  it('detects long setTimeout with simple callback', () => {
    // Pattern: (setTimeout|...)\s*\([^)]*[0-9]{4,}
    // [^)]* stops at first ), so callback must not contain parens
    expectDetection(
      'repo-delayed-execution',
      'malware.js',
      `setTimeout(stealData, 60000);`
    );
  });

  it('detects long time.sleep', () => {
    expectDetection(
      'repo-delayed-execution',
      'malware.py',
      `time.sleep(3600)`
    );
  });

  it('does not flag short setTimeout', () => {
    expectNoDetection(
      'repo-delayed-execution',
      'app.js',
      `setTimeout(handler, 100);`
    );
  });
});

// ============================================
// Credentials
// ============================================

describe('repo-hardcoded-key', () => {
  it('detects hardcoded API key (alphanumeric only)', () => {
    // Pattern: (api[_-]?key|...) then = or : then quote then [a-zA-Z0-9]{20,} then quote
    // Value must be purely alphanumeric (no underscores, dashes)
    expectDetection(
      'repo-hardcoded-key',
      'config.js',
      `const api_key = "abcdefghijklmnopqrstuv";`
    );
  });

  it('detects hardcoded secret with colon separator', () => {
    expectDetection(
      'repo-hardcoded-key',
      'config.py',
      `api_secret: "abcdefghijklmnopqrstuvwxyz123456"`
    );
  });

  it('does not flag short strings', () => {
    expectNoDetection(
      'repo-hardcoded-key',
      'config.js',
      `const api_key = "test";`
    );
  });
});

describe('repo-hex-private-key', () => {
  it('detects 64-char hex string (private key)', () => {
    expectDetection(
      'repo-hex-private-key',
      'wallet.js',
      `const key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";`
    );
  });

  it('detects without 0x prefix', () => {
    expectDetection(
      'repo-hex-private-key',
      'wallet.py',
      `key = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"`
    );
  });

  it('does not flag short hex strings', () => {
    expectNoDetection(
      'repo-hex-private-key',
      'color.js',
      `const color = "#ff4444";`
    );
  });
});

// ============================================
// Suspicious dependencies
// ============================================

describe('repo-git-dependency', () => {
  it('detects git+https dependency', () => {
    expectDetection(
      'repo-git-dependency',
      'package.json',
      `{
        "dependencies": {
          "evil-pkg": "git+https://github.com/evil/pkg.git"
        }
      }`
    );
  });

  it('detects git+ssh dependency', () => {
    expectDetection(
      'repo-git-dependency',
      'package.json',
      `{
        "devDependencies": {
          "evil-pkg": "git+ssh://git@github.com/evil/pkg.git"
        }
      }`
    );
  });

  it('does not flag npm registry dependencies', () => {
    expectNoDetection(
      'repo-git-dependency',
      'package.json',
      `{
        "dependencies": {
          "express": "^4.18.0",
          "lodash": "^4.17.21"
        }
      }`
    );
  });
});
