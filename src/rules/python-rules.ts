/**
 * Python Detection Rules
 * Focuses on install hooks and code execution patterns
 */

import { Rule } from '../types';

export const pythonRules: Rule[] = [
  // ============================================
  // setup.py / pyproject.toml - Install hooks
  // ============================================
  {
    id: 'py-setup-cmdclass',
    name: 'setup.py uses custom install commands',
    description:
      'This setup.py defines custom install commands (cmdclass). These run during pip install ' +
      'and can execute arbitrary code. Review the command implementations before installing.',
    severity: 'high',
    category: 'python',
    filePatterns: ['setup.py'],
    detect: {
      type: 'regex',
      pattern: 'cmdclass\\s*=\\s*\\{',
      flags: 'gi',
    },
  },
  {
    id: 'py-setup-exec',
    name: 'setup.py executes code',
    description:
      'This setup.py uses exec() or eval(). This can execute arbitrary code during installation ' +
      'and is a major red flag.',
    severity: 'high',
    category: 'python',
    filePatterns: ['setup.py'],
    detect: {
      type: 'regex',
      pattern: '\\b(exec|eval)\\s*\\(',
      flags: 'g',
    },
  },
  {
    id: 'py-setup-subprocess',
    name: 'setup.py runs subprocess',
    description:
      'This setup.py uses subprocess to run shell commands. This can execute arbitrary commands ' +
      'during pip install.',
    severity: 'high',
    category: 'python',
    filePatterns: ['setup.py'],
    detect: {
      type: 'regex',
      pattern: '(subprocess|os\\.system|os\\.popen|commands\\.getoutput)',
      flags: 'gi',
    },
  },
  {
    id: 'py-pyproject-scripts',
    name: 'pyproject.toml has build scripts',
    description:
      'This pyproject.toml defines build scripts that run during installation. Review these ' +
      'scripts before installing the package.',
    severity: 'low',
    category: 'python',
    filePatterns: ['pyproject.toml'],
    detect: {
      type: 'regex',
      pattern: '\\[tool\\.(setuptools|poetry)\\.scripts\\]',
      flags: 'gi',
    },
  },

  // ============================================
  // Code execution patterns
  // ============================================
  {
    id: 'py-exec-eval',
    name: 'Dynamic code execution (exec/eval)',
    description:
      'This Python code uses exec() or eval() to execute dynamic code. This can run any ' +
      'Python code, including malicious payloads.',
    severity: 'medium',
    category: 'python',
    filePatterns: ['*.py'],
    detect: {
      type: 'regex',
      pattern: '\\b(exec|eval|compile)\\s*\\(',
      flags: 'g',
    },
  },
  {
    id: 'py-subprocess',
    name: 'Subprocess execution',
    description:
      'This code uses subprocess to run shell commands. Verify the commands being executed ' +
      'are safe and expected.',
    severity: 'low',
    category: 'python',
    filePatterns: ['*.py'],
    detect: {
      type: 'regex',
      pattern:
        '(subprocess\\.(run|call|Popen|check_output)|os\\.(system|popen|exec))',
      flags: 'gi',
    },
  },

  // ============================================
  // Environment and secrets
  // ============================================
  {
    id: 'py-env-secrets',
    name: 'Accesses sensitive environment variables',
    description:
      'This code accesses environment variables that may contain secrets, keys, or passwords. ' +
      'Malicious code can exfiltrate these to steal credentials.',
    severity: 'medium',
    category: 'python',
    filePatterns: ['*.py'],
    detect: {
      type: 'regex',
      pattern:
        'os\\.(environ|getenv)\\s*\\[[\'"]?(PRIVATE|SECRET|KEY|TOKEN|PASSWORD|MNEMONIC|SEED)',
      flags: 'gi',
    },
  },
  {
    id: 'py-private-key',
    name: 'Private key handling',
    description:
      'This code handles private keys or mnemonics. Be extremely careful - malicious code ' +
      'can steal your keys and drain your wallets.',
    severity: 'high',
    category: 'python',
    filePatterns: ['*.py'],
    detect: {
      type: 'regex',
      pattern: '(private_key|secret_key|mnemonic|seed_phrase|PRIVATE_KEY)',
      flags: 'g',
    },
  },

  // ============================================
  // Network patterns
  // ============================================
  {
    id: 'py-requests-unknown',
    name: 'Network request to hardcoded URL',
    description:
      'This code makes HTTP requests to a hardcoded URL. Verify the destination is legitimate. ' +
      'Malicious code uses this to exfiltrate data.',
    severity: 'low',
    category: 'python',
    filePatterns: ['*.py'],
    detect: {
      type: 'regex',
      pattern:
        '(requests\\.(get|post|put)|urllib\\.request\\.urlopen|http\\.client)\\s*\\([\'"]https?://(?!localhost|127\\.0\\.0\\.1)',
      flags: 'gi',
    },
  },
  {
    id: 'py-socket-connection',
    name: 'Raw socket connection',
    description:
      'This code creates raw socket connections. This can be used for command & control ' +
      'communication or data exfiltration.',
    severity: 'medium',
    category: 'python',
    filePatterns: ['*.py'],
    detect: {
      type: 'regex',
      pattern: 'socket\\.socket\\s*\\(',
      flags: 'gi',
    },
  },

  // ============================================
  // Import-time execution
  // ============================================
  {
    id: 'py-init-execution',
    name: '__init__.py with executable code',
    description:
      'This __init__.py contains code that runs on import. While sometimes legitimate, ' +
      'malicious packages use this to execute code when you import them.',
    severity: 'low',
    category: 'python',
    filePatterns: ['__init__.py'],
    detect: {
      type: 'regex',
      pattern: '(subprocess|os\\.system|exec|eval|requests\\.|urllib)',
      flags: 'gi',
    },
  },

  // ============================================
  // Obfuscation
  // ============================================
  {
    id: 'py-base64-exec',
    name: 'Base64-encoded code execution',
    description:
      'This code decodes and executes base64-encoded data. This is commonly used to hide ' +
      'malicious payloads from code review.',
    severity: 'high',
    category: 'python',
    filePatterns: ['*.py'],
    detect: {
      type: 'regex',
      pattern: 'base64\\.(b64decode|decodebytes).*exec',
      flags: 'gis',
    },
  },
  {
    id: 'py-marshal-loads',
    name: 'Deserializes marshaled code',
    description:
      'This code uses marshal to deserialize bytecode. This can execute arbitrary Python code ' +
      'and is often used to hide malicious payloads.',
    severity: 'high',
    category: 'python',
    filePatterns: ['*.py'],
    detect: {
      type: 'regex',
      pattern: 'marshal\\.loads\\s*\\(',
      flags: 'gi',
    },
  },
];
