/**
 * VS Code Configuration File Detection Rules
 * CRITICAL PRIORITY - These files can execute automatically on workspace trust
 */

import { Rule } from '../types';

export const vscodeRules: Rule[] = [
  // ============================================
  // tasks.json - Auto-execution on folder open
  // ============================================
  {
    id: 'vscode-task-auto-run',
    name: 'Task auto-executes on folder open',
    description:
      'This task runs automatically when you open the folder and trust the workspace. ' +
      'This is a primary attack vector used by DPRK threat actors. The code executes ' +
      'without any user interaction beyond clicking "Trust".',
    severity: 'high',
    category: 'vscode-config',
    filePatterns: ['.vscode/tasks.json', 'tasks.json'],
    detect: {
      type: 'regex',
      pattern: '"runOn"\\s*:\\s*"folderOpen"',
      flags: 'gi',
    },
  },
  {
    id: 'vscode-task-hidden-terminal',
    name: 'Task hides terminal output',
    description:
      'This task is configured to hide its terminal output, making it invisible to the user. ' +
      'Legitimate tasks rarely need to hide their output. This is commonly used to run ' +
      'malicious code without the user noticing.',
    severity: 'high',
    category: 'vscode-config',
    filePatterns: ['.vscode/tasks.json', 'tasks.json'],
    detect: {
      type: 'regex',
      pattern: '"reveal"\\s*:\\s*"never"',
      flags: 'gi',
    },
  },
  {
    id: 'vscode-task-background',
    name: 'Task runs in background',
    description:
      'This task is configured to run in the background. Combined with other suspicious ' +
      'settings, this can be used to execute malicious code without visible indication.',
    severity: 'medium',
    category: 'vscode-config',
    filePatterns: ['.vscode/tasks.json', 'tasks.json'],
    detect: {
      type: 'regex',
      pattern: '"isBackground"\\s*:\\s*true',
      flags: 'gi',
    },
  },
  {
    id: 'vscode-task-auto-close',
    name: 'Task auto-closes terminal',
    description:
      'This task is configured to automatically close the terminal after execution, ' +
      'hiding any output or evidence of what was run.',
    severity: 'medium',
    category: 'vscode-config',
    filePatterns: ['.vscode/tasks.json', 'tasks.json'],
    detect: {
      type: 'regex',
      pattern: '"close"\\s*:\\s*true',
      flags: 'gi',
    },
  },
  {
    id: 'vscode-task-base64-command',
    name: 'Task contains base64-encoded command',
    description:
      'This task contains what appears to be a base64-encoded command. Attackers use ' +
      'base64 encoding to hide malicious payloads from casual inspection.',
    severity: 'high',
    category: 'vscode-config',
    filePatterns: ['.vscode/tasks.json', 'tasks.json'],
    detect: {
      type: 'regex',
      // Match base64 strings that are 20+ chars (likely encoded commands)
      pattern: '(atob|btoa|base64|--decode|\\-d)\\s*[\'"]?[A-Za-z0-9+/=]{20,}',
      flags: 'gi',
    },
  },
  {
    id: 'vscode-task-curl-wget',
    name: 'Task downloads and executes remote code',
    description:
      'This task downloads code from the internet and executes it. This is a classic ' +
      'attack pattern that can download and run any malicious payload.',
    severity: 'high',
    category: 'vscode-config',
    filePatterns: ['.vscode/tasks.json', 'tasks.json'],
    detect: {
      type: 'regex',
      pattern: '(curl|wget|fetch)\\s+[^|]*\\|\\s*(sh|bash|node|python)',
      flags: 'gi',
    },
  },
  {
    id: 'vscode-task-suspicious-command',
    name: 'Task executes suspicious shell command',
    description:
      'This task executes a shell command that could be used to exfiltrate data, ' +
      'download malware, or modify system files.',
    severity: 'medium',
    category: 'vscode-config',
    filePatterns: ['.vscode/tasks.json', 'tasks.json'],
    detect: {
      type: 'regex',
      pattern:
        '(nc\\s+-|ncat|netcat|/dev/tcp|mkfifo|>\\s*/dev/null|2>&1|\\$\\(|`[^`]+`)',
      flags: 'gi',
    },
  },
  {
    id: 'vscode-task-env-exfil',
    name: 'Task accesses environment variables suspiciously',
    description:
      'This task accesses sensitive environment variables like private keys, secrets, ' +
      'or API keys. This could be used to steal credentials.',
    severity: 'high',
    category: 'vscode-config',
    filePatterns: ['.vscode/tasks.json', 'tasks.json'],
    detect: {
      type: 'regex',
      pattern:
        '\\$\\{?env[:\\.]?(PRIVATE|SECRET|KEY|TOKEN|PASSWORD|MNEMONIC|SEED)',
      flags: 'gi',
    },
  },

  // ============================================
  // settings.json - Malicious configuration
  // ============================================
  {
    id: 'vscode-settings-terminal-profile',
    name: 'Custom terminal profile with shell command',
    description:
      'A custom terminal profile is defined with shell arguments. This could be used ' +
      'to run malicious commands whenever a terminal is opened.',
    severity: 'medium',
    category: 'vscode-config',
    filePatterns: ['.vscode/settings.json', 'settings.json'],
    detect: {
      type: 'regex',
      pattern: 'terminal\\.integrated\\.profiles\\.[^"]*"args"\\s*:',
      flags: 'gi',
    },
  },
  {
    id: 'vscode-settings-git-path-override',
    name: 'Git path override detected',
    description:
      'The git executable path is being overridden. This could point to a malicious ' +
      'binary that impersonates git while stealing credentials or running malware.',
    severity: 'high',
    category: 'vscode-config',
    filePatterns: ['.vscode/settings.json', 'settings.json'],
    detect: {
      type: 'regex',
      pattern: '"git\\.path"\\s*:\\s*"(?!/usr/|/bin/|/opt/|C:\\\\Program)',
      flags: 'gi',
    },
  },
  {
    id: 'vscode-settings-python-path-override',
    name: 'Python path override detected',
    description:
      'The Python executable path is being overridden to a non-standard location. ' +
      'This could point to a malicious binary.',
    severity: 'medium',
    category: 'vscode-config',
    filePatterns: ['.vscode/settings.json', 'settings.json'],
    detect: {
      type: 'regex',
      pattern: '"python\\.pythonPath"\\s*:\\s*"(?!.*/(python|python3|venv))',
      flags: 'gi',
    },
  },

  // ============================================
  // launch.json - Debug configuration attacks
  // ============================================
  {
    id: 'vscode-launch-prelaunch-task',
    name: 'Debug config has pre-launch task',
    description:
      'This debug configuration runs a task before launching. Check the referenced ' +
      'task in tasks.json for suspicious commands.',
    severity: 'low',
    category: 'vscode-config',
    filePatterns: ['.vscode/launch.json', 'launch.json'],
    detect: {
      type: 'regex',
      pattern: '"preLaunchTask"\\s*:',
      flags: 'gi',
    },
  },
  {
    id: 'vscode-launch-runtime-override',
    name: 'Debug config overrides runtime executable',
    description:
      'This debug configuration overrides the runtime executable. This could be used ' +
      'to run a malicious binary instead of the expected runtime.',
    severity: 'medium',
    category: 'vscode-config',
    filePatterns: ['.vscode/launch.json', 'launch.json'],
    detect: {
      type: 'regex',
      pattern: '"runtimeExecutable"\\s*:\\s*"(?!/usr/|/bin/|node|python)',
      flags: 'gi',
    },
  },
  {
    id: 'vscode-launch-env-injection',
    name: 'Debug config injects environment variables',
    description:
      'This debug configuration sets custom environment variables. Review them to ' +
      'ensure they are not overriding security-sensitive settings.',
    severity: 'low',
    category: 'vscode-config',
    filePatterns: ['.vscode/launch.json', 'launch.json'],
    detect: {
      type: 'regex',
      pattern: '"env"\\s*:\\s*\\{[^}]*(PATH|LD_PRELOAD|DYLD)',
      flags: 'gi',
    },
  },

  // ============================================
  // extensions.json - Malicious extension recommendations
  // ============================================
  {
    id: 'vscode-extensions-unknown-publisher',
    name: 'Extension recommendation from unknown publisher',
    description:
      'This repository recommends VS Code extensions. Malicious extensions can have ' +
      'full access to your system. Only install extensions from trusted publishers.',
    severity: 'low',
    category: 'vscode-config',
    filePatterns: ['.vscode/extensions.json', 'extensions.json'],
    detect: {
      type: 'regex',
      pattern: '"recommendations"\\s*:\\s*\\[',
      flags: 'gi',
    },
  },

  // ============================================
  // General .vscode folder checks
  // ============================================
  {
    id: 'vscode-executable-file',
    name: 'Executable file in .vscode folder',
    description:
      'There is an executable or script file inside the .vscode folder. This is unusual ' +
      'and could be used to run malicious code.',
    severity: 'high',
    category: 'vscode-config',
    filePatterns: ['.vscode/*.sh', '.vscode/*.bat', '.vscode/*.cmd', '.vscode/*.ps1'],
    detect: {
      type: 'regex',
      pattern: '.',
      flags: 'g',
    },
  },
  {
    id: 'vscode-hidden-file',
    name: 'Hidden file in .vscode folder',
    description:
      'There is a hidden file (starting with a dot) inside the .vscode folder. This ' +
      'is suspicious and could be used to hide malicious scripts.',
    severity: 'medium',
    category: 'vscode-config',
    filePatterns: ['.vscode/.*'],
    detect: {
      type: 'regex',
      pattern: '.',
      flags: 'g',
    },
  },
];
