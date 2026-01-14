/**
 * Shell Script Detection Rules
 * Focuses on dangerous shell patterns
 */

import { Rule } from '../types';

export const shellRules: Rule[] = [
  // ============================================
  // Remote code execution
  // ============================================
  {
    id: 'sh-curl-bash',
    name: 'Downloads and executes remote script',
    description:
      'This script downloads code from the internet and pipes it directly to bash/sh. ' +
      'This is extremely dangerous as it executes whatever is on that URL with no review.',
    severity: 'high',
    category: 'shell',
    filePatterns: ['*.sh', '*.bash', '*.zsh', 'Makefile', 'makefile'],
    detect: {
      type: 'regex',
      pattern: '(curl|wget)\\s+[^|]*\\|\\s*(bash|sh|zsh|source)',
      flags: 'gi',
    },
  },
  {
    id: 'sh-eval-curl',
    name: 'Evaluates downloaded content',
    description:
      'This script downloads content and evaluates it. This can execute any code ' +
      'from a remote server.',
    severity: 'high',
    category: 'shell',
    filePatterns: ['*.sh', '*.bash', '*.zsh'],
    detect: {
      type: 'regex',
      pattern: 'eval\\s+.*\\$\\((curl|wget)',
      flags: 'gi',
    },
  },

  // ============================================
  // Stealth/hiding patterns
  // ============================================
  {
    id: 'sh-background-nohup',
    name: 'Runs command in background with nohup',
    description:
      'This script runs a command in the background with nohup, which persists after the ' +
      'terminal closes. This can be used to run malware persistently.',
    severity: 'medium',
    category: 'shell',
    filePatterns: ['*.sh', '*.bash', '*.zsh'],
    detect: {
      type: 'regex',
      pattern: 'nohup\\s+.*&',
      flags: 'gi',
    },
  },
  {
    id: 'sh-redirect-null',
    name: 'Redirects output to /dev/null',
    description:
      'This script hides its output by redirecting to /dev/null. While sometimes legitimate, ' +
      'malicious scripts use this to hide their activity.',
    severity: 'low',
    category: 'shell',
    filePatterns: ['*.sh', '*.bash', '*.zsh'],
    detect: {
      type: 'regex',
      pattern: '[>]\\s*/dev/null\\s+2>&1|2>&1\\s*[>]\\s*/dev/null',
      flags: 'gi',
    },
  },
  {
    id: 'sh-disown-background',
    name: 'Disowns background process',
    description:
      'This script uses disown to detach a process from the shell. This can be used to ' +
      'run persistent malware.',
    severity: 'medium',
    category: 'shell',
    filePatterns: ['*.sh', '*.bash', '*.zsh'],
    detect: {
      type: 'regex',
      pattern: 'disown',
      flags: 'gi',
    },
  },

  // ============================================
  // Reverse shell patterns
  // ============================================
  {
    id: 'sh-reverse-shell',
    name: 'Potential reverse shell',
    description:
      'This script contains patterns commonly used in reverse shells. A reverse shell gives ' +
      'an attacker remote access to your machine.',
    severity: 'high',
    category: 'shell',
    filePatterns: ['*.sh', '*.bash', '*.zsh'],
    detect: {
      type: 'regex',
      pattern:
        '(nc\\s+-[el]|ncat\\s+-|/dev/tcp/|mkfifo\\s+/tmp|bash\\s+-i\\s+>&)',
      flags: 'gi',
    },
  },
  {
    id: 'sh-netcat-listen',
    name: 'Netcat listener',
    description:
      'This script sets up a netcat listener, which can receive incoming connections. ' +
      'This is commonly used for reverse shells.',
    severity: 'high',
    category: 'shell',
    filePatterns: ['*.sh', '*.bash', '*.zsh'],
    detect: {
      type: 'regex',
      pattern: 'nc\\s+(-l|-p|--listen)',
      flags: 'gi',
    },
  },

  // ============================================
  // Permission and persistence
  // ============================================
  {
    id: 'sh-chmod-executable',
    name: 'Makes files executable',
    description:
      'This script changes file permissions to make something executable. Verify what ' +
      'files are being made executable.',
    severity: 'low',
    category: 'shell',
    filePatterns: ['*.sh', '*.bash', '*.zsh'],
    detect: {
      type: 'regex',
      pattern: 'chmod\\s+[+]?[0-7]*x|chmod\\s+755|chmod\\s+777',
      flags: 'gi',
    },
  },
  {
    id: 'sh-crontab-modify',
    name: 'Modifies crontab',
    description:
      'This script modifies the crontab (scheduled tasks). Malware uses this to persist ' +
      'and run periodically.',
    severity: 'high',
    category: 'shell',
    filePatterns: ['*.sh', '*.bash', '*.zsh'],
    detect: {
      type: 'regex',
      pattern: 'crontab\\s+(-|<)|echo.*>>.*cron',
      flags: 'gi',
    },
  },
  {
    id: 'sh-rc-file-modify',
    name: 'Modifies shell RC files',
    description:
      'This script modifies shell configuration files (.bashrc, .zshrc, etc.). This can be ' +
      'used to persist malware or steal credentials.',
    severity: 'high',
    category: 'shell',
    filePatterns: ['*.sh', '*.bash', '*.zsh'],
    detect: {
      type: 'regex',
      pattern: '>\\s*~?/?\\.?(bash|zsh|profile|rc)',
      flags: 'gi',
    },
  },

  // ============================================
  // Data exfiltration
  // ============================================
  {
    id: 'sh-env-exfil',
    name: 'Accesses sensitive environment variables',
    description:
      'This script accesses environment variables that may contain secrets. This could be ' +
      'used to steal credentials.',
    severity: 'medium',
    category: 'shell',
    filePatterns: ['*.sh', '*.bash', '*.zsh'],
    detect: {
      type: 'regex',
      pattern:
        '\\$\\{?(PRIVATE|SECRET|KEY|TOKEN|PASSWORD|MNEMONIC|SEED|AWS_)',
      flags: 'gi',
    },
  },
  {
    id: 'sh-ssh-key-access',
    name: 'Accesses SSH keys',
    description:
      'This script accesses SSH key files. Malicious scripts steal SSH keys to gain access ' +
      'to your servers.',
    severity: 'high',
    category: 'shell',
    filePatterns: ['*.sh', '*.bash', '*.zsh'],
    detect: {
      type: 'regex',
      pattern: '~?\\.ssh/(id_|authorized_keys|known_hosts)',
      flags: 'gi',
    },
  },

  // ============================================
  // Encoding/obfuscation
  // ============================================
  {
    id: 'sh-base64-decode-exec',
    name: 'Decodes and executes base64',
    description:
      'This script decodes base64 and executes it. This is commonly used to hide malicious ' +
      'payloads from code review.',
    severity: 'high',
    category: 'shell',
    filePatterns: ['*.sh', '*.bash', '*.zsh'],
    detect: {
      type: 'regex',
      pattern: 'base64\\s+(-d|--decode).*\\|\\s*(bash|sh|eval)',
      flags: 'gi',
    },
  },
];
