/**
 * JavaScript / TypeScript Detection Rules
 * Focuses on package.json scripts and wallet-drain patterns
 */

import { Rule } from '../types';

export const javascriptRules: Rule[] = [
  // ============================================
  // package.json - Install hooks
  // ============================================
  {
    id: 'js-postinstall-script',
    name: 'package.json has postinstall script',
    description:
      'This package runs a script automatically after npm/yarn install. Malicious packages ' +
      'use postinstall scripts to execute code the moment you install dependencies. ' +
      'Review the script contents before running npm install.',
    severity: 'medium',
    category: 'javascript',
    filePatterns: ['package.json'],
    detect: {
      type: 'regex',
      pattern: '"postinstall"\\s*:',
      flags: 'gi',
    },
  },
  {
    id: 'js-preinstall-script',
    name: 'package.json has preinstall script',
    description:
      'This package runs a script before npm/yarn install completes. This can execute ' +
      'malicious code during the installation process.',
    severity: 'medium',
    category: 'javascript',
    filePatterns: ['package.json'],
    detect: {
      type: 'regex',
      pattern: '"preinstall"\\s*:',
      flags: 'gi',
    },
  },
  {
    id: 'js-prepare-script',
    name: 'package.json has prepare script',
    description:
      'This package has a prepare script that runs after install and before publish. ' +
      'While often legitimate, it can be abused to run malicious code.',
    severity: 'low',
    category: 'javascript',
    filePatterns: ['package.json'],
    detect: {
      type: 'regex',
      pattern: '"prepare"\\s*:',
      flags: 'gi',
    },
  },

  // ============================================
  // Code execution patterns
  // ============================================
  {
    id: 'js-child-process-exec',
    name: 'Uses child_process to execute commands',
    description:
      'This code uses child_process to execute shell commands. This can be used to run ' +
      'arbitrary commands on your system. Verify the commands being executed are safe.',
    severity: 'medium',
    category: 'javascript',
    filePatterns: ['*.js', '*.ts', '*.mjs', '*.cjs', '*.jsx', '*.tsx'],
    detect: {
      type: 'regex',
      pattern:
        '(require\\s*\\([\'"]child_process[\'"]\\)|from\\s+[\'"]child_process[\'"]|exec|execSync|spawn|spawnSync)\\s*\\(',
      flags: 'gi',
    },
  },
  {
    id: 'js-eval-usage',
    name: 'Uses eval() or Function() for dynamic code execution',
    description:
      'This code uses eval() or Function() to execute dynamic code. This is dangerous ' +
      'as it can execute any JavaScript, including malicious payloads.',
    severity: 'high',
    category: 'javascript',
    filePatterns: ['*.js', '*.ts', '*.mjs', '*.cjs', '*.jsx', '*.tsx'],
    detect: {
      type: 'regex',
      pattern: '\\b(eval|Function)\\s*\\(',
      flags: 'g',
    },
  },
  {
    id: 'js-dynamic-import-url',
    name: 'Dynamic import from URL',
    description:
      'This code imports modules from a URL. This can be used to load and execute ' +
      'malicious code from a remote server.',
    severity: 'high',
    category: 'javascript',
    filePatterns: ['*.js', '*.ts', '*.mjs', '*.cjs', '*.jsx', '*.tsx'],
    detect: {
      type: 'regex',
      pattern: 'import\\s*\\(\\s*[\'"`]https?://',
      flags: 'gi',
    },
  },

  // ============================================
  // Web3 / Wallet patterns
  // ============================================
  {
    id: 'js-wallet-signing',
    name: 'Wallet signing operation detected',
    description:
      'This code performs wallet signing operations. Ensure you understand what is being ' +
      'signed. Malicious code can trick you into signing transactions that drain your wallet.',
    severity: 'medium',
    category: 'javascript',
    filePatterns: ['*.js', '*.ts', '*.mjs', '*.cjs', '*.jsx', '*.tsx'],
    detect: {
      type: 'regex',
      pattern:
        '(eth_sign|personal_sign|signTypedData|eth_signTransaction|signMessage|signTransaction)',
      flags: 'gi',
    },
  },
  {
    id: 'js-unlimited-approval',
    name: 'Unlimited token approval pattern',
    description:
      'This code may request unlimited token approval (max uint256). This allows a contract ' +
      'to spend all your tokens. Malicious contracts abuse this to drain wallets.',
    severity: 'high',
    category: 'javascript',
    filePatterns: ['*.js', '*.ts', '*.mjs', '*.cjs', '*.jsx', '*.tsx'],
    detect: {
      type: 'regex',
      pattern:
        '(approve|setApprovalForAll)\\s*\\([^)]*((2\\s*\\*\\*\\s*256|MaxUint256|ethers\\.constants\\.MaxUint256|MAX_UINT|0xf+))',
      flags: 'gi',
    },
  },
  {
    id: 'js-private-key-handling',
    name: 'Private key handling detected',
    description:
      'This code handles private keys or seed phrases. Be extremely careful - malicious ' +
      'code can exfiltrate your keys and steal all your funds.',
    severity: 'high',
    category: 'javascript',
    filePatterns: ['*.js', '*.ts', '*.mjs', '*.cjs', '*.jsx', '*.tsx'],
    detect: {
      type: 'regex',
      pattern:
        '(privateKey|private_key|secretKey|secret_key|mnemonic|seed[Pp]hrase|PRIVATE_KEY)',
      flags: 'g',
    },
  },
  {
    id: 'js-rpc-override',
    name: 'RPC endpoint override',
    description:
      'This code overrides the RPC endpoint. Malicious RPC endpoints can return false ' +
      'information or capture your transactions.',
    severity: 'medium',
    category: 'javascript',
    filePatterns: ['*.js', '*.ts', '*.mjs', '*.cjs', '*.jsx', '*.tsx'],
    detect: {
      type: 'regex',
      pattern:
        '(JsonRpcProvider|Web3Provider|createPublicClient|createWalletClient)\\s*\\([^)]*http',
      flags: 'gi',
    },
  },

  // ============================================
  // Obfuscation patterns
  // ============================================
  {
    id: 'js-obfuscated-code',
    name: 'Potentially obfuscated JavaScript',
    description:
      'This file contains patterns commonly seen in obfuscated JavaScript. Obfuscation ' +
      'is often used to hide malicious code. Legitimate code rarely needs obfuscation.',
    severity: 'high',
    category: 'javascript',
    filePatterns: ['*.js', '*.ts', '*.mjs', '*.cjs'],
    detect: {
      type: 'regex',
      // Common obfuscation patterns: hex escapes, unicode escapes, long variable names
      pattern:
        '(\\\\x[0-9a-f]{2}){10,}|(\\\\u[0-9a-f]{4}){5,}|_0x[a-f0-9]{4,}|\\[\\s*[\'"][^\'"]{1,3}[\'"]\\s*\\]\\s*\\(',
      flags: 'gi',
    },
  },
  {
    id: 'js-base64-decode',
    name: 'Base64 decoding with execution',
    description:
      'This code decodes base64 data and may execute it. This is a common technique to ' +
      'hide malicious payloads from code review.',
    severity: 'high',
    category: 'javascript',
    filePatterns: ['*.js', '*.ts', '*.mjs', '*.cjs', '*.jsx', '*.tsx'],
    detect: {
      type: 'regex',
      pattern:
        '(atob|Buffer\\.from)\\s*\\([^)]+[\'"]base64[\'"]\\)[^;]*(eval|Function|require|import)',
      flags: 'gi',
    },
  },

  // ============================================
  // Network patterns
  // ============================================
  {
    id: 'js-fetch-unknown-endpoint',
    name: 'Network request to hardcoded URL',
    description:
      'This code makes network requests to a hardcoded URL. Verify the destination is ' +
      'legitimate. Malicious code uses this to exfiltrate data or download payloads.',
    severity: 'low',
    category: 'javascript',
    filePatterns: ['*.js', '*.ts', '*.mjs', '*.cjs', '*.jsx', '*.tsx'],
    detect: {
      type: 'regex',
      pattern:
        '(fetch|axios|request|got|http\\.get|https\\.get)\\s*\\([\'"`]https?://(?!localhost|127\\.0\\.0\\.1)',
      flags: 'gi',
    },
  },
];
