/**
 * Repository-Level Heuristic Rules
 * Detects suspicious patterns at the repo level
 */

import { Rule } from '../types';

export const repoHeuristicsRules: Rule[] = [
  // ============================================
  // Minified/obfuscated files
  // ============================================
  {
    id: 'repo-minified-source',
    name: 'Minified JavaScript in source directory',
    description:
      'Found minified JavaScript in a source directory (not dist/build). Minified code in ' +
      'source is suspicious - it hides what the code actually does. Legitimate projects ' +
      'keep source readable.',
    severity: 'high',
    category: 'repo-heuristics',
    filePatterns: ['src/*.min.js', 'lib/*.min.js', 'app/*.min.js'],
    detect: {
      type: 'regex',
      pattern: '.',
      flags: 'g',
    },
  },
  {
    id: 'repo-long-lines',
    name: 'Extremely long lines (potential obfuscation)',
    description:
      'This file has extremely long lines, which can indicate obfuscated or minified code ' +
      'hidden in what looks like a normal file.',
    severity: 'medium',
    category: 'repo-heuristics',
    filePatterns: ['*.js', '*.ts', '*.py'],
    detect: {
      type: 'regex',
      // Lines over 1000 characters that aren't in build directories
      pattern: '^.{1000,}$',
      flags: 'gm',
    },
  },

  // ============================================
  // Binary and executable files
  // ============================================
  {
    id: 'repo-binary-blob',
    name: 'Binary file in repository',
    description:
      'Found a binary executable file in the repository. Binary files can contain malware ' +
      'that antivirus might not detect. Legitimate projects rarely include pre-compiled binaries.',
    severity: 'medium',
    category: 'repo-heuristics',
    filePatterns: ['*.exe', '*.dll', '*.so', '*.dylib', '*.bin'],
    detect: {
      type: 'regex',
      pattern: '.',
      flags: 'g',
    },
  },

  // ============================================
  // Typosquatting indicators
  // ============================================
  {
    id: 'repo-similar-package-name',
    name: 'Package name similar to popular package',
    description:
      'This package.json has a name that looks similar to a popular package. Typosquatting ' +
      'is a common attack where malicious packages use names similar to legitimate ones.',
    severity: 'low',
    category: 'repo-heuristics',
    filePatterns: ['package.json'],
    detect: {
      type: 'regex',
      // Common typosquatting patterns
      pattern:
        '"name"\\s*:\\s*"(lodash-|lodassh|lod4sh|reactjs|react-dom-|expresss|expres|axio|axois)',
      flags: 'gi',
    },
  },

  // ============================================
  // Suspicious file patterns
  // ============================================
  {
    id: 'repo-hidden-executable',
    name: 'Hidden file with executable extension',
    description:
      'Found a hidden file (starting with dot) with an executable extension. This is ' +
      'highly suspicious and could be hiding malware.',
    severity: 'high',
    category: 'repo-heuristics',
    filePatterns: [
      '.*.sh',
      '.*.py',
      '.*.js',
      '.*.exe',
      '.*.bat',
      '.*.cmd',
      '.*.ps1',
    ],
    detect: {
      type: 'regex',
      pattern: '.',
      flags: 'g',
    },
  },
  {
    id: 'repo-double-extension',
    name: 'File with double extension',
    description:
      'Found a file with a double extension (e.g., file.txt.exe). This is a common technique ' +
      'to disguise executables as harmless files.',
    severity: 'high',
    category: 'repo-heuristics',
    filePatterns: [
      '*.txt.exe',
      '*.doc.exe',
      '*.pdf.exe',
      '*.jpg.exe',
      '*.png.js',
      '*.md.sh',
    ],
    detect: {
      type: 'regex',
      pattern: '.',
      flags: 'g',
    },
  },

  // ============================================
  // Time-based execution
  // ============================================
  {
    id: 'repo-delayed-execution',
    name: 'Time-delayed code execution',
    description:
      'This code has time-delayed execution. While sometimes legitimate, malware uses delays ' +
      'to evade detection and sandbox analysis.',
    severity: 'low',
    category: 'repo-heuristics',
    filePatterns: ['*.js', '*.ts', '*.py'],
    detect: {
      type: 'regex',
      pattern:
        '(setTimeout|setInterval|time\\.sleep|asyncio\\.sleep)\\s*\\([^)]*[0-9]{4,}',
      flags: 'gi',
    },
  },

  // ============================================
  // Credential patterns
  // ============================================
  {
    id: 'repo-hardcoded-key',
    name: 'Hardcoded API key or secret',
    description:
      'Found what appears to be a hardcoded API key or secret. While this might be a test key, ' +
      'it could also indicate careless security practices or intentionally exposed credentials.',
    severity: 'medium',
    category: 'repo-heuristics',
    filePatterns: ['*.js', '*.ts', '*.py', '*.json', '*.env*'],
    detect: {
      type: 'regex',
      pattern:
        '(api[_-]?key|api[_-]?secret|access[_-]?token|private[_-]?key)\\s*[=:]\\s*[\'"][a-zA-Z0-9]{20,}[\'"]',
      flags: 'gi',
    },
  },
  {
    id: 'repo-hex-private-key',
    name: 'Potential private key (hex string)',
    description:
      'Found a 64-character hex string that could be a private key. If this is a real private ' +
      'key, it should never be in source code.',
    severity: 'high',
    category: 'repo-heuristics',
    filePatterns: ['*.js', '*.ts', '*.py', '*.json', '*.env*'],
    detect: {
      type: 'regex',
      // 64 hex chars = 32 bytes = 256 bits (typical private key size)
      pattern: '(0x)?[a-fA-F0-9]{64}',
      flags: 'g',
    },
  },

  // ============================================
  // Suspicious dependencies
  // ============================================
  {
    id: 'repo-git-dependency',
    name: 'Git URL dependency',
    description:
      'This package.json has dependencies from git URLs. These bypass npm registry security ' +
      'and can point to malicious repositories.',
    severity: 'medium',
    category: 'repo-heuristics',
    filePatterns: ['package.json'],
    detect: {
      type: 'regex',
      pattern: '"(dependencies|devDependencies)"[^}]*"git(\\+https?|\\+ssh)?://',
      flags: 'gis',
    },
  },
];
