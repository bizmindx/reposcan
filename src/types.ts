/**
 * RepoScan Type Definitions
 */

export type Severity = 'high' | 'medium' | 'low' | 'info';

export type Verdict = 'high' | 'medium' | 'low';

export interface Rule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  category: RuleCategory;
  filePatterns: string[];
  detect: DetectionMethod;
}

export type RuleCategory =
  | 'vscode-config'
  | 'javascript'
  | 'python'
  | 'shell'
  | 'solidity'
  | 'repo-heuristics';

export type DetectionMethod =
  | { type: 'regex'; pattern: string; flags?: string }
  | { type: 'json-path'; path: string; condition: JsonCondition }
  | { type: 'file-exists'; paths: string[] }
  | { type: 'custom'; handler: string };

export type JsonCondition =
  | { op: 'exists' }
  | { op: 'equals'; value: unknown }
  | { op: 'contains'; value: string }
  | { op: 'matches'; pattern: string };

export interface Finding {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  category: RuleCategory;
  file: string;
  line?: number;
  column?: number;
  match?: string;
  message: string;
  explanation: string;
}

export interface ScanResult {
  verdict: Verdict;
  findings: Finding[];
  scannedFiles: number;
  scanDuration: number;
  timestamp: string;
}

export interface ScanOptions {
  rootPath: string;
  excludePatterns?: string[];
  maxFileSize?: number;
  timeout?: number;
}
