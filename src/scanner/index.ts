/**
 * RepoScan Scanner Engine
 * Walks the repository tree and applies detection rules
 */

import * as fs from 'fs';
import * as path from 'path';
import { Finding, Rule, ScanOptions, ScanResult, Verdict } from '../types';
import { getAllRules } from '../rules';
import { matchFile, applyRule } from './matcher';

const DEFAULT_EXCLUDE = [
  'node_modules',
  '.git',
  'dist',
  'build',
  'out',
  '.next',
  '__pycache__',
  'venv',
  '.venv',
  'target',
];

const DEFAULT_MAX_FILE_SIZE = 1024 * 1024; // 1MB
const DEFAULT_TIMEOUT = 30000; // 30 seconds

export class Scanner {
  private options: Required<ScanOptions>;
  private rules: Rule[];
  private findings: Finding[] = [];
  private scannedFiles = 0;
  private startTime = 0;
  private aborted = false;

  constructor(options: ScanOptions) {
    this.options = {
      rootPath: options.rootPath,
      excludePatterns: options.excludePatterns ?? DEFAULT_EXCLUDE,
      maxFileSize: options.maxFileSize ?? DEFAULT_MAX_FILE_SIZE,
      timeout: options.timeout ?? DEFAULT_TIMEOUT,
    };
    this.rules = getAllRules();
  }

  /**
   * Run the full repository scan
   */
  async scan(): Promise<ScanResult> {
    this.startTime = Date.now();
    this.findings = [];
    this.scannedFiles = 0;
    this.aborted = false;

    try {
      await this.walkDirectory(this.options.rootPath);
    } catch (error) {
      // Log but don't fail the scan
      console.error('Scanner error:', error);
    }

    const scanDuration = Date.now() - this.startTime;
    const verdict = this.determineVerdict();

    return {
      verdict,
      findings: this.findings,
      scannedFiles: this.scannedFiles,
      scanDuration,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Abort the current scan
   */
  abort(): void {
    this.aborted = true;
  }

  /**
   * Walk directory recursively
   */
  private async walkDirectory(dirPath: string): Promise<void> {
    if (this.aborted || this.isTimedOut()) {
      return;
    }

    let entries: fs.Dirent[];
    try {
      entries = await fs.promises.readdir(dirPath, { withFileTypes: true });
    } catch {
      // Permission denied or other error - skip
      return;
    }

    for (const entry of entries) {
      if (this.aborted || this.isTimedOut()) {
        break;
      }

      const fullPath = path.join(dirPath, entry.name);
      const relativePath = path.relative(this.options.rootPath, fullPath);

      // Skip excluded paths
      if (this.shouldExclude(relativePath, entry.name)) {
        continue;
      }

      if (entry.isDirectory()) {
        await this.walkDirectory(fullPath);
      } else if (entry.isFile()) {
        await this.scanFile(fullPath, relativePath);
      }
    }
  }

  /**
   * Scan a single file
   */
  private async scanFile(fullPath: string, relativePath: string): Promise<void> {
    // Check file size
    try {
      const stats = await fs.promises.stat(fullPath);
      if (stats.size > this.options.maxFileSize) {
        return;
      }
    } catch {
      return;
    }

    // Get applicable rules for this file
    const applicableRules = this.rules.filter((rule) =>
      matchFile(relativePath, rule.filePatterns)
    );

    if (applicableRules.length === 0) {
      return;
    }

    // Read file content
    let content: string;
    try {
      content = await fs.promises.readFile(fullPath, 'utf-8');
    } catch {
      return;
    }

    this.scannedFiles++;

    // Apply each applicable rule
    for (const rule of applicableRules) {
      const ruleFindings = applyRule(rule, relativePath, content);
      this.findings.push(...ruleFindings);
    }
  }

  /**
   * Check if path should be excluded
   */
  private shouldExclude(relativePath: string, name: string): boolean {
    // Skip hidden files/folders (except .vscode which we need to scan)
    if (name.startsWith('.') && name !== '.vscode') {
      return true;
    }

    return this.options.excludePatterns.some((pattern) => {
      if (pattern.includes('/')) {
        return relativePath.includes(pattern);
      }
      return name === pattern || relativePath.split(path.sep).includes(pattern);
    });
  }

  /**
   * Check if scan has timed out
   */
  private isTimedOut(): boolean {
    return Date.now() - this.startTime > this.options.timeout;
  }

  /**
   * Determine overall verdict based on findings
   */
  private determineVerdict(): Verdict {
    const hasHigh = this.findings.some((f) => f.severity === 'high');
    const hasMedium = this.findings.some((f) => f.severity === 'medium');

    if (hasHigh) {
      return 'high';
    }
    if (hasMedium) {
      return 'medium';
    }
    return 'low';
  }
}

/**
 * Convenience function to run a scan
 */
export async function scanRepository(rootPath: string): Promise<ScanResult> {
  const scanner = new Scanner({ rootPath });
  return scanner.scan();
}
