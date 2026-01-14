/**
 * RepoScan Rule Matcher
 * Matches files against rules and extracts findings
 */

import { Finding, Rule, JsonCondition } from '../types';

/**
 * Check if a file path matches any of the given patterns
 */
export function matchFile(filePath: string, patterns: string[]): boolean {
  const normalizedPath = filePath.replace(/\\/g, '/').toLowerCase();

  return patterns.some((pattern) => {
    const normalizedPattern = pattern.toLowerCase();

    // Exact match
    if (normalizedPath === normalizedPattern) {
      return true;
    }

    // Ends with pattern (e.g., "tasks.json" matches ".vscode/tasks.json")
    if (normalizedPath.endsWith(normalizedPattern)) {
      return true;
    }

    // Glob-like matching for extensions
    if (pattern.startsWith('*.')) {
      const ext = pattern.slice(1);
      return normalizedPath.endsWith(ext);
    }

    // Directory prefix match
    if (pattern.endsWith('/')) {
      return normalizedPath.startsWith(normalizedPattern);
    }

    // Contains match for paths with wildcards
    if (pattern.includes('*')) {
      const regex = new RegExp(
        '^' + pattern.replace(/\*/g, '.*').replace(/\//g, '\\/') + '$',
        'i'
      );
      return regex.test(normalizedPath);
    }

    return false;
  });
}

/**
 * Apply a rule to file content and return findings
 */
export function applyRule(rule: Rule, filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];

  switch (rule.detect.type) {
    case 'regex':
      findings.push(...applyRegexRule(rule, filePath, content));
      break;

    case 'json-path':
      findings.push(...applyJsonPathRule(rule, filePath, content));
      break;

    case 'file-exists':
      // File exists check is handled at scanner level
      findings.push({
        ruleId: rule.id,
        ruleName: rule.name,
        severity: rule.severity,
        category: rule.category,
        file: filePath,
        message: rule.name,
        explanation: rule.description,
      });
      break;

    case 'custom':
      // Custom handlers can be added here
      break;
  }

  return findings;
}

/**
 * Apply regex-based detection
 */
function applyRegexRule(rule: Rule, filePath: string, content: string): Finding[] {
  if (rule.detect.type !== 'regex') return [];

  const findings: Finding[] = [];
  const { pattern, flags = 'gm' } = rule.detect;

  try {
    const regex = new RegExp(pattern, flags);
    const lines = content.split('\n');

    let match: RegExpExecArray | null;
    while ((match = regex.exec(content)) !== null) {
      // Find line number
      const beforeMatch = content.slice(0, match.index);
      const lineNumber = beforeMatch.split('\n').length;

      // Find column
      const lastNewline = beforeMatch.lastIndexOf('\n');
      const column = match.index - lastNewline;

      findings.push({
        ruleId: rule.id,
        ruleName: rule.name,
        severity: rule.severity,
        category: rule.category,
        file: filePath,
        line: lineNumber,
        column: column,
        match: match[0].slice(0, 200), // Truncate long matches
        message: rule.name,
        explanation: rule.description,
      });

      // Prevent infinite loops on zero-width matches
      if (match[0].length === 0) {
        regex.lastIndex++;
      }
    }
  } catch (error) {
    console.error(`Invalid regex in rule ${rule.id}:`, error);
  }

  return findings;
}

/**
 * Apply JSON path-based detection
 */
function applyJsonPathRule(rule: Rule, filePath: string, content: string): Finding[] {
  if (rule.detect.type !== 'json-path') return [];

  const findings: Finding[] = [];

  try {
    const json = JSON.parse(content);
    const { path, condition } = rule.detect;

    const value = getJsonPath(json, path);

    if (checkCondition(value, condition)) {
      // Find line number of the path in the JSON
      const lineNumber = findJsonPathLine(content, path);

      findings.push({
        ruleId: rule.id,
        ruleName: rule.name,
        severity: rule.severity,
        category: rule.category,
        file: filePath,
        line: lineNumber,
        match: JSON.stringify(value).slice(0, 200),
        message: rule.name,
        explanation: rule.description,
      });
    }
  } catch {
    // Not valid JSON or path doesn't exist - skip
  }

  return findings;
}

/**
 * Get value at JSON path (simple dot notation)
 */
function getJsonPath(obj: unknown, path: string): unknown {
  const parts = path.split('.');
  let current: unknown = obj;

  for (const part of parts) {
    if (current === null || current === undefined) {
      return undefined;
    }

    // Handle array notation like "tasks[0]"
    const arrayMatch = part.match(/^(\w+)\[(\d+)\]$/);
    if (arrayMatch) {
      const [, key, index] = arrayMatch;
      current = (current as Record<string, unknown>)[key];
      if (Array.isArray(current)) {
        current = current[parseInt(index, 10)];
      } else {
        return undefined;
      }
    } else if (part === '*') {
      // Wildcard - return all values if it's an array or object
      if (Array.isArray(current)) {
        return current;
      }
      if (typeof current === 'object' && current !== null) {
        return Object.values(current);
      }
      return undefined;
    } else {
      current = (current as Record<string, unknown>)[part];
    }
  }

  return current;
}

/**
 * Check if value matches condition
 */
function checkCondition(value: unknown, condition: JsonCondition): boolean {
  switch (condition.op) {
    case 'exists':
      return value !== undefined && value !== null;

    case 'equals':
      return value === condition.value;

    case 'contains':
      if (typeof value === 'string') {
        return value.includes(condition.value);
      }
      if (Array.isArray(value)) {
        return value.some(
          (v) => typeof v === 'string' && v.includes(condition.value)
        );
      }
      return JSON.stringify(value).includes(condition.value);

    case 'matches':
      if (typeof value === 'string') {
        return new RegExp(condition.pattern).test(value);
      }
      return new RegExp(condition.pattern).test(JSON.stringify(value));

    default:
      return false;
  }
}

/**
 * Find approximate line number for a JSON path
 */
function findJsonPathLine(content: string, path: string): number {
  const parts = path.split('.');
  const searchKey = parts[parts.length - 1].replace(/\[\d+\]$/, '');

  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes(`"${searchKey}"`)) {
      return i + 1;
    }
  }

  return 1;
}
