/**
 * RepoScan Rule Engine
 * Central registry for all detection rules
 */

import { Rule } from '../types';
import { vscodeRules } from './vscode-rules';
import { javascriptRules } from './javascript-rules';
import { pythonRules } from './python-rules';
import { shellRules } from './shell-rules';
import { repoHeuristicsRules } from './repo-heuristics-rules';

/**
 * Get all registered rules
 */
export function getAllRules(): Rule[] {
  return [
    ...vscodeRules,
    ...javascriptRules,
    ...pythonRules,
    ...shellRules,
    ...repoHeuristicsRules,
  ];
}

/**
 * Get rules by category
 */
export function getRulesByCategory(category: string): Rule[] {
  return getAllRules().filter((rule) => rule.category === category);
}

/**
 * Get rule by ID
 */
export function getRuleById(id: string): Rule | undefined {
  return getAllRules().find((rule) => rule.id === id);
}
