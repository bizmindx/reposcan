/**
 * RepoScan Results Panel
 * Displays scan results in a VS Code webview
 */

import * as vscode from 'vscode';
import { ScanResult, Finding, Verdict } from '../types';

export class ResultsPanel {
  public static currentPanel: ResultsPanel | undefined;
  private readonly panel: vscode.WebviewPanel;
  private disposables: vscode.Disposable[] = [];

  private constructor(panel: vscode.WebviewPanel) {
    this.panel = panel;
    this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
  }

  public static show(result: ScanResult, extensionUri: vscode.Uri): ResultsPanel {
    const column = vscode.ViewColumn.Beside;

    if (ResultsPanel.currentPanel) {
      ResultsPanel.currentPanel.panel.reveal(column);
      ResultsPanel.currentPanel.update(result);
      return ResultsPanel.currentPanel;
    }

    const panel = vscode.window.createWebviewPanel(
      'reposcanResults',
      'RepoScan Results',
      column,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
      }
    );

    ResultsPanel.currentPanel = new ResultsPanel(panel);
    ResultsPanel.currentPanel.update(result);
    return ResultsPanel.currentPanel;
  }

  public update(result: ScanResult): void {
    this.panel.webview.html = this.getHtml(result);
  }

  private getHtml(result: ScanResult): string {
    const verdictColor = this.getVerdictColor(result.verdict);
    const verdictLabel = this.getVerdictLabel(result.verdict);
    const verdictEmoji = this.getVerdictEmoji(result.verdict);

    const findingsHtml = result.findings.length > 0
      ? result.findings.map((f) => this.getFindingHtml(f)).join('')
      : '<div class="no-findings">✅ No threats detected</div>';

    const highCount = result.findings.filter((f) => f.severity === 'high').length;
    const mediumCount = result.findings.filter((f) => f.severity === 'medium').length;
    const lowCount = result.findings.filter((f) => f.severity === 'low').length;

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>RepoScan Results</title>
  <style>
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }
    body {
      font-family: var(--vscode-font-family);
      font-size: var(--vscode-font-size);
      color: var(--vscode-foreground);
      background: var(--vscode-editor-background);
      padding: 20px;
      line-height: 1.5;
    }
    .header {
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--vscode-panel-border);
    }
    .verdict {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 12px;
    }
    .verdict-badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 8px 16px;
      border-radius: 6px;
      font-size: 18px;
      font-weight: 600;
      background: ${verdictColor}22;
      border: 2px solid ${verdictColor};
      color: ${verdictColor};
    }
    .verdict-emoji {
      font-size: 24px;
    }
    .stats {
      display: flex;
      gap: 16px;
      color: var(--vscode-descriptionForeground);
      font-size: 13px;
    }
    .stat {
      display: flex;
      align-items: center;
      gap: 4px;
    }
    .severity-counts {
      display: flex;
      gap: 12px;
      margin-top: 12px;
    }
    .severity-count {
      display: flex;
      align-items: center;
      gap: 4px;
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 500;
    }
    .severity-count.high {
      background: #ff444422;
      color: #ff4444;
    }
    .severity-count.medium {
      background: #ffaa0022;
      color: #ffaa00;
    }
    .severity-count.low {
      background: #44ff4422;
      color: #44ff44;
    }
    .findings {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    .finding {
      padding: 16px;
      border-radius: 8px;
      background: var(--vscode-editor-inactiveSelectionBackground);
      border-left: 4px solid;
    }
    .finding.high {
      border-color: #ff4444;
    }
    .finding.medium {
      border-color: #ffaa00;
    }
    .finding.low {
      border-color: #44ff44;
    }
    .finding-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 8px;
    }
    .finding-title {
      font-weight: 600;
      font-size: 14px;
    }
    .finding-severity {
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
    }
    .finding-severity.high {
      background: #ff444433;
      color: #ff6666;
    }
    .finding-severity.medium {
      background: #ffaa0033;
      color: #ffcc00;
    }
    .finding-severity.low {
      background: #44ff4433;
      color: #66ff66;
    }
    .finding-file {
      font-family: var(--vscode-editor-font-family);
      font-size: 12px;
      color: var(--vscode-textLink-foreground);
      margin-bottom: 8px;
    }
    .finding-explanation {
      font-size: 13px;
      color: var(--vscode-descriptionForeground);
      line-height: 1.6;
    }
    .finding-match {
      margin-top: 8px;
      padding: 8px;
      background: var(--vscode-textCodeBlock-background);
      border-radius: 4px;
      font-family: var(--vscode-editor-font-family);
      font-size: 12px;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .no-findings {
      padding: 40px;
      text-align: center;
      font-size: 18px;
      color: #44ff44;
    }
    .warning-banner {
      padding: 16px;
      background: #ff444422;
      border: 1px solid #ff4444;
      border-radius: 8px;
      margin-bottom: 20px;
    }
    .warning-banner h3 {
      color: #ff6666;
      margin-bottom: 8px;
    }
    .warning-banner p {
      font-size: 13px;
      color: var(--vscode-foreground);
    }
  </style>
</head>
<body>
  ${result.verdict === 'high' ? `
  <div class="warning-banner">
    <h3>⚠️ HIGH RISK DETECTED</h3>
    <p>This repository contains patterns associated with wallet drains and malicious code execution. 
    <strong>Do NOT trust this workspace</strong> until you have carefully reviewed each finding.</p>
  </div>
  ` : ''}

  <div class="header">
    <div class="verdict">
      <div class="verdict-badge">
        <span class="verdict-emoji">${verdictEmoji}</span>
        <span>${verdictLabel} Risk</span>
      </div>
    </div>
    <div class="stats">
      <div class="stat">📁 ${result.scannedFiles} files scanned</div>
      <div class="stat">⏱️ ${result.scanDuration}ms</div>
      <div class="stat">🔍 ${result.findings.length} findings</div>
    </div>
    ${result.findings.length > 0 ? `
    <div class="severity-counts">
      ${highCount > 0 ? `<div class="severity-count high">🔴 ${highCount} High</div>` : ''}
      ${mediumCount > 0 ? `<div class="severity-count medium">🟡 ${mediumCount} Medium</div>` : ''}
      ${lowCount > 0 ? `<div class="severity-count low">🟢 ${lowCount} Low</div>` : ''}
    </div>
    ` : ''}
  </div>

  <div class="findings">
    ${findingsHtml}
  </div>
</body>
</html>`;
  }

  private getFindingHtml(finding: Finding): string {
    const location = finding.line
      ? `${finding.file}:${finding.line}${finding.column ? ':' + finding.column : ''}`
      : finding.file;

    return `
    <div class="finding ${finding.severity}">
      <div class="finding-header">
        <div class="finding-title">${this.escapeHtml(finding.ruleName)}</div>
        <div class="finding-severity ${finding.severity}">${finding.severity}</div>
      </div>
      <div class="finding-file">${this.escapeHtml(location)}</div>
      <div class="finding-explanation">${this.escapeHtml(finding.explanation)}</div>
      ${finding.match ? `<div class="finding-match">${this.escapeHtml(finding.match)}</div>` : ''}
    </div>`;
  }

  private getVerdictColor(verdict: Verdict): string {
    switch (verdict) {
      case 'high':
        return '#ff4444';
      case 'medium':
        return '#ffaa00';
      case 'low':
        return '#44ff44';
    }
  }

  private getVerdictLabel(verdict: Verdict): string {
    switch (verdict) {
      case 'high':
        return 'High';
      case 'medium':
        return 'Medium';
      case 'low':
        return 'Low';
    }
  }

  private getVerdictEmoji(verdict: Verdict): string {
    switch (verdict) {
      case 'high':
        return '🚨';
      case 'medium':
        return '⚠️';
      case 'low':
        return '✅';
    }
  }

  private escapeHtml(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  public dispose(): void {
    ResultsPanel.currentPanel = undefined;
    this.panel.dispose();
    while (this.disposables.length) {
      const x = this.disposables.pop();
      if (x) {
        x.dispose();
      }
    }
  }
}
