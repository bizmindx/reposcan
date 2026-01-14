/**
 * RepoScan - VS Code Extension
 * "RepoScan warns you before a repo can steal from you."
 *
 * @license AGPL-3.0
 */

import * as vscode from 'vscode';
import { Scanner, scanRepository } from './scanner';
import { ResultsPanel } from './ui/results-panel';
import { ScanResult } from './types';

let currentScanner: Scanner | undefined;

export function activate(context: vscode.ExtensionContext) {
  console.log('RepoScan is now active');

  // Register scan repository command
  const scanRepoCommand = vscode.commands.registerCommand(
    'reposcan.scanRepository',
    async (uri?: vscode.Uri) => {
      await runScan(uri, context);
    }
  );

  // Register scan file command
  const scanFileCommand = vscode.commands.registerCommand(
    'reposcan.scanFile',
    async (uri?: vscode.Uri) => {
      if (uri) {
        await runScan(uri, context);
      } else {
        const editor = vscode.window.activeTextEditor;
        if (editor) {
          await runScan(editor.document.uri, context);
        }
      }
    }
  );

  // Auto-prompt on untrusted workspace (future enhancement)
  // For now, users manually trigger the scan

  context.subscriptions.push(scanRepoCommand, scanFileCommand);

  // Show welcome message for untrusted workspaces
  if (!vscode.workspace.isTrusted) {
    showUntrustedWorkspaceNotice();
  }
}

async function runScan(uri: vscode.Uri | undefined, context: vscode.ExtensionContext) {
  // Determine scan root
  let scanRoot: string;

  if (uri) {
    scanRoot = uri.fsPath;
  } else if (vscode.workspace.workspaceFolders?.length) {
    // Let user pick if multiple folders
    if (vscode.workspace.workspaceFolders.length > 1) {
      const picked = await vscode.window.showWorkspaceFolderPick({
        placeHolder: 'Select folder to scan',
      });
      if (!picked) return;
      scanRoot = picked.uri.fsPath;
    } else {
      scanRoot = vscode.workspace.workspaceFolders[0].uri.fsPath;
    }
  } else {
    vscode.window.showErrorMessage('No folder open. Open a folder to scan.');
    return;
  }

  // Show progress
  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'RepoScan',
      cancellable: true,
    },
    async (progress, token) => {
      progress.report({ message: 'Scanning repository...' });

      // Create scanner
      currentScanner = new Scanner({ rootPath: scanRoot });

      // Handle cancellation
      token.onCancellationRequested(() => {
        currentScanner?.abort();
      });

      try {
        const result = await currentScanner.scan();
        currentScanner = undefined;

        // Show results
        showResults(result, context);

        // Show notification based on verdict
        showVerdictNotification(result);

        // Set context for UI
        vscode.commands.executeCommand('setContext', 'reposcan.hasResults', true);
      } catch (error) {
        currentScanner = undefined;
        vscode.window.showErrorMessage(`RepoScan error: ${error}`);
      }
    }
  );
}

function showResults(result: ScanResult, context: vscode.ExtensionContext) {
  ResultsPanel.show(result, context.extensionUri);
}

function showVerdictNotification(result: ScanResult) {
  const highCount = result.findings.filter((f) => f.severity === 'high').length;
  const mediumCount = result.findings.filter((f) => f.severity === 'medium').length;

  if (result.verdict === 'high') {
    vscode.window.showErrorMessage(
      `🚨 HIGH RISK: Found ${highCount} critical security issues. DO NOT trust this workspace.`,
      'View Details'
    ).then((action) => {
      if (action === 'View Details') {
        vscode.commands.executeCommand('reposcanResults.focus');
      }
    });
  } else if (result.verdict === 'medium') {
    vscode.window.showWarningMessage(
      `⚠️ CAUTION: Found ${mediumCount} suspicious patterns. Review before trusting.`,
      'View Details'
    ).then((action) => {
      if (action === 'View Details') {
        vscode.commands.executeCommand('reposcanResults.focus');
      }
    });
  } else {
    vscode.window.showInformationMessage(
      `✅ LOW RISK: No critical issues found. ${result.scannedFiles} files scanned.`
    );
  }
}

function showUntrustedWorkspaceNotice() {
  vscode.window.showInformationMessage(
    '🔍 RepoScan: Run "RepoScan: Scan Repository" before trusting this workspace.',
    'Scan Now'
  ).then((action) => {
    if (action === 'Scan Now') {
      vscode.commands.executeCommand('reposcan.scanRepository');
    }
  });
}

export function deactivate() {
  currentScanner?.abort();
}
