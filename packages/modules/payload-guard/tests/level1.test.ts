import { describe, it, expect } from 'vitest';
import {
  generateHash,
  detectXSS,
  detectSQLi,
  detectCommandInjection,
  detectPathTraversal,
  detectNoSQLi,
  detectTemplateInjection,
  traverseAndCheck,
} from '../src/utils';
import { PayloadGuardEventType } from '../src/types';

describe('generateHash', () => {
  it('should return "0" for an empty string', () => {
    expect(generateHash('')).toBe('0');
  });

  it('should generate the same hash for the same input', () => {
    const input = 'consistent';
    const hash1 = generateHash(input);
    const hash2 = generateHash(input);
    expect(hash1).toBe(hash2);
  });

  it('should generate different hashes for different inputs', () => {
    const hash1 = generateHash('input1');
    const hash2 = generateHash('input2');
    expect(hash1).not.toBe(hash2);
  });
});

describe('detectXSS', () => {
  it('should not detect XSS in benign input', () => {
    const result = detectXSS('Hello, world!');
    expect(result.detected).toBe(false);
  });

  it('should detect XSS with a <script> tag', () => {
    const malicious = `<script>alert('xss')</script>`;
    const result = detectXSS(malicious);
    expect(result.detected).toBe(true);
    expect(result.type).toBe(PayloadGuardEventType.XSS_DETECTED);
  });

  it('should detect XSS with inline event handler', () => {
    const malicious = `<div onclick="alert('xss')">Click me</div>`;
    const result = detectXSS(malicious);
    expect(result.detected).toBe(true);
  });
});

describe('detectSQLi', () => {
  it('should not detect SQLi in benign input', () => {
    const result = detectSQLi('Just some harmless text');
    expect(result.detected).toBe(false);
  });

  it('should detect SQLi with a SELECT statement', () => {
    const malicious = "SELECT * FROM users WHERE username = 'admin'";
    const result = detectSQLi(malicious);
    expect(result.detected).toBe(true);
    expect(result.type).toBe(PayloadGuardEventType.SQL_INJECTION_DETECTED);
  });

  it('should detect SQLi with DROP table', () => {
    const malicious = 'DROP table users;';
    const result = detectSQLi(malicious);
    expect(result.detected).toBe(true);
  });
});

describe('detectCommandInjection', () => {
  it('should not detect command injection in benign input', () => {
    const result = detectCommandInjection('Normal text with no commands.');
    expect(result.detected).toBe(false);
  });

  it('should detect command injection using backticks', () => {
    const malicious = '`rm -rf /`';
    const result = detectCommandInjection(malicious);
    expect(result.detected).toBe(true);
    expect(result.type).toBe(PayloadGuardEventType.COMMAND_INJECTION_DETECTED);
  });

  it('should detect command injection using semicolon followed by command', () => {
    const malicious = '; rm -rf /';
    const result = detectCommandInjection(malicious);
    expect(result.detected).toBe(true);
  });

  it('should detect command injection using common binary references', () => {
    const malicious = "Run /bin/sh -c 'echo hacked'";
    const result = detectCommandInjection(malicious);
    expect(result.detected).toBe(true);
  });
});

describe('detectPathTraversal', () => {
  it('should not detect path traversal in safe input', () => {
    const result = detectPathTraversal('This is a safe path string.');
    expect(result.detected).toBe(false);
  });

  it('should detect path traversal using "../"', () => {
    const malicious = '../etc/passwd';
    const result = detectPathTraversal(malicious);
    expect(result.detected).toBe(true);
    expect(result.type).toBe(PayloadGuardEventType.PATH_TRAVERSAL_DETECTED);
  });

  it('should detect path traversal using encoded sequences', () => {
    const malicious = '..%2fetc%2fpasswd';
    const result = detectPathTraversal(malicious);
    expect(result.detected).toBe(true);
  });
});

describe('detectNoSQLi', () => {
  it('should not detect NoSQL injection in safe input', () => {
    const result = detectNoSQLi('Safe text without injections.');
    expect(result.detected).toBe(false);
  });

  it('should detect NoSQL injection with operator syntax', () => {
    const malicious = '{ $gt: 1 }';
    const result = detectNoSQLi(malicious);
    expect(result.detected).toBe(true);
    expect(result.type).toBe(PayloadGuardEventType.GENERAL_INJECTION_DETECTED);
  });
});

describe('detectTemplateInjection', () => {
  it('should not detect template injection in safe input', () => {
    const result = detectTemplateInjection('Nothing to inject here.');
    expect(result.detected).toBe(false);
  });

  it('should detect template injection with handlebars syntax', () => {
    const malicious = '{{ user.input }}';
    const result = detectTemplateInjection(malicious);
    expect(result.detected).toBe(true);
    expect(result.type).toBe(PayloadGuardEventType.GENERAL_INJECTION_DETECTED);
  });

  it('should detect template injection with ${...} syntax', () => {
    const malicious = '${7*7}';
    const result = detectTemplateInjection(malicious);
    expect(result.detected).toBe(true);
  });
});

describe('traverseAndCheck', () => {
  const detectors = [
    detectXSS,
    detectSQLi,
    detectCommandInjection,
    detectPathTraversal,
    detectNoSQLi,
    detectTemplateInjection,
  ];

  it('should not detect any injection in an object with safe strings', () => {
    const obj = {
      a: 'safe',
      b: ['still safe', 'also safe'],
      c: { nested: 'clean text' },
    };
    const result = traverseAndCheck(obj, '', detectors);
    expect(result.detected).toBe(false);
  });

  it('should detect XSS in a nested object', () => {
    const obj = {
      a: 'safe',
      b: {
        nested: `<script>alert('xss')</script>`,
      },
    };
    const result = traverseAndCheck(obj, '', detectors);
    expect(result.detected).toBe(true);
    expect(result.path).toBe('b.nested');
    expect(result.type).toBe(PayloadGuardEventType.XSS_DETECTED);
  });

  it('should detect SQLi in an array', () => {
    const obj = {
      arr: ['clean', "SELECT * FROM users WHERE username = 'admin'", 'clean'],
    };
    const result = traverseAndCheck(obj, '', detectors);
    expect(result.detected).toBe(true);
    expect(result.path).toBe('arr[1]');
    expect(result.type).toBe(PayloadGuardEventType.SQL_INJECTION_DETECTED);
  });

  it('should skip excluded fields during traversal', () => {
    const obj = {
      safeField: 'clean',
      ignore: `<script>alert('xss')</script>`,
    };
    const result = traverseAndCheck(obj, '', detectors, ['ignore']);
    expect(result.detected).toBe(false);
  });

  it('should handle null and undefined values gracefully', () => {
    expect(traverseAndCheck(null, '', detectors).detected).toBe(false);
    expect(traverseAndCheck(undefined, '', detectors).detected).toBe(false);
  });
});
