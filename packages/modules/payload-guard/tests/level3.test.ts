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

describe('Level 3: Advanced Penetration and Injection Attacks', () => {
  describe('Multi-Stage Injection Attacks', () => {
    it('should detect a base64-encoded payload after decoding (simulating runtime deobfuscation)', () => {
      const base64Payload = Buffer.from("<script>eval('alert(1)')</script>").toString('base64');
      const decodedPayload = Buffer.from(base64Payload, 'base64').toString('utf8');
      const result = detectXSS(decodedPayload);
      expect(result.detected).toBe(true);
      expect(result.type).toBe(PayloadGuardEventType.XSS_DETECTED);
    });

    it('should detect a payload constructed via string concatenation to evade static analysis', () => {
      const part1 = '<scr';
      const part2 = "ipt>alert('";
      const part3 = "XSS')";
      const part4 = '</scr';
      const part5 = 'ipt>';
      const fullPayload = part1 + part2 + part3 + part4 + part5;
      const result = detectXSS(fullPayload);
      expect(result.detected).toBe(true);
    });
  });

  describe('Multi-Vector Injection Attack', () => {
    it('should detect a payload combining SQLi and command injection vectors', () => {
      const payload = '1; DROP TABLE users; -- && echo `id`';
      const resultSQL = detectSQLi(payload);
      const resultCmd = detectCommandInjection(payload);
      expect(resultSQL.detected || resultCmd.detected).toBe(true);
    });

    it('should detect a payload combining NoSQLi and template injection patterns', () => {
      const payload = '{"$gt": ""} {{user.input}}';
      const resultNoSQL = detectNoSQLi(payload);
      const resultTemplate = detectTemplateInjection(payload);
      expect(resultNoSQL.detected || resultTemplate.detected).toBe(true);
    });
  });

  describe('Deeply Nested Complex Object Attacks', () => {
    it('should detect an injection buried deep within a multi-level object structure', () => {
      const obj = {
        level1: [
          {
            level2: {
              level3: [
                'clean',
                {
                  level4: {
                    level5: {
                      payload: '<div onerror=\'javascript:alert("XSS")\'>',
                    },
                  },
                },
              ],
            },
          },
        ],
      };
      const detectors = [
        detectXSS,
        detectSQLi,
        detectCommandInjection,
        detectPathTraversal,
        detectNoSQLi,
        detectTemplateInjection,
      ];
      const result = traverseAndCheck(obj, '', detectors);
      expect(result.detected).toBe(true);
      expect(result.path).toMatch(/level1\[\d+\]\.level2\.level3\[\d+\]\.level4\.level5\.payload/);
      expect(result.type).toBe(PayloadGuardEventType.XSS_DETECTED);
    });

    it('should not produce false positives on deeply nested safe objects with decoy patterns', () => {
      const obj = {
        level1: {
          safe: 'This is safe, even though it mentions SELECT and <div> tags',
          array: ['safe string', { decoy: 'Just a comment: union select data' }],
          nested: {
            field: 'Another safe field without real injection',
          },
        },
      };
      const detectors = [
        detectXSS,
        detectSQLi,
        detectCommandInjection,
        detectPathTraversal,
        detectNoSQLi,
        detectTemplateInjection,
      ];
      const result = traverseAndCheck(obj, '', detectors);
      expect(result.detected).toBe(false);
    });
  });

  describe('Dynamic Field Name Injection', () => {
    it('should detect injections in fields with dynamic names not explicitly excluded', () => {
      const obj = {
        safe: 'normal',
        [`inj${'ect'}`]: "<script>alert('XSS')</script>",
      };
      const detectors = [
        detectXSS,
        detectSQLi,
        detectCommandInjection,
        detectPathTraversal,
        detectNoSQLi,
        detectTemplateInjection,
      ];
      const result = traverseAndCheck(obj, '', detectors, ['nonExistent']);
      expect(result.detected).toBe(true);
      expect(result.type).toBe(PayloadGuardEventType.XSS_DETECTED);
    });
  });

  describe('Obfuscated Patterns with Whitespace and Decoys', () => {
    it('should detect SQL injection payloads obfuscated with excessive whitespace and newline characters', () => {
      const payload = "SEL\nECT *\tFROM\nusers WHERE username='admin'";
      const result = detectSQLi(payload);
      expect(result.detected).toBe(true);
    });

    it('should detect injection payloads hidden within seemingly benign text', () => {
      const payload =
        'Hello, world! ' + '<script>' + "alert('XSS')" + '</script>' + ' Have a nice day!';
      const result = detectXSS(payload);
      expect(result.detected).toBe(true);
    });
  });
});
