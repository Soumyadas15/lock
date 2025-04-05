import { describe, it, expect } from 'vitest';
import {
  detectXSS,
  detectSQLi,
  detectNoSQLi,
  detectTemplateInjection,
} from '../src/utils';
import { PayloadGuardEventType } from '../src/types';

describe('Level 4: Sophisticated Evasion Techniques', () => {
  describe('Advanced Encoding and Obfuscation', () => {
    it('should detect double-encoded XSS payloads', () => {
      // Single encoding: "<script>alert(1)</script>" -> %3Cscript%3Ealert%281%29%3C%2Fscript%3E
      // Double encoding: %253Cscript%253Ealert%25281%2529%253C%252Fscript%253E
      const doubleEncodedPayload = '%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E';
      const singleDecodedPayload = decodeURIComponent(doubleEncodedPayload);
      const fullyDecodedPayload = decodeURIComponent(singleDecodedPayload);

      // Test if our detector can find XSS after full decoding
      const result = detectXSS(fullyDecodedPayload);
      expect(result.detected).toBe(true);
      expect(result.type).toBe(PayloadGuardEventType.XSS_DETECTED);
    });

    it('should detect hex-encoded JavaScript execution', () => {
      const payload =
        '\\x3c\\x73\\x63\\x72\\x69\\x70\\x74\\x3e\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29\\x3c\\x2f\\x73\\x63\\x72\\x69\\x70\\x74\\x3e';
      // This would be decoded at runtime to: <script>alert(1)</script>

      // For testing purposes, let's simulate decoding
      const decoded = payload.replace(/\\x([0-9A-Fa-f]{2})/g, (_, hex) =>
        String.fromCharCode(parseInt(hex, 16))
      );

      const result = detectXSS(decoded);
      expect(result.detected).toBe(true);
    });

    it('should detect unicode-escaped payloads', () => {
      // Unicode escape for: <img src=x onerror=alert(1)>
      const payload = '\\u003Cimg\\u0020src\\u003Dx\\u0020onerror\\u003Dalert(1)\\u003E';

      // Simulate JavaScript unicode interpretation
      const decoded = payload.replace(/\\u([0-9A-Fa-f]{4})/g, (_, hex) =>
        String.fromCharCode(parseInt(hex, 16))
      );

      const result = detectXSS(decoded);
      expect(result.detected).toBe(true);
    });
  });

  describe('Polyglot Injection Attacks', () => {
    it('should detect polyglot payloads targeting multiple contexts', () => {
      // This is a polyglot payload that can work as XSS and SQLi
      const polyglot = '\'";</script><script>alert(1)</script><script>"\'';

      const xssResult = detectXSS(polyglot);
      const sqlResult = detectSQLi(polyglot);

      expect(xssResult.detected || sqlResult.detected).toBe(true);
    });

    it('should detect mutation XSS combined with HTML5 features', () => {
      // Complex mutation XSS using HTML5 attributes and non-standard tags
      const payload = '<svg><animate onbegin=alert(1) attributeName=x dur=1s>';
      const result = detectXSS(payload);
      expect(result.detected).toBe(true);
    });
  });

  describe('Dynamic Runtime Evasion', () => {
    it('should detect attacks using DOM-clobbering techniques', () => {
      // DOM clobbering payload that creates properties/methods at runtime
      const payload = '<form id=test><input id=parentNode name=innerText>';
      const result = detectXSS(payload);
      expect(result.detected).toBe(true);
    });

    it('should detect JavaScript prototype pollution attempts', () => {
      // Payload attempting to modify Object.prototype via JSON
      const payload = '{"__proto__":{"isAdmin":true}}';
      // This isn't a direct XSS but a serious security issue
      const result = detectNoSQLi(payload);
      expect(result.detected).toBe(true);
    });
  });

  describe('Context-Aware Attacks', () => {
    it('should detect template injection in Angular-style contexts', () => {
      const payload = '{{constructor.constructor("alert(1)")()}}';
      const result = detectTemplateInjection(payload);
      expect(result.detected).toBe(true);
    });

    it('should detect conditional blinds in SQL injections', () => {
      // Time-based blind SQLi
      const payload = "1; IF (1=1) WAITFOR DELAY '0:0:5'--";
      const result = detectSQLi(payload);
      expect(result.detected).toBe(true);
    });
  });

  describe('Filter Evasion Techniques', () => {
    it('should detect XSS with null bytes attempting to bypass filters', () => {
      // Null byte insertion to confuse parsers
      const payload = '<scr\0ipt>alert(1)</script>';
      const result = detectXSS(payload);
      expect(result.detected).toBe(true);
    });

    it('should detect XSS using uncommon event handlers', () => {
      // Less common event handlers that might bypass simple filters
      const payload = '<div onpointerrawupdate="alert(1)"></div>';
      const result = detectXSS(payload);
      expect(result.detected).toBe(true);
    });

    it('should detect SQLi using case variation and comments', () => {
      // Mix of case and inline comments to evade detection
      const payload = 'sEL/**/ecT/**/name/**/Fr/**/OM/**/users;';
      const result = detectSQLi(payload);
      expect(result.detected).toBe(true);
    });
  });
});
