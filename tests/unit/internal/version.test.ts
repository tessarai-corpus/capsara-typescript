/// <reference types="vitest/globals" />
/**
 * Tests for SDK version information module
 * @module tests/unit/internal/version.test
 *
 * Tests exported version constants and User-Agent builder function:
 * - SDK_VERSION constant value
 * - SDK_NAME constant value
 * - DEFAULT_USER_AGENT format and composition
 * - buildUserAgent() function behavior with and without custom agent strings
 */

import {
  SDK_VERSION,
  SDK_NAME,
  DEFAULT_USER_AGENT,
  buildUserAgent,
} from '../../../src/internal/version.js';

describe('SDK Version Module', () => {
  describe('SDK_VERSION Constant', () => {
    it('should be a string', () => {
      expect(typeof SDK_VERSION).toBe('string');
    });

    it('should have expected value of 1.0.0', () => {
      expect(SDK_VERSION).toBe('1.0.0');
    });

    it('should follow semantic versioning format (major.minor.patch)', () => {
      const semverRegex = /^\d+\.\d+\.\d+$/;
      expect(SDK_VERSION).toMatch(semverRegex);
    });

    it('should not be empty', () => {
      expect(SDK_VERSION.length).toBeGreaterThan(0);
    });

    it('should not contain leading or trailing whitespace', () => {
      expect(SDK_VERSION).toBe(SDK_VERSION.trim());
    });
  });

  describe('SDK_NAME Constant', () => {
    it('should be a string', () => {
      expect(typeof SDK_NAME).toBe('string');
    });

    it('should have expected value of Capsara-SDK-typescript', () => {
      expect(SDK_NAME).toBe('Capsara-SDK-typescript');
    });

    it('should not be empty', () => {
      expect(SDK_NAME.length).toBeGreaterThan(0);
    });

    it('should not contain leading or trailing whitespace', () => {
      expect(SDK_NAME).toBe(SDK_NAME.trim());
    });

    it('should not contain spaces (URL-safe format)', () => {
      expect(SDK_NAME).not.toContain(' ');
    });
  });

  describe('DEFAULT_USER_AGENT Constant', () => {
    it('should be a string', () => {
      expect(typeof DEFAULT_USER_AGENT).toBe('string');
    });

    it('should include SDK_NAME', () => {
      expect(DEFAULT_USER_AGENT).toContain(SDK_NAME);
    });

    it('should include SDK_VERSION', () => {
      expect(DEFAULT_USER_AGENT).toContain(SDK_VERSION);
    });

    it('should include Node.js version indicator', () => {
      expect(DEFAULT_USER_AGENT).toContain('Node.js');
    });

    it('should include actual Node.js process version', () => {
      expect(DEFAULT_USER_AGENT).toContain(process.version);
    });

    it('should follow expected format: SDK_NAME/SDK_VERSION (Node.js version)', () => {
      const expectedFormat = `${SDK_NAME}/${SDK_VERSION} (Node.js ${process.version})`;
      expect(DEFAULT_USER_AGENT).toBe(expectedFormat);
    });

    it('should not be empty', () => {
      expect(DEFAULT_USER_AGENT.length).toBeGreaterThan(0);
    });

    it('should not contain leading or trailing whitespace', () => {
      expect(DEFAULT_USER_AGENT).toBe(DEFAULT_USER_AGENT.trim());
    });

    it('should start with SDK_NAME', () => {
      expect(DEFAULT_USER_AGENT.startsWith(SDK_NAME)).toBe(true);
    });

    it('should contain slash separator between name and version', () => {
      expect(DEFAULT_USER_AGENT).toContain(`${SDK_NAME}/${SDK_VERSION}`);
    });

    it('should contain Node.js version in parentheses', () => {
      const nodeVersionPattern = /\(Node\.js v\d+\.\d+\.\d+\)/;
      expect(DEFAULT_USER_AGENT).toMatch(nodeVersionPattern);
    });
  });

  describe('buildUserAgent Function', () => {
    describe('Without Custom Agent (Default Behavior)', () => {
      it('should return DEFAULT_USER_AGENT when called without arguments', () => {
        const result = buildUserAgent();
        expect(result).toBe(DEFAULT_USER_AGENT);
      });

      it('should return DEFAULT_USER_AGENT when called with undefined', () => {
        const result = buildUserAgent(undefined);
        expect(result).toBe(DEFAULT_USER_AGENT);
      });

      it('should return a string type', () => {
        const result = buildUserAgent();
        expect(typeof result).toBe('string');
      });

      it('should return consistent results on multiple calls', () => {
        const result1 = buildUserAgent();
        const result2 = buildUserAgent();
        const result3 = buildUserAgent();
        expect(result1).toBe(result2);
        expect(result2).toBe(result3);
      });
    });

    describe('With Custom Agent String', () => {
      it('should append custom agent with space separator', () => {
        const customAgent = 'MyApp/1.0.0';
        const result = buildUserAgent(customAgent);
        expect(result).toBe(`${DEFAULT_USER_AGENT} ${customAgent}`);
      });

      it('should include DEFAULT_USER_AGENT as prefix', () => {
        const customAgent = 'TestAgent/2.0';
        const result = buildUserAgent(customAgent);
        expect(result.startsWith(DEFAULT_USER_AGENT)).toBe(true);
      });

      it('should include custom agent at the end', () => {
        const customAgent = 'TestAgent/2.0';
        const result = buildUserAgent(customAgent);
        expect(result.endsWith(customAgent)).toBe(true);
      });

      it('should handle simple custom agent strings', () => {
        const customAgent = 'SimpleAgent';
        const result = buildUserAgent(customAgent);
        expect(result).toBe(`${DEFAULT_USER_AGENT} ${customAgent}`);
      });

      it('should handle custom agent with version', () => {
        const customAgent = 'CustomApp/3.2.1';
        const result = buildUserAgent(customAgent);
        expect(result).toBe(`${DEFAULT_USER_AGENT} ${customAgent}`);
      });

      it('should handle custom agent with complex version', () => {
        const customAgent = 'EnterpriseApp/1.0.0-beta.1';
        const result = buildUserAgent(customAgent);
        expect(result).toBe(`${DEFAULT_USER_AGENT} ${customAgent}`);
      });

      it('should handle custom agent with platform info', () => {
        const customAgent = 'MyApp/1.0.0 (Windows; x64)';
        const result = buildUserAgent(customAgent);
        expect(result).toBe(`${DEFAULT_USER_AGENT} ${customAgent}`);
      });

      it('should handle custom agent with multiple components', () => {
        const customAgent = 'MyApp/1.0.0 MyLib/2.0.0 Platform/Linux';
        const result = buildUserAgent(customAgent);
        expect(result).toBe(`${DEFAULT_USER_AGENT} ${customAgent}`);
      });
    });

    describe('Edge Cases - Empty and Whitespace Strings', () => {
      it('should return DEFAULT_USER_AGENT for empty string', () => {
        const result = buildUserAgent('');
        expect(result).toBe(DEFAULT_USER_AGENT);
      });

      it('should NOT return DEFAULT_USER_AGENT for whitespace-only string (truthy check)', () => {
        // A string with spaces is truthy, so it will be appended
        const result = buildUserAgent('   ');
        expect(result).toBe(`${DEFAULT_USER_AGENT}    `);
      });

      it('should handle single space custom agent', () => {
        const result = buildUserAgent(' ');
        expect(result).toBe(`${DEFAULT_USER_AGENT}  `);
      });

      it('should handle custom agent with leading whitespace', () => {
        const customAgent = '  LeadingSpace/1.0';
        const result = buildUserAgent(customAgent);
        expect(result).toBe(`${DEFAULT_USER_AGENT} ${customAgent}`);
      });

      it('should handle custom agent with trailing whitespace', () => {
        const customAgent = 'TrailingSpace/1.0  ';
        const result = buildUserAgent(customAgent);
        expect(result).toBe(`${DEFAULT_USER_AGENT} ${customAgent}`);
      });
    });

    describe('Edge Cases - Special Characters', () => {
      it('should handle custom agent with special characters', () => {
        const customAgent = 'App_Name-v1.0+build.123';
        const result = buildUserAgent(customAgent);
        expect(result).toBe(`${DEFAULT_USER_AGENT} ${customAgent}`);
      });

      it('should handle custom agent with parentheses', () => {
        const customAgent = 'MyApp/1.0 (Linux; Ubuntu 22.04)';
        const result = buildUserAgent(customAgent);
        expect(result).toBe(`${DEFAULT_USER_AGENT} ${customAgent}`);
      });

      it('should handle custom agent with semicolons', () => {
        const customAgent = 'Agent/1.0; Component/2.0';
        const result = buildUserAgent(customAgent);
        expect(result).toBe(`${DEFAULT_USER_AGENT} ${customAgent}`);
      });

      it('should handle custom agent with unicode characters', () => {
        const customAgent = 'MyApp/1.0 (Japanese; UTF-8)';
        const result = buildUserAgent(customAgent);
        expect(result).toBe(`${DEFAULT_USER_AGENT} ${customAgent}`);
      });

      it('should handle custom agent with slashes', () => {
        const customAgent = 'Org/Team/App/1.0.0';
        const result = buildUserAgent(customAgent);
        expect(result).toBe(`${DEFAULT_USER_AGENT} ${customAgent}`);
      });
    });

    describe('Edge Cases - Long Strings', () => {
      it('should handle very long custom agent strings', () => {
        const customAgent = 'A'.repeat(1000);
        const result = buildUserAgent(customAgent);
        expect(result).toBe(`${DEFAULT_USER_AGENT} ${customAgent}`);
        expect(result.length).toBe(DEFAULT_USER_AGENT.length + 1 + 1000);
      });

      it('should handle moderately long realistic custom agent', () => {
        const customAgent =
          'EnterpriseApplication/15.2.3 (Windows NT 10.0; Win64; x64) Integration/4.1.0 Module/12.0.0-rc.1';
        const result = buildUserAgent(customAgent);
        expect(result).toBe(`${DEFAULT_USER_AGENT} ${customAgent}`);
      });
    });

    describe('Edge Cases - Numeric Strings', () => {
      it('should handle numeric-only custom agent', () => {
        const customAgent = '12345';
        const result = buildUserAgent(customAgent);
        expect(result).toBe(`${DEFAULT_USER_AGENT} ${customAgent}`);
      });

      it('should handle version-like numeric string', () => {
        const customAgent = '1.0.0';
        const result = buildUserAgent(customAgent);
        expect(result).toBe(`${DEFAULT_USER_AGENT} ${customAgent}`);
      });
    });

    describe('Return Type Validation', () => {
      it('should always return a string type without custom agent', () => {
        expect(typeof buildUserAgent()).toBe('string');
        expect(typeof buildUserAgent(undefined)).toBe('string');
      });

      it('should always return a string type with custom agent', () => {
        expect(typeof buildUserAgent('custom')).toBe('string');
        expect(typeof buildUserAgent('App/1.0')).toBe('string');
      });

      it('should return primitive string, not String object', () => {
        const result = buildUserAgent('test');
        expect(result).not.toBeInstanceOf(String);
        expect(Object.prototype.toString.call(result)).toBe('[object String]');
      });
    });

    describe('Immutability Verification', () => {
      it('should not modify DEFAULT_USER_AGENT constant when custom agent is provided', () => {
        const originalDefault = DEFAULT_USER_AGENT;
        buildUserAgent('CustomApp/1.0');
        expect(DEFAULT_USER_AGENT).toBe(originalDefault);
      });

      it('should not modify SDK_VERSION constant', () => {
        const originalVersion = SDK_VERSION;
        buildUserAgent('CustomApp/1.0');
        expect(SDK_VERSION).toBe(originalVersion);
      });

      it('should not modify SDK_NAME constant', () => {
        const originalName = SDK_NAME;
        buildUserAgent('CustomApp/1.0');
        expect(SDK_NAME).toBe(originalName);
      });
    });

    describe('Concurrent Calls', () => {
      it('should handle multiple concurrent calls correctly', async () => {
        const customAgents = [
          'App1/1.0',
          'App2/2.0',
          'App3/3.0',
          undefined,
          'App4/4.0',
          '',
        ];

        const promises = customAgents.map((agent) =>
          Promise.resolve(buildUserAgent(agent))
        );

        const results = await Promise.all(promises);

        expect(results[0]).toBe(`${DEFAULT_USER_AGENT} App1/1.0`);
        expect(results[1]).toBe(`${DEFAULT_USER_AGENT} App2/2.0`);
        expect(results[2]).toBe(`${DEFAULT_USER_AGENT} App3/3.0`);
        expect(results[3]).toBe(DEFAULT_USER_AGENT);
        expect(results[4]).toBe(`${DEFAULT_USER_AGENT} App4/4.0`);
        expect(results[5]).toBe(DEFAULT_USER_AGENT);
      });

      it('should produce consistent results for same input across many calls', () => {
        const customAgent = 'TestApp/1.0.0';
        const expected = `${DEFAULT_USER_AGENT} ${customAgent}`;

        for (let i = 0; i < 100; i++) {
          expect(buildUserAgent(customAgent)).toBe(expected);
        }
      });
    });
  });

  describe('Integration - Constants and Function', () => {
    it('should have consistent relationship between constants and function output', () => {
      const result = buildUserAgent();
      expect(result).toContain(SDK_NAME);
      expect(result).toContain(SDK_VERSION);
      expect(result).toBe(DEFAULT_USER_AGENT);
    });

    it('should maintain SDK name/version order in all outputs', () => {
      const result = buildUserAgent('custom');
      const nameIndex = result.indexOf(SDK_NAME);
      const versionIndex = result.indexOf(SDK_VERSION);
      expect(nameIndex).toBeLessThan(versionIndex);
    });

    it('should place custom agent after Node.js version info', () => {
      const customAgent = 'CustomApp/1.0';
      const result = buildUserAgent(customAgent);
      const nodeJsIndex = result.indexOf('Node.js');
      const customIndex = result.indexOf(customAgent);
      expect(nodeJsIndex).toBeLessThan(customIndex);
    });
  });
});
