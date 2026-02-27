/**
 * Tests for limits-service.ts - System limits management
 * @file tests/unit/internal/services/limits-service.test.ts
 */

import { describe, it, expect, vi, beforeEach, afterEach, type Mock } from 'vitest';
import type { AxiosInstance } from 'axios';
import type { SystemLimits } from '../../../../src/types/index.js';

// Use vi.hoisted for mock functions
const { mockAxiosCreate, mockConfigureRetryInterceptor } = vi.hoisted(() => ({
  mockAxiosCreate: vi.fn(),
  mockConfigureRetryInterceptor: vi.fn(),
}));

// Mock axios
vi.mock('axios', () => ({
  default: {
    create: mockAxiosCreate,
  },
}));

// Mock http-client
vi.mock('../../../../src/internal/config/http-client.js', () => ({
  createAxiosConfig: vi.fn().mockReturnValue({
    baseURL: 'https://api.example.com',
    timeout: 60000,
    headers: {
      'Content-Type': 'application/json',
    },
  }),
  configureRetryInterceptor: mockConfigureRetryInterceptor,
  DEFAULT_TIMEOUT_CONFIG: {
    apiTimeout: 60000,
    uploadTimeout: 120000,
    downloadTimeout: 30000,
    requestTimeout: 30000,
    maxSockets: 50,
    keepAlive: true,
  },
}));

import { LimitsManager } from '../../../../src/internal/services/limits-service.js';

// Helper to create mock axios instance
function createMockAxiosInstance(): AxiosInstance {
  return {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
    patch: vi.fn(),
    request: vi.fn(),
    head: vi.fn(),
    options: vi.fn(),
    defaults: {},
    interceptors: {
      request: { use: vi.fn(), eject: vi.fn(), clear: vi.fn() },
      response: { use: vi.fn(), eject: vi.fn(), clear: vi.fn() },
    },
  } as unknown as AxiosInstance;
}

describe('LimitsManager', () => {
  let mockAxios: AxiosInstance;

  beforeEach(() => {
    vi.clearAllMocks();
    mockAxios = createMockAxiosInstance();
    mockAxiosCreate.mockReturnValue(mockAxios);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('constructor', () => {
    it('should create axios instance with base URL', () => {
      new LimitsManager('https://api.example.com');

      expect(mockAxiosCreate).toHaveBeenCalled();
      expect(mockConfigureRetryInterceptor).toHaveBeenCalled();
    });

    it('should accept custom timeout config', () => {
      new LimitsManager('https://api.example.com', {
        apiTimeout: 30000,
        uploadTimeout: 60000,
      });

      expect(mockAxiosCreate).toHaveBeenCalled();
    });

    it('should accept custom retry config', () => {
      new LimitsManager('https://api.example.com', undefined, {
        maxRetries: 5,
        baseDelay: 2000,
      });

      expect(mockConfigureRetryInterceptor).toHaveBeenCalledWith(
        mockAxios,
        expect.objectContaining({ maxRetries: 5, baseDelay: 2000 })
      );
    });
  });

  describe('getLimits', () => {
    it('should fetch limits from API', async () => {
      const apiLimits: SystemLimits = {
        maxFileSize: 100 * 1024 * 1024,
        maxFilesPerCapsa: 1000,
        maxTotalSize: 1024 * 1024 * 1024,
      };

      (mockAxios.get as Mock).mockResolvedValue({ data: apiLimits });

      const manager = new LimitsManager('https://api.example.com');
      const limits = await manager.getLimits();

      expect(limits).toEqual(apiLimits);
      expect(mockAxios.get).toHaveBeenCalledWith('/api/limits');
    });

    it('should cache limits after fetching', async () => {
      const apiLimits: SystemLimits = {
        maxFileSize: 100 * 1024 * 1024,
        maxFilesPerCapsa: 1000,
        maxTotalSize: 1024 * 1024 * 1024,
      };

      (mockAxios.get as Mock).mockResolvedValue({ data: apiLimits });

      const manager = new LimitsManager('https://api.example.com');

      // First call fetches from API
      const limits1 = await manager.getLimits();
      // Second call should use cache
      const limits2 = await manager.getLimits();

      expect(limits1).toEqual(apiLimits);
      expect(limits2).toEqual(apiLimits);
      expect(mockAxios.get).toHaveBeenCalledTimes(1);
    });

    it('should return fallback limits on API error', async () => {
      (mockAxios.get as Mock).mockRejectedValue(new Error('Network error'));

      const manager = new LimitsManager('https://api.example.com');
      const limits = await manager.getLimits();

      expect(limits).toEqual({
        maxFileSize: 50 * 1024 * 1024,
        maxFilesPerCapsa: 500,
        maxTotalSize: 500 * 1024 * 1024,
      });
    });

    it('should refresh cache after TTL expires', async () => {
      vi.useFakeTimers();

      const apiLimits1: SystemLimits = {
        maxFileSize: 100 * 1024 * 1024,
        maxFilesPerCapsa: 1000,
        maxTotalSize: 1024 * 1024 * 1024,
      };

      const apiLimits2: SystemLimits = {
        maxFileSize: 200 * 1024 * 1024,
        maxFilesPerCapsa: 2000,
        maxTotalSize: 2 * 1024 * 1024 * 1024,
      };

      (mockAxios.get as Mock)
        .mockResolvedValueOnce({ data: apiLimits1 })
        .mockResolvedValueOnce({ data: apiLimits2 });

      const manager = new LimitsManager('https://api.example.com');

      // First call
      const limits1 = await manager.getLimits();
      expect(limits1).toEqual(apiLimits1);

      // Advance time past cache TTL (7 days + 1 second)
      vi.advanceTimersByTime(7 * 24 * 60 * 60 * 1000 + 1000);

      // Second call should fetch fresh limits
      const limits2 = await manager.getLimits();
      expect(limits2).toEqual(apiLimits2);
      expect(mockAxios.get).toHaveBeenCalledTimes(2);
    });

    it('should use cache within TTL', async () => {
      vi.useFakeTimers();

      const apiLimits: SystemLimits = {
        maxFileSize: 100 * 1024 * 1024,
        maxFilesPerCapsa: 1000,
        maxTotalSize: 1024 * 1024 * 1024,
      };

      (mockAxios.get as Mock).mockResolvedValue({ data: apiLimits });

      const manager = new LimitsManager('https://api.example.com');

      // First call
      await manager.getLimits();

      // Advance time but stay within TTL (6 days)
      vi.advanceTimersByTime(6 * 24 * 60 * 60 * 1000);

      // Second call should use cache
      await manager.getLimits();
      expect(mockAxios.get).toHaveBeenCalledTimes(1);
    });
  });

  describe('clearCache', () => {
    it('should clear the limits cache', async () => {
      const apiLimits: SystemLimits = {
        maxFileSize: 100 * 1024 * 1024,
        maxFilesPerCapsa: 1000,
        maxTotalSize: 1024 * 1024 * 1024,
      };

      (mockAxios.get as Mock).mockResolvedValue({ data: apiLimits });

      const manager = new LimitsManager('https://api.example.com');

      // First call
      await manager.getLimits();
      expect(mockAxios.get).toHaveBeenCalledTimes(1);

      // Clear cache
      manager.clearCache();

      // Next call should fetch from API again
      await manager.getLimits();
      expect(mockAxios.get).toHaveBeenCalledTimes(2);
    });
  });

  describe('getFallbackLimits', () => {
    it('should return fallback limits', () => {
      const fallback = LimitsManager.getFallbackLimits();

      expect(fallback).toEqual({
        maxFileSize: 50 * 1024 * 1024,
        maxFilesPerCapsa: 500,
        maxTotalSize: 500 * 1024 * 1024,
      });
    });

    it('should return a copy of fallback limits', () => {
      const fallback1 = LimitsManager.getFallbackLimits();
      const fallback2 = LimitsManager.getFallbackLimits();

      expect(fallback1).not.toBe(fallback2);
      expect(fallback1).toEqual(fallback2);
    });

    it('should not allow modification of internal fallback', () => {
      const fallback = LimitsManager.getFallbackLimits();
      fallback.maxFileSize = 0;

      const freshFallback = LimitsManager.getFallbackLimits();
      expect(freshFallback.maxFileSize).toBe(50 * 1024 * 1024);
    });
  });
});
