/**
 * Tests for audit-service.ts - Audit trail service
 * @file tests/unit/internal/services/audit-service.test.ts
 */

import { describe, it, expect, vi, beforeEach, type Mock } from 'vitest';
import type { AxiosInstance } from 'axios';
import type {
  GetAuditEntriesFilters,
  GetAuditEntriesResponse,
  CreateAuditEntryRequest,
  CreateAuditEntryResponse,
} from '../../../../src/types/index.js';
import { CapsaraAuditError } from '../../../../src/errors/audit-error.js';

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

import { AuditService, type AuditServiceOptions } from '../../../../src/internal/services/audit-service.js';

describe('AuditService', () => {
  let mockAxios: AxiosInstance;
  let service: AuditService;

  beforeEach(() => {
    vi.clearAllMocks();
    mockAxios = createMockAxiosInstance();
    const options: AuditServiceOptions = {
      axiosInstance: mockAxios,
    };
    service = new AuditService(options);
  });

  describe('constructor', () => {
    it('should create service with axios instance', () => {
      const options: AuditServiceOptions = {
        axiosInstance: mockAxios,
      };
      const svc = new AuditService(options);
      expect(svc).toBeInstanceOf(AuditService);
    });
  });

  describe('getAuditEntries', () => {
    const allNull = { page: null, limit: null, total: null, totalPages: null };

    it('returns null for pagination fields the server omits or nulls, with no invented defaults', async () => {
      (mockAxios.get as Mock).mockResolvedValue({ data: { auditEntries: [], pagination: { page: 2, total: null } } });

      const result = await service.getAuditEntries('capsa_123');

      expect(result.pagination).toStrictEqual({ page: 2, limit: null, total: null, totalPages: null });
    });

    it.each([
      ['missing', { auditEntries: [] }],
      ['null', { auditEntries: [], pagination: null }],
      ['not an object', { auditEntries: [], pagination: 'page 1' }],
      ['an array', { auditEntries: [], pagination: [1] }],
    ])('returns a pagination object with every field null when it is %s', async (_label, body) => {
      (mockAxios.get as Mock).mockResolvedValue({ data: body });

      const result = await service.getAuditEntries('capsa_123');

      expect(result.pagination).toStrictEqual(allNull);
      expect(result.auditEntries).toEqual([]);
    });

    it('keeps zero values and extra pagination fields as sent', async () => {
      (mockAxios.get as Mock).mockResolvedValue({
        data: { auditEntries: [], pagination: { page: 0, limit: 0, total: 0, totalPages: 0, cursor: 'x' } },
      });

      const result = await service.getAuditEntries('capsa_123');

      expect(result.pagination).toStrictEqual({ page: 0, limit: 0, total: 0, totalPages: 0, cursor: 'x' });
    });

    it('returns a non-object 2xx body as it is', async () => {
      (mockAxios.get as Mock).mockResolvedValue({ data: 'not json' });

      await expect(service.getAuditEntries('capsa_123')).resolves.toBe('not json');
    });

    it('should fetch audit entries without filters', async () => {
      const response: GetAuditEntriesResponse = {
        auditEntries: [
          {
            action: 'created',
            timestamp: '2024-01-15T10:30:00Z',
            party: 'party_123',
          },
          {
            action: 'accessed',
            timestamp: '2024-01-15T11:00:00Z',
            party: 'party_456',
          },
        ],
        pagination: { page: 1, limit: 100, total: 2, totalPages: 1 },
      };

      (mockAxios.get as Mock).mockResolvedValue({ data: response });

      const result = await service.getAuditEntries('capsa_123');

      expect(result).toEqual(response);
      expect(mockAxios.get).toHaveBeenCalledWith('/api/capsas/capsa_123/audit', {
        params: undefined,
      });
    });

    it('should fetch audit entries with filters', async () => {
      const filters: GetAuditEntriesFilters = {
        action: 'accessed',
        party: 'party_123',
        limit: 10,
      };

      const response: GetAuditEntriesResponse = {
        auditEntries: [
          {
            action: 'accessed',
            timestamp: '2024-01-15T10:30:00Z',
            party: 'party_123',
          },
        ],
        pagination: { page: 1, limit: 10, total: 1, totalPages: 1 },
      };

      (mockAxios.get as Mock).mockResolvedValue({ data: response });

      const result = await service.getAuditEntries('capsa_123', filters);

      expect(result).toEqual(response);
      expect(mockAxios.get).toHaveBeenCalledWith('/api/capsas/capsa_123/audit', {
        params: filters,
      });
    });

    it('should pass page and limit filters as query params', async () => {
      const filters: GetAuditEntriesFilters = {
        page: 2,
        limit: 50,
      };

      const response: GetAuditEntriesResponse = {
        auditEntries: [],
        pagination: { page: 2, limit: 50, total: 0, totalPages: 0 },
      };

      (mockAxios.get as Mock).mockResolvedValue({ data: response });

      const result = await service.getAuditEntries('capsa_123', filters);

      expect(result).toEqual(response);
      expect(mockAxios.get).toHaveBeenCalledWith('/api/capsas/capsa_123/audit', {
        params: filters,
      });
    });

    it('should return page-based pagination from the API response', async () => {
      (mockAxios.get as Mock).mockResolvedValue({
        data: {
          auditEntries: [
            { timestamp: '2024-01-15T10:30:00Z', party: 'party_123', action: 'accessed' },
            { timestamp: '2024-01-15T10:00:00Z', party: 'party_123', action: 'created' },
          ],
          pagination: { page: 2, limit: 2, total: 5, totalPages: 3 },
        },
      });

      const result = await service.getAuditEntries('capsa_123', { page: 2, limit: 2 });

      expect(result.auditEntries).toHaveLength(2);
      expect(result.pagination.page).toBe(2);
      expect(result.pagination.limit).toBe(2);
      expect(result.pagination.total).toBe(5);
      expect(result.pagination.totalPages).toBe(3);
    });

    it('should return empty pagination when there are no entries', async () => {
      (mockAxios.get as Mock).mockResolvedValue({
        data: {
          auditEntries: [],
          pagination: { page: 1, limit: 100, total: 0, totalPages: 0 },
        },
      });

      const result = await service.getAuditEntries('capsa_123');

      expect(result.auditEntries).toEqual([]);
      expect(result.pagination).toEqual({ page: 1, limit: 100, total: 0, totalPages: 0 });
    });

    it('should throw CapsaraAuditError on API error', async () => {
      const axiosError = {
        response: {
          status: 404,
          data: { error: { code: 'ENVELOPE_NOT_FOUND', message: 'Envelope not found' } },
        },
        isAxiosError: true,
      };

      (mockAxios.get as Mock).mockRejectedValue(axiosError);

      await expect(service.getAuditEntries('nonexistent_capsa')).rejects.toThrow();
    });

    it('should throw CapsaraAuditError on network error', async () => {
      (mockAxios.get as Mock).mockRejectedValue(new Error('Network error'));

      await expect(service.getAuditEntries('capsa_123')).rejects.toThrow();
    });
  });

  describe('createAuditEntry', () => {
    it('should create audit entry for processed action', async () => {
      const entry: CreateAuditEntryRequest = {
        action: 'processed',
      };

      const response: CreateAuditEntryResponse = {
        success: true,
      };

      (mockAxios.post as Mock).mockResolvedValue({ data: response });

      const result = await service.createAuditEntry('capsa_123', entry);

      expect(result).toEqual(response);
      expect(mockAxios.post).toHaveBeenCalledWith('/api/capsas/capsa_123/audit', entry);
    });

    it('should create processed entry with details', async () => {
      const entry: CreateAuditEntryRequest = {
        action: 'processed',
        details: {
          fileId: 'file_001',
        },
      };

      const response: CreateAuditEntryResponse = {
        success: true,
      };

      (mockAxios.post as Mock).mockResolvedValue({ data: response });

      const result = await service.createAuditEntry('capsa_123', entry);

      expect(result).toEqual(response);
      expect(mockAxios.post).toHaveBeenCalledWith('/api/capsas/capsa_123/audit', entry);
    });

    it('should create log entry with details', async () => {
      const entry: CreateAuditEntryRequest = {
        action: 'log',
        details: {
          message: 'Custom log message',
          customField: 'value',
        },
      };

      const response: CreateAuditEntryResponse = {
        success: true,
      };

      (mockAxios.post as Mock).mockResolvedValue({ data: response });

      const result = await service.createAuditEntry('capsa_123', entry);

      expect(result).toEqual(response);
      expect(mockAxios.post).toHaveBeenCalledWith('/api/capsas/capsa_123/audit', entry);
    });

    it('should throw error for log action without details', async () => {
      const entry: CreateAuditEntryRequest = {
        action: 'log',
      };

      await expect(service.createAuditEntry('capsa_123', entry)).rejects.toThrow(CapsaraAuditError);
      expect(mockAxios.post).not.toHaveBeenCalled();
    });

    it('should throw error for log action with empty details', async () => {
      const entry: CreateAuditEntryRequest = {
        action: 'log',
        details: {},
      };

      await expect(service.createAuditEntry('capsa_123', entry)).rejects.toThrow(CapsaraAuditError);
      expect(mockAxios.post).not.toHaveBeenCalled();
    });

    it('should throw CapsaraAuditError on API error', async () => {
      const entry: CreateAuditEntryRequest = {
        action: 'processed',
      };

      const axiosError = {
        response: {
          status: 403,
          data: { error: { code: 'ACCESS_DENIED', message: 'Not authorized' } },
        },
        isAxiosError: true,
      };

      (mockAxios.post as Mock).mockRejectedValue(axiosError);

      await expect(service.createAuditEntry('capsa_123', entry)).rejects.toThrow();
    });
  });
});
