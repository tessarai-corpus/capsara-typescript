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
    it('should fetch audit entries without filters', async () => {
      const response: GetAuditEntriesResponse = {
        entries: [
          {
            id: 'audit_001',
            action: 'created',
            timestamp: '2024-01-15T10:30:00Z',
            partyId: 'party_123',
          },
          {
            id: 'audit_002',
            action: 'accessed',
            timestamp: '2024-01-15T11:00:00Z',
            partyId: 'party_456',
          },
        ],
        hasMore: false,
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
        partyId: 'party_123',
        limit: 10,
      };

      const response: GetAuditEntriesResponse = {
        entries: [
          {
            id: 'audit_001',
            action: 'accessed',
            timestamp: '2024-01-15T10:30:00Z',
            partyId: 'party_123',
          },
        ],
        hasMore: false,
      };

      (mockAxios.get as Mock).mockResolvedValue({ data: response });

      const result = await service.getAuditEntries('capsa_123', filters);

      expect(result).toEqual(response);
      expect(mockAxios.get).toHaveBeenCalledWith('/api/capsas/capsa_123/audit', {
        params: filters,
      });
    });

    it('should handle pagination with cursor', async () => {
      const filters: GetAuditEntriesFilters = {
        cursor: 'cursor_abc123',
        limit: 50,
      };

      const response: GetAuditEntriesResponse = {
        entries: [],
        hasMore: false,
        nextCursor: undefined,
      };

      (mockAxios.get as Mock).mockResolvedValue({ data: response });

      const result = await service.getAuditEntries('capsa_123', filters);

      expect(result).toEqual(response);
      expect(mockAxios.get).toHaveBeenCalledWith('/api/capsas/capsa_123/audit', {
        params: filters,
      });
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
    it('should create audit entry for accessed action', async () => {
      const entry: CreateAuditEntryRequest = {
        action: 'accessed',
      };

      const response: CreateAuditEntryResponse = {
        success: true,
        message: 'Audit entry created',
      };

      (mockAxios.post as Mock).mockResolvedValue({ data: response });

      const result = await service.createAuditEntry('capsa_123', entry);

      expect(result).toEqual(response);
      expect(mockAxios.post).toHaveBeenCalledWith('/api/capsas/capsa_123/audit', entry);
    });

    it('should create audit entry for downloaded action', async () => {
      const entry: CreateAuditEntryRequest = {
        action: 'downloaded',
        details: {
          fileId: 'file_001',
        },
      };

      const response: CreateAuditEntryResponse = {
        success: true,
        message: 'Audit entry created',
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
        message: 'Audit entry created',
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
        action: 'accessed',
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
