/// <reference types="vitest/globals" />
/**
 * Golden Unit Tests - Audit Operations
 * Tests log missing details error (client-side), processed action,
 * API error mapping.
 */

import { AuditService } from '../../src/internal/services/audit-service.js';
import { CapsaraAuditError } from '../../src/errors/audit-error.js';
import type { AxiosInstance } from 'axios';

function createMockAxios(): AxiosInstance {
  return {
    get: vi.fn(),
    post: vi.fn(),
    interceptors: {
      request: { use: vi.fn() },
      response: { use: vi.fn() },
    },
  } as unknown as AxiosInstance;
}

describe('Golden: Audit', () => {
  let service: AuditService;
  let mockHttp: AxiosInstance;

  beforeEach(() => {
    vi.clearAllMocks();
    mockHttp = createMockAxios();
    service = new AuditService({ axiosInstance: mockHttp });
  });

  it('should throw MISSING_DETAILS error when log action has no details (client-side validation)', async () => {
    await expect(
      service.createAuditEntry('capsa_1', { action: 'log' })
    ).rejects.toThrow(CapsaraAuditError);

    await expect(
      service.createAuditEntry('capsa_1', { action: 'log' })
    ).rejects.toThrow(/Details field is required/);

    // Empty details object should also fail
    await expect(
      service.createAuditEntry('capsa_1', { action: 'log', details: {} })
    ).rejects.toThrow(/Details field is required/);

    // HTTP should not be called for client-side validation errors
    expect(mockHttp.post).not.toHaveBeenCalled();
  });

  it('should allow processed action without details', async () => {
    (mockHttp.post as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      data: { success: true },
    });

    const result = await service.createAuditEntry('capsa_1', { action: 'processed' });

    expect(result.success).toBe(true);
    expect(mockHttp.post).toHaveBeenCalledWith(
      '/api/capsas/capsa_1/audit',
      { action: 'processed' }
    );
  });

  it('should map API error codes to CapsaraAuditError', async () => {
    const apiError = {
      response: {
        status: 403,
        data: {
          error: {
            code: 'ACCESS_DENIED',
            message: 'You do not have access',
          },
        },
      },
    };
    (mockHttp.get as ReturnType<typeof vi.fn>).mockRejectedValueOnce(apiError);

    await expect(
      service.getAuditEntries('capsa_1')
    ).rejects.toThrow(CapsaraAuditError);

    try {
      await service.getAuditEntries('capsa_1');
    } catch (error) {
      // Second call for inspection
      (mockHttp.get as ReturnType<typeof vi.fn>).mockRejectedValueOnce(apiError);
      try {
        await service.getAuditEntries('capsa_1');
      } catch (err) {
        const auditErr = err as CapsaraAuditError;
        expect(auditErr.code).toBe('ACCESS_DENIED');
        expect(auditErr.statusCode).toBe(403);
      }
    }
  });

  it('should return audit entries with pagination', async () => {
    const mockResponse = {
      auditEntries: [
        { timestamp: '2025-01-01T00:00:00Z', party: 'party_1', action: 'created' },
        { timestamp: '2025-01-02T00:00:00Z', party: 'party_2', action: 'accessed' },
      ],
      pagination: { limit: 20, hasMore: false },
    };
    (mockHttp.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ data: mockResponse });

    const result = await service.getAuditEntries('capsa_1');

    expect(result.auditEntries).toHaveLength(2);
    expect(result.pagination.hasMore).toBe(false);
  });
});
