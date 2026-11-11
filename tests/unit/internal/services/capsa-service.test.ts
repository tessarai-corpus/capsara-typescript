/**
 * Tests for capsa-service.ts - Capsa CRUD operations
 * @file tests/unit/internal/services/capsa-service.test.ts
 */

import { describe, it, expect, vi, beforeEach, type Mock } from 'vitest';
import type { AxiosInstance } from 'axios';
import type { Capsa, CapsaListResponse, CapsaSummary } from '../../../../src/types/index.js';
import type { DecryptedCapsa } from '../../../../src/internal/decryptor/capsa-decryptor.js';
import { CapsaraCapsaError } from '../../../../src/errors/capsa-error.js';

const { mockDecryptCapsa } = vi.hoisted(() => ({
  mockDecryptCapsa: vi.fn(),
}));

vi.mock('../../../../src/internal/decryptor/capsa-decryptor.js', () => ({
  decryptCapsa: mockDecryptCapsa,
}));

import { CapsaService } from '../../../../src/internal/services/capsa-service.js';

function createMockAxiosInstance(): AxiosInstance {
  return {
    get: vi.fn(),
    post: vi.fn(),
    delete: vi.fn(),
  } as unknown as AxiosInstance;
}

function createSampleCapsa(overrides?: Partial<Capsa>): Capsa {
  return {
    id: 'capsa_123',
    creator: 'party_creator',
    creatorPublicKey: '-----BEGIN PUBLIC KEY-----\nCreatorKey\n-----END PUBLIC KEY-----\n',
    status: 'active',
    createdAt: '2024-01-15T10:30:00Z',
    updatedAt: '2024-01-15T10:30:00Z',
    keychain: {
      algorithm: 'AES-256-GCM',
      keys: [
        {
          party: 'party_recipient',
          encryptedKey: 'encrypted-master-key-for-recipient',
          iv: 'iv',
          fingerprint: 'fp',
          permissions: ['read'],
        },
      ],
    },
    files: [],
    signature: { algorithm: 'RS256', protected: 'p', payload: 'q', signature: 's' },
    accessControl: { expiresAt: '2025-01-15T10:30:00Z' },
    totalSize: 0,
    ...overrides,
  };
}

function summary(id: string): CapsaSummary {
  return { id, createdAt: '2024-01-15T10:30:00Z', creator: 'party_creator', status: 'active' };
}

function apiError(status: number, code: string, message: string, details?: unknown) {
  return { response: { status, data: { error: { code, message, ...(details !== undefined && { details }) } } } };
}

const PRIVATE_KEY = '-----BEGIN PRIVATE KEY-----\nPrivateKey\n-----END PRIVATE KEY-----';

describe('CapsaService', () => {
  let mockAxios: AxiosInstance;
  let service: CapsaService;

  beforeEach(() => {
    vi.clearAllMocks();
    mockAxios = createMockAxiosInstance();
    service = new CapsaService({ axiosInstance: mockAxios });
  });

  describe('getCapsa', () => {
    it('should fetch capsa by ID', async () => {
      const capsa = createSampleCapsa();
      (mockAxios.get as Mock).mockResolvedValue({ data: capsa });

      const result = await service.getCapsa('capsa_123');

      expect(result).toEqual(capsa);
      expect(mockAxios.get).toHaveBeenCalledWith('/api/capsas/capsa_123');
    });

    it('should expose 404 ENVELOPE_NOT_FOUND verbatim', async () => {
      (mockAxios.get as Mock).mockRejectedValue(apiError(404, 'ENVELOPE_NOT_FOUND', 'Envelope not found'));

      await expect(service.getCapsa('nonexistent')).rejects.toMatchObject({
        name: 'CapsaraCapsaError',
        code: 'ENVELOPE_NOT_FOUND',
        statusCode: 404,
        message: 'Envelope not found',
      });
    });

    it('should surface 410 ENVELOPE_EXPIRED with its details', async () => {
      const details = { status: 'expired', expiredAt: '2026-01-01T00:00:00.000Z' };
      (mockAxios.get as Mock).mockRejectedValue(apiError(410, 'ENVELOPE_EXPIRED', 'Capsa has expired', details));

      const error = await service.getCapsa('capsa_old').catch((e: unknown) => e);

      expect(error).toBeInstanceOf(CapsaraCapsaError);
      expect(error).toMatchObject({ code: 'ENVELOPE_EXPIRED', statusCode: 410, details });
    });

    it('should surface 410 ENVELOPE_DELETED with its details', async () => {
      const details = { status: 'soft_deleted', deletedAt: '2026-02-01T00:00:00.000Z' };
      (mockAxios.get as Mock).mockRejectedValue(apiError(410, 'ENVELOPE_DELETED', 'Capsa was deleted', details));

      await expect(service.getCapsa('capsa_gone')).rejects.toMatchObject({
        code: 'ENVELOPE_DELETED',
        statusCode: 410,
        details,
      });
    });

    it('should expose retryAfter on 429', async () => {
      (mockAxios.get as Mock).mockRejectedValue({
        response: { status: 429, headers: { 'retry-after': '30' }, data: { error: { code: 'TOO_MANY_FAILURES', message: 'Slow down' } } },
      });

      await expect(service.getCapsa('capsa_123')).rejects.toMatchObject({ code: 'TOO_MANY_FAILURES', retryAfter: 30 });
    });

    it.each([
      ['HTML text', '<html>gateway</html>'],
      ['an empty body', ''],
      ['JSON null', null],
      ['an array', [createSampleCapsa()]],
      ['a number', 1],
    ])('throws INVALID_RESPONSE for a 2xx body that is %s', async (_label, body) => {
      (mockAxios.get as Mock).mockResolvedValue({ status: 200, data: body });

      const error = await service.getCapsa('capsa_123').catch((e: unknown) => e);

      expect(error).toBeInstanceOf(CapsaraCapsaError);
      expect(error).toMatchObject({ code: 'INVALID_RESPONSE', statusCode: 0, details: { capsaId: 'capsa_123' } });
    });

    it('passes the raw status through on a capsa and on list items', async () => {
      (mockAxios.get as Mock).mockResolvedValueOnce({ data: createSampleCapsa({ status: 'archived' }) });
      (mockAxios.get as Mock).mockResolvedValueOnce({
        data: {
          capsas: [
            { id: 'a', createdAt: 'x', creator: 'c', status: 'soft_deleted' },
            { id: 'b', createdAt: 'x', creator: 'c', status: 'archived' },
            { id: 'c', createdAt: 'x', creator: 'c' },
          ],
          pagination: { limit: 20, hasMore: false },
        },
      });

      expect((await service.getCapsa('capsa_123')).status).toBe('archived');
      const list = await service.listCapsas();
      expect(list.capsas.map(c => c.status)).toEqual(['soft_deleted', 'archived', undefined]);
    });

    it('does not decrypt a 2xx body that is not an object', async () => {
      (mockAxios.get as Mock).mockResolvedValue({ status: 200, data: null });

      await expect(service.getDecryptedCapsa('capsa_123', PRIVATE_KEY)).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
      expect(mockDecryptCapsa).not.toHaveBeenCalled();
    });
  });

  describe('getDecryptedCapsa', () => {
    it('should fetch the capsa and decrypt it without any party key lookup', async () => {
      const capsa = createSampleCapsa();
      const decrypted = { id: capsa.id } as DecryptedCapsa;
      (mockAxios.get as Mock).mockResolvedValue({ data: capsa });
      mockDecryptCapsa.mockReturnValue(decrypted);

      const result = await service.getDecryptedCapsa('capsa_123', PRIVATE_KEY, {
        partyId: 'party_recipient',
        previousPrivateKeys: ['old'],
      });

      expect(result).toBe(decrypted);
      expect(mockAxios.get).toHaveBeenCalledTimes(1);
      expect(mockAxios.get).toHaveBeenCalledWith('/api/capsas/capsa_123');
      expect(mockAxios.post).not.toHaveBeenCalled();
      expect(mockDecryptCapsa).toHaveBeenCalledWith(capsa, PRIVATE_KEY, {
        partyId: 'party_recipient',
        previousPrivateKeys: ['old'],
      });
    });

    it('should default to no options', async () => {
      const capsa = createSampleCapsa();
      (mockAxios.get as Mock).mockResolvedValue({ data: capsa });
      mockDecryptCapsa.mockReturnValue({});

      await service.getDecryptedCapsa('capsa_123', PRIVATE_KEY);

      expect(mockDecryptCapsa).toHaveBeenCalledWith(capsa, PRIVATE_KEY, {});
    });

    it('should propagate verification failures from the decryptor', async () => {
      (mockAxios.get as Mock).mockResolvedValue({ data: createSampleCapsa({ creatorPublicKey: undefined }) });
      mockDecryptCapsa.mockImplementation(() => {
        throw new CapsaraCapsaError('no key', 'SIGNATURE_KEY_MISSING', 0);
      });

      await expect(service.getDecryptedCapsa('capsa_123', PRIVATE_KEY)).rejects.toMatchObject({
        code: 'SIGNATURE_KEY_MISSING',
      });
    });

    it('should not decrypt when the fetch fails', async () => {
      (mockAxios.get as Mock).mockRejectedValue(apiError(410, 'ENVELOPE_EXPIRED', 'Expired'));

      await expect(service.getDecryptedCapsa('capsa_123', PRIVATE_KEY)).rejects.toMatchObject({ statusCode: 410 });
      expect(mockDecryptCapsa).not.toHaveBeenCalled();
    });
  });

  describe('listCapsas', () => {
    it('should list capsas without filters', async () => {
      const response: CapsaListResponse = {
        capsas: [summary('capsa_1'), summary('capsa_2')],
        pagination: { limit: 20, hasMore: false },
      };
      (mockAxios.get as Mock).mockResolvedValue({ data: response });

      const result = await service.listCapsas();

      expect(result.capsas).toHaveLength(2);
      expect(result.pagination.hasMore).toBe(false);
      expect(mockAxios.get).toHaveBeenCalledWith('/api/capsas', { params: undefined });
    });

    it('should pass filters, including soft_deleted status', async () => {
      (mockAxios.get as Mock).mockResolvedValue({ data: { capsas: [], pagination: { limit: 10, hasMore: false } } });

      await service.listCapsas({ status: 'soft_deleted', limit: 10 });

      expect(mockAxios.get).toHaveBeenCalledWith('/api/capsas', { params: { status: 'soft_deleted', limit: 10 } });
    });

    it('should return cursors', async () => {
      (mockAxios.get as Mock).mockResolvedValue({
        data: { capsas: [summary('capsa_3')], pagination: { limit: 1, hasMore: true, nextCursor: 'n', prevCursor: 'p' } },
      });

      const result = await service.listCapsas({ limit: 1, after: 'c' });

      expect(result.pagination).toEqual({ limit: 1, hasMore: true, nextCursor: 'n', prevCursor: 'p' });
    });

    it('should handle null response data defensively', async () => {
      (mockAxios.get as Mock).mockResolvedValue({ data: null });

      const result = await service.listCapsas({ limit: 5 });

      expect(result.capsas).toEqual([]);
      expect(result.pagination.limit).toBe(5);
      expect(result.pagination.hasMore).toBe(false);
    });

    it('should default the limit when neither response nor filters give one', async () => {
      (mockAxios.get as Mock).mockResolvedValue({ data: { capsas: [] } });

      expect((await service.listCapsas()).pagination.limit).toBe(20);
    });

    it('should expose VALIDATION_ERROR array details', async () => {
      const issues = [{ path: 'limit', message: 'Too big' }];
      (mockAxios.get as Mock).mockRejectedValue(apiError(400, 'VALIDATION_ERROR', 'Invalid query', issues));

      await expect(service.listCapsas({ limit: 5000 })).rejects.toMatchObject({ code: 'VALIDATION_ERROR', details: issues });
    });
  });

  describe('deleteCapsa', () => {
    it('should delete capsa by ID', async () => {
      (mockAxios.delete as Mock).mockResolvedValue({ data: {} });

      await service.deleteCapsa('capsa_123');

      expect(mockAxios.delete).toHaveBeenCalledWith('/api/capsas/capsa_123');
    });

    it('should expose PERMISSION_DENIED verbatim', async () => {
      (mockAxios.delete as Mock).mockRejectedValue(apiError(403, 'PERMISSION_DENIED', 'Only the creator can delete'));

      await expect(service.deleteCapsa('capsa_123')).rejects.toMatchObject({ code: 'PERMISSION_DENIED', statusCode: 403 });
    });

    it('should tolerate a non-JSON error body', async () => {
      (mockAxios.delete as Mock).mockRejectedValue({ response: { status: 502, data: '<html></html>' } });

      await expect(service.deleteCapsa('capsa_123')).rejects.toMatchObject({ code: 'HTTP_502', message: 'Bad Gateway' });
    });
  });
});
