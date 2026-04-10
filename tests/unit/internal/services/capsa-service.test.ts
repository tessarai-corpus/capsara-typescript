/**
 * Tests for capsa-service.ts - Capsa CRUD operations
 * @file tests/unit/internal/services/capsa-service.test.ts
 */

import { describe, it, expect, vi, beforeEach, type Mock } from 'vitest';
import type { AxiosInstance } from 'axios';
import type { Capsa, CapsaListFilters, CapsaListResponse } from '../../../../src/types/index.js';
import type { DecryptedCapsa } from '../../../../src/internal/decryptor/capsa-decryptor.js';
import type { KeyManager } from '../../../../src/internal/services/key-service.js';

// Use vi.hoisted for mock functions
const { mockDecryptCapsa } = vi.hoisted(() => ({
  mockDecryptCapsa: vi.fn(),
}));

// Mock capsa-decryptor
vi.mock('../../../../src/internal/decryptor/capsa-decryptor.js', () => ({
  decryptCapsa: mockDecryptCapsa,
}));

import { CapsaService, type CapsaServiceOptions } from '../../../../src/internal/services/capsa-service.js';

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

// Helper to create mock KeyManager
function createMockKeyManager(): KeyManager {
  return {
    fetchExplicitPartyKey: vi.fn(),
    fetchPartyKeys: vi.fn(),
  } as unknown as KeyManager;
}

// Sample capsa fixture
function createSampleCapsa(overrides?: Partial<Capsa>): Capsa {
  return {
    id: 'capsa_123',
    creator: 'party_creator',
    status: 'active',
    createdAt: '2024-01-15T10:30:00Z',
    expiresAt: '2025-01-15T10:30:00Z',
    keychain: [
      {
        partyId: 'party_creator',
        encryptedKey: 'encrypted-master-key-for-creator',
        permissions: ['read'],
      },
      {
        partyId: 'party_recipient',
        encryptedKey: 'encrypted-master-key-for-recipient',
        permissions: ['read'],
      },
    ],
    files: [
      {
        id: 'file_001',
        encryptedFilename: 'encrypted-filename',
        encryptedMimeType: 'encrypted-mimetype',
        size: 1024,
        blobUrl: 'https://storage.example.com/file_001',
        iv: 'base64-iv',
        authTag: 'base64-auth-tag',
        filenameIV: 'base64-filename-iv',
        filenameAuthTag: 'base64-filename-auth-tag',
        mimeTypeIV: 'base64-mimetype-iv',
        mimeTypeAuthTag: 'base64-mimetype-auth-tag',
      },
    ],
    encryptedMetadata: 'encrypted-metadata-blob',
    metadataIV: 'base64-metadata-iv',
    metadataAuthTag: 'base64-metadata-auth-tag',
    signature: 'base64-signature',
    ...overrides,
  };
}

describe('CapsaService', () => {
  let mockAxios: AxiosInstance;
  let mockKeyManager: KeyManager;
  let service: CapsaService;

  beforeEach(() => {
    vi.clearAllMocks();
    mockAxios = createMockAxiosInstance();
    mockKeyManager = createMockKeyManager();
    const options: CapsaServiceOptions = {
      axiosInstance: mockAxios,
      keyManager: mockKeyManager,
    };
    service = new CapsaService(options);
  });

  describe('constructor', () => {
    it('should create service with axios instance and key manager', () => {
      const options: CapsaServiceOptions = {
        axiosInstance: mockAxios,
        keyManager: mockKeyManager,
      };
      const svc = new CapsaService(options);
      expect(svc).toBeInstanceOf(CapsaService);
    });
  });

  describe('getCapsa', () => {
    it('should fetch capsa by ID', async () => {
      const capsa = createSampleCapsa();
      (mockAxios.get as Mock).mockResolvedValue({ data: capsa });

      const result = await service.getCapsa('capsa_123');

      expect(result).toEqual(capsa);
      expect(mockAxios.get).toHaveBeenCalledWith('/api/capsas/capsa_123');
    });

    it('should throw CapsaraCapsaError on API error', async () => {
      const axiosError = {
        response: {
          status: 404,
          data: { error: { code: 'ENVELOPE_NOT_FOUND', message: 'Capsa not found' } },
        },
        isAxiosError: true,
      };

      (mockAxios.get as Mock).mockRejectedValue(axiosError);

      await expect(service.getCapsa('nonexistent')).rejects.toThrow();
    });
  });

  describe('getDecryptedCapsa', () => {
    it('should fetch and decrypt capsa with signature verification', async () => {
      const capsa = createSampleCapsa();
      const decryptedCapsa: DecryptedCapsa = {
        id: capsa.id,
        creator: capsa.creator,
        status: capsa.status,
        createdAt: capsa.createdAt,
        expiresAt: capsa.expiresAt,
        masterKey: 'decrypted-master-key',
        metadata: { title: 'Test Document' },
        files: [],
        signatureValid: true,
      };

      (mockAxios.get as Mock).mockResolvedValue({ data: capsa });
      (mockKeyManager.fetchExplicitPartyKey as Mock).mockResolvedValue({
        id: 'party_creator',
        publicKey: '-----BEGIN PUBLIC KEY-----\nCreatorKey\n-----END PUBLIC KEY-----',
        fingerprint: 'SHA256:creator',
      });
      mockDecryptCapsa.mockReturnValue(decryptedCapsa);

      const result = await service.getDecryptedCapsa(
        'capsa_123',
        '-----BEGIN PRIVATE KEY-----\nPrivateKey\n-----END PRIVATE KEY-----'
      );

      expect(result).toEqual(decryptedCapsa);
      expect(mockAxios.get).toHaveBeenCalledWith('/api/capsas/capsa_123');
      expect(mockKeyManager.fetchExplicitPartyKey).toHaveBeenCalledWith('party_creator');
      expect(mockDecryptCapsa).toHaveBeenCalledWith(
        capsa,
        '-----BEGIN PRIVATE KEY-----\nPrivateKey\n-----END PRIVATE KEY-----',
        undefined,
        '-----BEGIN PUBLIC KEY-----\nCreatorKey\n-----END PUBLIC KEY-----',
        true
      );
    });

    it('should decrypt capsa without signature verification', async () => {
      const capsa = createSampleCapsa();
      const decryptedCapsa: DecryptedCapsa = {
        id: capsa.id,
        creator: capsa.creator,
        status: capsa.status,
        createdAt: capsa.createdAt,
        expiresAt: capsa.expiresAt,
        masterKey: 'decrypted-master-key',
        metadata: {},
        files: [],
        signatureValid: undefined,
      };

      (mockAxios.get as Mock).mockResolvedValue({ data: capsa });
      mockDecryptCapsa.mockReturnValue(decryptedCapsa);

      const result = await service.getDecryptedCapsa(
        'capsa_123',
        '-----BEGIN PRIVATE KEY-----\nPrivateKey\n-----END PRIVATE KEY-----',
        false
      );

      expect(result).toEqual(decryptedCapsa);
      expect(mockKeyManager.fetchExplicitPartyKey).not.toHaveBeenCalled();
      expect(mockDecryptCapsa).toHaveBeenCalledWith(
        capsa,
        '-----BEGIN PRIVATE KEY-----\nPrivateKey\n-----END PRIVATE KEY-----',
        undefined,
        undefined,
        false
      );
    });

    it('should handle missing creator public key', async () => {
      const capsa = createSampleCapsa();
      const decryptedCapsa: DecryptedCapsa = {
        id: capsa.id,
        creator: capsa.creator,
        status: capsa.status,
        createdAt: capsa.createdAt,
        expiresAt: capsa.expiresAt,
        masterKey: 'decrypted-master-key',
        metadata: {},
        files: [],
        signatureValid: false,
      };

      (mockAxios.get as Mock).mockResolvedValue({ data: capsa });
      (mockKeyManager.fetchExplicitPartyKey as Mock).mockResolvedValue(undefined);
      mockDecryptCapsa.mockReturnValue(decryptedCapsa);

      const result = await service.getDecryptedCapsa(
        'capsa_123',
        '-----BEGIN PRIVATE KEY-----\nPrivateKey\n-----END PRIVATE KEY-----'
      );

      expect(result).toEqual(decryptedCapsa);
      expect(mockDecryptCapsa).toHaveBeenCalledWith(
        capsa,
        '-----BEGIN PRIVATE KEY-----\nPrivateKey\n-----END PRIVATE KEY-----',
        undefined,
        undefined,
        true
      );
    });
  });

  describe('listCapsas', () => {
    it('should list capsas without filters', async () => {
      const response: CapsaListResponse = {
        capsas: [createSampleCapsa({ id: 'capsa_1' }), createSampleCapsa({ id: 'capsa_2' })],
        pagination: {
          limit: 20,
          hasMore: false,
        },
      };

      (mockAxios.get as Mock).mockResolvedValue({ data: response });

      const result = await service.listCapsas();

      expect(result.capsas).toHaveLength(2);
      expect(result.pagination.hasMore).toBe(false);
      expect(mockAxios.get).toHaveBeenCalledWith('/api/capsas', { params: undefined });
    });

    it('should list capsas with filters', async () => {
      const filters: CapsaListFilters = {
        limit: 10,
        status: 'active',
      };

      const response: CapsaListResponse = {
        capsas: [createSampleCapsa()],
        pagination: {
          limit: 10,
          hasMore: true,
          nextCursor: 'cursor_abc123',
        },
      };

      (mockAxios.get as Mock).mockResolvedValue({ data: response });

      const result = await service.listCapsas(filters);

      expect(result).toEqual(response);
      expect(mockAxios.get).toHaveBeenCalledWith('/api/capsas', { params: filters });
    });

    it('should handle pagination with cursor', async () => {
      const filters: CapsaListFilters = {
        cursor: 'cursor_abc123',
        limit: 20,
      };

      const response: CapsaListResponse = {
        capsas: [],
        pagination: {
          limit: 20,
          hasMore: false,
          prevCursor: 'cursor_prev',
        },
      };

      (mockAxios.get as Mock).mockResolvedValue({ data: response });

      const result = await service.listCapsas(filters);

      expect(result.capsas).toEqual([]);
      expect(result.pagination.prevCursor).toBe('cursor_prev');
    });

    it('should handle null/undefined response data defensively', async () => {
      (mockAxios.get as Mock).mockResolvedValue({ data: null });

      const result = await service.listCapsas({ limit: 15 });

      expect(result.capsas).toEqual([]);
      expect(result.pagination.limit).toBe(15);
      expect(result.pagination.hasMore).toBe(false);
    });

    it('should handle undefined pagination in response', async () => {
      (mockAxios.get as Mock).mockResolvedValue({
        data: {
          capsas: [createSampleCapsa()],
          // pagination is missing
        },
      });

      const result = await service.listCapsas();

      expect(result.capsas).toHaveLength(1);
      expect(result.pagination.limit).toBe(20);
      expect(result.pagination.hasMore).toBe(false);
    });

    it('should throw CapsaraCapsaError on API error', async () => {
      const axiosError = {
        response: {
          status: 401,
          data: { error: { code: 'UNAUTHORIZED', message: 'Not authenticated' } },
        },
        isAxiosError: true,
      };

      (mockAxios.get as Mock).mockRejectedValue(axiosError);

      await expect(service.listCapsas()).rejects.toThrow();
    });
  });

  describe('deleteCapsa', () => {
    it('should delete capsa by ID', async () => {
      (mockAxios.delete as Mock).mockResolvedValue({ data: {} });

      await service.deleteCapsa('capsa_123');

      expect(mockAxios.delete).toHaveBeenCalledWith('/api/capsas/capsa_123');
    });

    it('should throw CapsaraCapsaError on API error', async () => {
      const axiosError = {
        response: {
          status: 403,
          data: { error: { code: 'ACCESS_DENIED', message: 'Not authorized to delete' } },
        },
        isAxiosError: true,
      };

      (mockAxios.delete as Mock).mockRejectedValue(axiosError);

      await expect(service.deleteCapsa('capsa_123')).rejects.toThrow();
    });

    it('should throw error for legal hold capsa', async () => {
      const axiosError = {
        response: {
          status: 409,
          data: { error: { code: 'LEGAL_HOLD', message: 'Capsa is under legal hold' } },
        },
        isAxiosError: true,
      };

      (mockAxios.delete as Mock).mockRejectedValue(axiosError);

      await expect(service.deleteCapsa('capsa_legal')).rejects.toThrow();
    });
  });
});
