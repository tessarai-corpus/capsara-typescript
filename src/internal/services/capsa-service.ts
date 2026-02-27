/** Capsa CRUD operations service. */

import type { AxiosInstance } from 'axios';
import { decryptCapsa, type DecryptedCapsa } from '../decryptor/capsa-decryptor.js';
import { CapsaraCapsaError } from '../../errors/capsa-error.js';
import type { AxiosLikeError } from '../../errors/capsara-error.js';
import type { Capsa, CapsaListFilters, CapsaListResponse } from '../../types/index.js';
import type { KeyManager } from './key-service.js';

export interface CapsaServiceOptions {
  axiosInstance: AxiosInstance;
  keyManager: KeyManager;
}

export class CapsaService {
  private http: AxiosInstance;
  private keyManager: KeyManager;

  constructor(options: CapsaServiceOptions) {
    this.http = options.axiosInstance;
    this.keyManager = options.keyManager;
  }

  /**
   * Get capsa by ID (encrypted)
   * @param capsaId - Capsa ID
   * @returns Encrypted capsa
   */
  async getCapsa(capsaId: string): Promise<Capsa> {
    try {
      const response = await this.http.get<Capsa>(`/api/capsas/${capsaId}`);
      return response.data;
    } catch (error) {
      throw CapsaraCapsaError.fromApiError(error as AxiosLikeError);
    }
  }

  /**
   * Get and decrypt capsa
   * @param capsaId - Capsa ID
   * @param privateKey - Private key for decryption
   * @param verifySignature - Whether to verify signature (default: true)
   * @returns Decrypted capsa
   */
  async getDecryptedCapsa(
    capsaId: string,
    privateKey: string,
    verifySignature = true
  ): Promise<DecryptedCapsa> {
    const capsa = await this.getCapsa(capsaId);

    // Fetch creator's public key for signature verification
    let creatorPublicKey: string | undefined;
    if (verifySignature) {
      const creatorKey = await this.keyManager.fetchExplicitPartyKey(capsa.creator);
      creatorPublicKey = creatorKey?.publicKey;
    }

    return decryptCapsa(
      capsa,
      privateKey,
      undefined, // Auto-detect party from keychain
      creatorPublicKey,
      verifySignature
    );
  }

  /**
   * List capsas with cursor-based pagination
   * @param filters - Query filters
   * @returns Paginated capsa list (always returns valid structure, even if empty)
   */
  async listCapsas(filters?: CapsaListFilters): Promise<CapsaListResponse> {
    try {
      const response = await this.http.get<CapsaListResponse>('/api/capsas', {
        params: filters as Record<string, unknown>,
      });

      // Defensive handling for null/undefined response data
      const data = response.data;
      return {
        capsas: data?.capsas ?? [],
        pagination: {
          limit: data?.pagination?.limit ?? filters?.limit ?? 20,
          hasMore: data?.pagination?.hasMore ?? false,
          nextCursor: data?.pagination?.nextCursor,
          prevCursor: data?.pagination?.prevCursor,
        },
      };
    } catch (error) {
      throw CapsaraCapsaError.fromApiError(error as AxiosLikeError);
    }
  }

  /**
   * Soft delete a capsa
   * @param capsaId - Capsa ID
   */
  async deleteCapsa(capsaId: string): Promise<void> {
    try {
      await this.http.delete(`/api/capsas/${capsaId}`);
    } catch (error) {
      throw CapsaraCapsaError.fromApiError(error as AxiosLikeError);
    }
  }
}
