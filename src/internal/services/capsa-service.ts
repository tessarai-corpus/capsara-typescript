/** Capsa CRUD operations service. */

import type { AxiosInstance } from 'axios';
import { decryptCapsa, type DecryptCapsaOptions, type DecryptedCapsa } from '../decryptor/capsa-decryptor.js';
import { CapsaraCapsaError } from '../../errors/capsa-error.js';
import type { Capsa, CapsaListFilters, CapsaListResponse } from '../../types/index.js';

export interface CapsaServiceOptions {
  axiosInstance: AxiosInstance;
}

export class CapsaService {
  private http: AxiosInstance;

  constructor(options: CapsaServiceOptions) {
    this.http = options.axiosInstance;
  }

  async getCapsa(capsaId: string): Promise<Capsa> {
    let data: unknown;
    try {
      const response = await this.http.get<unknown>(`/api/capsas/${capsaId}`);
      data = response.data;
    } catch (error) {
      throw CapsaraCapsaError.fromApiError(error);
    }
    if (typeof data !== 'object' || data === null || Array.isArray(data)) {
      throw new CapsaraCapsaError(
        `The server returned an unexpected response body for capsa ${capsaId}.`,
        'INVALID_RESPONSE',
        0,
        { capsaId }
      );
    }
    return data as Capsa;
  }

  async getDecryptedCapsa(
    capsaId: string,
    privateKey: string,
    options: DecryptCapsaOptions = {}
  ): Promise<DecryptedCapsa> {
    const capsa = await this.getCapsa(capsaId);
    return decryptCapsa(capsa, privateKey, options);
  }

  async listCapsas(filters?: CapsaListFilters): Promise<CapsaListResponse> {
    try {
      const response = await this.http.get<CapsaListResponse>('/api/capsas', {
        params: filters as Record<string, unknown>,
      });

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
      throw CapsaraCapsaError.fromApiError(error);
    }
  }

  async deleteCapsa(capsaId: string): Promise<void> {
    try {
      await this.http.delete(`/api/capsas/${capsaId}`);
    } catch (error) {
      throw CapsaraCapsaError.fromApiError(error);
    }
  }
}
