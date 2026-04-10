/** Audit trail service for capsa audit entry operations. */

import type { AxiosInstance } from 'axios';
import { CapsaraAuditError } from '../../errors/audit-error.js';
import type { AxiosLikeError } from '../../errors/capsara-error.js';
import type {
  GetAuditEntriesFilters,
  GetAuditEntriesResponse,
  CreateAuditEntryRequest,
  CreateAuditEntryResponse,
} from '../../types/index.js';

export interface AuditServiceOptions {
  axiosInstance: AxiosInstance;
}

export class AuditService {
  private http: AxiosInstance;

  constructor(options: AuditServiceOptions) {
    this.http = options.axiosInstance;
  }

  /**
   * Get audit trail for a capsa
   * @param capsaId - Capsa ID
   * @param filters - Optional filters
   * @returns Paginated audit entries
   */
  async getAuditEntries(
    capsaId: string,
    filters?: GetAuditEntriesFilters
  ): Promise<GetAuditEntriesResponse> {
    try {
      const response = await this.http.get<GetAuditEntriesResponse>(
        `/api/capsas/${capsaId}/audit`,
        { params: filters as Record<string, unknown> }
      );
      return response.data;
    } catch (error) {
      throw CapsaraAuditError.fromApiError(error as AxiosLikeError);
    }
  }

  /**
   * Create audit entry for a capsa
   * @param capsaId - Capsa ID
   * @param entry - Audit entry request
   * @returns Success response
   */
  async createAuditEntry(
    capsaId: string,
    entry: CreateAuditEntryRequest
  ): Promise<CreateAuditEntryResponse> {
    // Client-side validation: 'log' action requires details
    if (entry.action === 'log' && (!entry.details || Object.keys(entry.details).length === 0)) {
      throw CapsaraAuditError.missingDetails();
    }

    try {
      const response = await this.http.post<CreateAuditEntryResponse>(
        `/api/capsas/${capsaId}/audit`,
        entry
      );
      return response.data;
    } catch (error) {
      throw CapsaraAuditError.fromApiError(error as AxiosLikeError);
    }
  }
}
