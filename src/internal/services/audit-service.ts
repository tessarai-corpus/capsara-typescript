/** Audit trail service for capsa audit entry operations. */

import type { AxiosInstance } from 'axios';
import { CapsaraAuditError } from '../../errors/audit-error.js';
import type {
  GetAuditEntriesFilters,
  GetAuditEntriesResponse,
  OffsetPagination,
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
      const data: unknown = response.data;
      if (typeof data !== 'object' || data === null || Array.isArray(data)) {
        return response.data;
      }
      const body = data as GetAuditEntriesResponse;
      const raw: unknown = body.pagination;
      const pagination = (typeof raw === 'object' && raw !== null && !Array.isArray(raw) ? raw : {}) as Partial<OffsetPagination>;
      return {
        ...body,
        pagination: {
          ...pagination,
          page: pagination.page ?? null,
          limit: pagination.limit ?? null,
          total: pagination.total ?? null,
          totalPages: pagination.totalPages ?? null,
        },
      };
    } catch (error) {
      throw CapsaraAuditError.fromApiError(error);
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
      throw CapsaraAuditError.fromApiError(error);
    }
  }
}
