/** Refreshes the access token once on a 401 and retries the request, shared by every authenticated client. */

import type { AxiosInstance, InternalAxiosRequestConfig } from 'axios';

export interface TokenRefresher {
  /** Refreshes the access token, sharing one in-flight refresh between concurrent callers. */
  refresh(): Promise<boolean>;
  canRefresh(): boolean;
  getToken(): string | null;
  getLastRefreshError(): Error | null;
}

export function createTokenRefresher(auth: TokenRefresher): TokenRefresher {
  let inFlight: Promise<boolean> | null = null;
  return {
    refresh(): Promise<boolean> {
      inFlight ??= auth.refresh().finally(() => {
        inFlight = null;
      });
      return inFlight;
    },
    canRefresh: () => auth.canRefresh(),
    getToken: () => auth.getToken(),
    getLastRefreshError: () => auth.getLastRefreshError(),
  };
}

type RetriableConfig = InternalAxiosRequestConfig & { _refreshed?: boolean };

export function addTokenRefreshInterceptor(axiosInstance: AxiosInstance, refresher: TokenRefresher): void {
  axiosInstance.interceptors.response.use(
    (response) => response,
    async (error: unknown) => {
      const axiosError = error as { response?: { status?: number }; config?: RetriableConfig };
      const originalRequest = axiosError.config;

      if (
        axiosError.response?.status === 401 &&
        originalRequest &&
        !originalRequest._refreshed &&
        refresher.canRefresh()
      ) {
        originalRequest._refreshed = true;

        if (await refresher.refresh()) {
          const newToken = refresher.getToken();
          if (newToken) {
            originalRequest.headers.Authorization = `Bearer ${newToken}`;
          }
          return axiosInstance(originalRequest);
        }

        const refreshError = refresher.getLastRefreshError();
        if (refreshError) {
          return Promise.reject(refreshError);
        }
      }

      if (error instanceof Error) {
        return Promise.reject(error);
      }
      return Promise.reject(new Error(String(error)));
    }
  );
}
