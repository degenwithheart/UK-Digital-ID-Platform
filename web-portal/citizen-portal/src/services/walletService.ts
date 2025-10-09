import axios, { AxiosInstance, AxiosResponse } from 'axios';
import { API_BASE_URL } from '@/config/constants';
import { Credential, Service, ApiResponse } from '@/types';
import authService from './authService';

class WalletService {
  private api: AxiosInstance;

  constructor() {
    this.api = axios.create({
      baseURL: `${API_BASE_URL}/wallet`,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    this.setupInterceptors();
  }

  private setupInterceptors(): void {
    this.api.interceptors.request.use(
      (config) => {
        const token = authService.getToken();
        if (token && config.headers) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );
  }

  // Credentials Management
  async getCredentials(): Promise<ApiResponse<Credential[]>> {
    try {
      const response: AxiosResponse<ApiResponse<Credential[]>> = 
        await this.api.get('/credentials');
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async getCredential(id: string): Promise<ApiResponse<Credential>> {
    try {
      const response: AxiosResponse<ApiResponse<Credential>> = 
        await this.api.get(`/credentials/${id}`);
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async addCredential(credentialData: Partial<Credential>): Promise<ApiResponse<Credential>> {
    try {
      const response: AxiosResponse<ApiResponse<Credential>> = 
        await this.api.post('/credentials', credentialData);
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async updateCredential(id: string, updates: Partial<Credential>): Promise<ApiResponse<Credential>> {
    try {
      const response: AxiosResponse<ApiResponse<Credential>> = 
        await this.api.patch(`/credentials/${id}`, updates);
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async deleteCredential(id: string): Promise<ApiResponse> {
    try {
      const response: AxiosResponse<ApiResponse> = 
        await this.api.delete(`/credentials/${id}`);
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async uploadCredentialDocument(credentialId: string, file: File): Promise<ApiResponse<{ url: string }>> {
    try {
      const formData = new FormData();
      formData.append('document', file);

      const response: AxiosResponse<ApiResponse<{ url: string }>> = 
        await this.api.post(`/credentials/${credentialId}/upload`, formData, {
          headers: {
            'Content-Type': 'multipart/form-data',
          },
          onUploadProgress: (progressEvent) => {
            const percentCompleted = Math.round((progressEvent.loaded * 100) / (progressEvent.total || 1));
            // Emit progress event
            window.dispatchEvent(new CustomEvent('uploadProgress', { 
              detail: { credentialId, progress: percentCompleted }
            }));
          },
        });

      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async verifyCredential(id: string, verificationData: any): Promise<ApiResponse<Credential>> {
    try {
      const response: AxiosResponse<ApiResponse<Credential>> = 
        await this.api.post(`/credentials/${id}/verify`, verificationData);
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  // Services Management
  async getServices(): Promise<ApiResponse<Service[]>> {
    try {
      const response: AxiosResponse<ApiResponse<Service[]>> = 
        await this.api.get('/services');
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async getAvailableServices(): Promise<ApiResponse<Service[]>> {
    try {
      const response: AxiosResponse<ApiResponse<Service[]>> = 
        await this.api.get('/services/available');
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async enrollInService(serviceId: string): Promise<ApiResponse<Service>> {
    try {
      const response: AxiosResponse<ApiResponse<Service>> = 
        await this.api.post(`/services/${serviceId}/enroll`);
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async unenrollFromService(serviceId: string): Promise<ApiResponse> {
    try {
      const response: AxiosResponse<ApiResponse> = 
        await this.api.delete(`/services/${serviceId}/enroll`);
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async accessService(serviceId: string): Promise<ApiResponse<{ accessUrl: string; token: string }>> {
    try {
      const response: AxiosResponse<ApiResponse<{ accessUrl: string; token: string }>> = 
        await this.api.post(`/services/${serviceId}/access`);
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  // Wallet Operations
  async syncWallet(): Promise<ApiResponse<{ credentials: Credential[]; services: Service[] }>> {
    try {
      const response: AxiosResponse<ApiResponse<{ credentials: Credential[]; services: Service[] }>> = 
        await this.api.post('/sync');
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async exportWallet(): Promise<ApiResponse<{ data: string }>> {
    try {
      const response: AxiosResponse<ApiResponse<{ data: string }>> = 
        await this.api.post('/export');
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async importWallet(walletData: string): Promise<ApiResponse> {
    try {
      const response: AxiosResponse<ApiResponse> = 
        await this.api.post('/import', { data: walletData });
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async backupWallet(): Promise<ApiResponse<{ backupId: string }>> {
    try {
      const response: AxiosResponse<ApiResponse<{ backupId: string }>> = 
        await this.api.post('/backup');
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async restoreWallet(backupId: string): Promise<ApiResponse> {
    try {
      const response: AxiosResponse<ApiResponse> = 
        await this.api.post('/restore', { backupId });
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  // Sharing and Permissions
  async shareCredential(credentialId: string, recipientEmail: string, permissions: string[]): Promise<ApiResponse<{ shareId: string }>> {
    try {
      const response: AxiosResponse<ApiResponse<{ shareId: string }>> = 
        await this.api.post('/share', {
          credentialId,
          recipientEmail,
          permissions,
        });
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async revokeShare(shareId: string): Promise<ApiResponse> {
    try {
      const response: AxiosResponse<ApiResponse> = 
        await this.api.delete(`/share/${shareId}`);
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async getSharedCredentials(): Promise<ApiResponse<any[]>> {
    try {
      const response: AxiosResponse<ApiResponse<any[]>> = 
        await this.api.get('/shared');
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  // QR Code Generation
  async generateQRCode(credentialId: string): Promise<ApiResponse<{ qrCode: string }>> {
    try {
      const response: AxiosResponse<ApiResponse<{ qrCode: string }>> = 
        await this.api.post(`/credentials/${credentialId}/qr`);
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  // Statistics and Analytics
  async getWalletStats(): Promise<ApiResponse<{
    totalCredentials: number;
    verifiedCredentials: number;
    pendingCredentials: number;
    activeServices: number;
    recentActivity: number;
  }>> {
    try {
      const response: AxiosResponse<ApiResponse<{
        totalCredentials: number;
        verifiedCredentials: number;
        pendingCredentials: number;
        activeServices: number;
        recentActivity: number;
      }>> = await this.api.get('/stats');
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async getActivity(limit: number = 50): Promise<ApiResponse<any[]>> {
    try {
      const response: AxiosResponse<ApiResponse<any[]>> = 
        await this.api.get(`/activity?limit=${limit}`);
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  // Search and Filtering
  async searchCredentials(query: string, filters?: any): Promise<ApiResponse<Credential[]>> {
    try {
      const params = new URLSearchParams({ query });
      if (filters) {
        Object.entries(filters).forEach(([key, value]) => {
          if (value) params.append(key, String(value));
        });
      }

      const response: AxiosResponse<ApiResponse<Credential[]>> = 
        await this.api.get(`/credentials/search?${params.toString()}`);
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async searchServices(query: string, filters?: any): Promise<ApiResponse<Service[]>> {
    try {
      const params = new URLSearchParams({ query });
      if (filters) {
        Object.entries(filters).forEach(([key, value]) => {
          if (value) params.append(key, String(value));
        });
      }

      const response: AxiosResponse<ApiResponse<Service[]>> = 
        await this.api.get(`/services/search?${params.toString()}`);
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  // Offline Support
  async getCachedData(): Promise<{
    credentials: Credential[];
    services: Service[];
    lastSync: string;
  }> {
    if (typeof window !== 'undefined' && 'localStorage' in window) {
      const cached = localStorage.getItem('walletCache');
      if (cached) {
        return JSON.parse(cached);
      }
    }
    return { credentials: [], services: [], lastSync: '' };
  }

  async setCachedData(data: {
    credentials: Credential[];
    services: Service[];
    lastSync: string;
  }): Promise<void> {
    if (typeof window !== 'undefined' && 'localStorage' in window) {
      localStorage.setItem('walletCache', JSON.stringify(data));
    }
  }

  async clearCache(): Promise<void> {
    if (typeof window !== 'undefined' && 'localStorage' in window) {
      localStorage.removeItem('walletCache');
    }
  }

  private handleError(error: any): Error {
    if (error.response?.data?.message) {
      return new Error(error.response.data.message);
    }
    if (error.message) {
      return new Error(error.message);
    }
    return new Error('An unexpected error occurred');
  }
}

export const walletService = new WalletService();
export default walletService;