import axios, { AxiosInstance, AxiosResponse } from 'axios';
import { API_BASE_URL, SECURITY } from '@/config/constants';
import { User, LoginCredentials, RegisterData, ApiResponse } from '@/types';

class AuthService {
  private api: AxiosInstance;
  private tokenRefreshPromise: Promise<string> | null = null;

  constructor() {
    this.api = axios.create({
      baseURL: `${API_BASE_URL}/auth`,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    this.setupInterceptors();
  }

  private setupInterceptors(): void {
    // Request interceptor
    this.api.interceptors.request.use(
      (config) => {
        const token = this.getStoredToken();
        if (token && config.headers) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor
    this.api.interceptors.response.use(
      (response) => response,
      async (error) => {
        const originalRequest = error.config;

        if (error.response?.status === 401 && !originalRequest._retry) {
          originalRequest._retry = true;

          try {
            const newToken = await this.handleTokenRefresh();
            if (newToken && originalRequest.headers) {
              originalRequest.headers.Authorization = `Bearer ${newToken}`;
              return this.api(originalRequest);
            }
          } catch (refreshError) {
            this.clearStoredTokens();
            window.location.href = '/auth/login';
            return Promise.reject(refreshError);
          }
        }

        return Promise.reject(error);
      }
    );
  }

  private async handleTokenRefresh(): Promise<string | null> {
    if (this.tokenRefreshPromise) {
      return this.tokenRefreshPromise;
    }

    this.tokenRefreshPromise = this.refreshToken();
    
    try {
      const token = await this.tokenRefreshPromise;
      this.tokenRefreshPromise = null;
      return token;
    } catch (error) {
      this.tokenRefreshPromise = null;
      throw error;
    }
  }

  private getStoredToken(): string | null {
    if (typeof window === 'undefined') return null;
    return localStorage.getItem('token') || sessionStorage.getItem('token');
  }

  private getStoredRefreshToken(): string | null {
    if (typeof window === 'undefined') return null;
    return localStorage.getItem('refreshToken') || sessionStorage.getItem('refreshToken');
  }

  private setStoredTokens(token: string, refreshToken: string, rememberMe: boolean = false): void {
    if (typeof window === 'undefined') return;
    
    const storage = rememberMe ? localStorage : sessionStorage;
    storage.setItem('token', token);
    storage.setItem('refreshToken', refreshToken);
  }

  private clearStoredTokens(): void {
    if (typeof window === 'undefined') return;
    
    localStorage.removeItem('token');
    localStorage.removeItem('refreshToken');
    sessionStorage.removeItem('token');
    sessionStorage.removeItem('refreshToken');
  }

  // Authentication methods
  async login(credentials: LoginCredentials): Promise<ApiResponse<{ user: User; token: string; refreshToken: string }>> {
    try {
      const response: AxiosResponse<ApiResponse<{ user: User; token: string; refreshToken: string }>> = 
        await this.api.post('/login', credentials);

      if (response.data.success && response.data.data) {
        const { token, refreshToken } = response.data.data;
        this.setStoredTokens(token, refreshToken, credentials.rememberMe);
      }

      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async register(userData: RegisterData): Promise<ApiResponse<{ user: User }>> {
    try {
      const response: AxiosResponse<ApiResponse<{ user: User }>> = 
        await this.api.post('/register', userData);
      
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async logout(): Promise<ApiResponse> {
    try {
      const response: AxiosResponse<ApiResponse> = await this.api.post('/logout');
      this.clearStoredTokens();
      return response.data;
    } catch (error: any) {
      this.clearStoredTokens();
      throw this.handleError(error);
    }
  }

  async refreshToken(): Promise<string> {
    const refreshToken = this.getStoredRefreshToken();
    
    if (!refreshToken) {
      throw new Error('No refresh token available');
    }

    try {
      const response: AxiosResponse<ApiResponse<{ token: string; refreshToken: string }>> = 
        await axios.post(`${API_BASE_URL}/auth/refresh`, {}, {
          headers: {
            'Authorization': `Bearer ${refreshToken}`,
            'Content-Type': 'application/json',
          },
        });

      if (response.data.success && response.data.data) {
        const { token, refreshToken: newRefreshToken } = response.data.data;
        this.setStoredTokens(token, newRefreshToken, !!localStorage.getItem('refreshToken'));
        return token;
      }

      throw new Error('Token refresh failed');
    } catch (error: any) {
      this.clearStoredTokens();
      throw this.handleError(error);
    }
  }

  async verifyEmail(token: string): Promise<ApiResponse> {
    try {
      const response: AxiosResponse<ApiResponse> = 
        await this.api.post('/verify-email', { token });
      
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async resendVerificationEmail(email: string): Promise<ApiResponse> {
    try {
      const response: AxiosResponse<ApiResponse> = 
        await this.api.post('/resend-verification', { email });
      
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async forgotPassword(email: string): Promise<ApiResponse> {
    try {
      const response: AxiosResponse<ApiResponse> = 
        await this.api.post('/forgot-password', { email });
      
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async resetPassword(token: string, password: string): Promise<ApiResponse> {
    try {
      const response: AxiosResponse<ApiResponse> = 
        await this.api.post('/reset-password', { token, password });
      
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<ApiResponse> {
    try {
      const response: AxiosResponse<ApiResponse> = 
        await this.api.post('/change-password', { currentPassword, newPassword });
      
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async getCurrentUser(): Promise<ApiResponse<User>> {
    try {
      const response: AxiosResponse<ApiResponse<User>> = 
        await this.api.get('/me');
      
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async updateProfile(userData: Partial<User>): Promise<ApiResponse<User>> {
    try {
      const response: AxiosResponse<ApiResponse<User>> = 
        await this.api.patch('/profile', userData);
      
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  // Two-factor authentication
  async enableTwoFactor(): Promise<ApiResponse<{ secret: string; qrCode: string }>> {
    try {
      const response: AxiosResponse<ApiResponse<{ secret: string; qrCode: string }>> = 
        await this.api.post('/2fa/enable');
      
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async verifyTwoFactor(code: string): Promise<ApiResponse<{ backupCodes: string[] }>> {
    try {
      const response: AxiosResponse<ApiResponse<{ backupCodes: string[] }>> = 
        await this.api.post('/2fa/verify', { code });
      
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async disableTwoFactor(code: string): Promise<ApiResponse> {
    try {
      const response: AxiosResponse<ApiResponse> = 
        await this.api.post('/2fa/disable', { code });
      
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  // Biometric authentication
  async registerBiometric(biometricData: string): Promise<ApiResponse> {
    try {
      const response: AxaxResponse<ApiResponse> = 
        await this.api.post('/biometric/register', { biometricData });
      
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async authenticateBiometric(biometricData: string): Promise<ApiResponse<{ token: string; refreshToken: string }>> {
    try {
      const response: AxiosResponse<ApiResponse<{ token: string; refreshToken: string }>> = 
        await this.api.post('/biometric/authenticate', { biometricData });
      
      if (response.data.success && response.data.data) {
        const { token, refreshToken } = response.data.data;
        this.setStoredTokens(token, refreshToken, true);
      }

      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  // Session management
  async validateSession(): Promise<ApiResponse<{ valid: boolean; expiresAt: string }>> {
    try {
      const response: AxiosResponse<ApiResponse<{ valid: boolean; expiresAt: string }>> = 
        await this.api.get('/session/validate');
      
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async extendSession(): Promise<ApiResponse<{ expiresAt: string }>> {
    try {
      const response: AxiosResponse<ApiResponse<{ expiresAt: string }>> = 
        await this.api.post('/session/extend');
      
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  // Security
  async getSecurityEvents(): Promise<ApiResponse<any[]>> {
    try {
      const response: AxiosResponse<ApiResponse<any[]>> = 
        await this.api.get('/security/events');
      
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  async reportSuspiciousActivity(description: string): Promise<ApiResponse> {
    try {
      const response: AxiosResponse<ApiResponse> = 
        await this.api.post('/security/report', { description });
      
      return response.data;
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  // Utility methods
  isAuthenticated(): boolean {
    return !!this.getStoredToken();
  }

  getToken(): string | null {
    return this.getStoredToken();
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

export const authService = new AuthService();
export default authService;