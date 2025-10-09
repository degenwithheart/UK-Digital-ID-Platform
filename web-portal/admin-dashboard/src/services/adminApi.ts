import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';

// Types for API responses
export interface ApiResponse<T = any> {
  success: boolean;
  data: T;
  message?: string;
  errors?: string[];
  timestamp: string;
}

export interface PaginatedResponse<T> extends ApiResponse<T[]> {
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

export interface SystemMetrics {
  totalUsers: number;
  activeUsers: number;
  verifications24h: number;
  systemHealth: number;
  apiResponseTime: number;
  errorRate: number;
  storageUsage: number;
  cpuUsage: number;
  memoryUsage: number;
  uptime: string;
  lastUpdated: string;
}

export interface User {
  id: string;
  email: string;
  name: string;
  role: 'admin' | 'government_official' | 'citizen';
  status: 'active' | 'inactive' | 'suspended' | 'pending';
  verificationLevel: number;
  riskScore: number;
  lastLogin: string;
  createdAt: string;
  permissions: string[];
  profile: {
    phone?: string;
    address?: string;
    department?: string;
    position?: string;
  };
}

export interface SecurityAlert {
  id: string;
  type: 'critical' | 'high' | 'medium' | 'low';
  category: 'authentication' | 'api' | 'system' | 'data' | 'network';
  title: string;
  description: string;
  timestamp: string;
  resolved: boolean;
  resolvedBy?: string;
  resolvedAt?: string;
  metadata: Record<string, any>;
  severity: number;
  affectedSystems: string[];
}

export interface GovernmentAPIStatus {
  service: string;
  status: 'online' | 'offline' | 'degraded' | 'maintenance';
  responseTime: number;
  successRate: number;
  errorRate: number;
  lastChecked: string;
  endpoint: string;
  version: string;
  documentation?: string;
  healthScore: number;
}

export interface AuditLog {
  id: string;
  userId: string;
  userName: string;
  action: string;
  resource: string;
  resourceId?: string;
  timestamp: string;
  ipAddress: string;
  userAgent: string;
  success: boolean;
  details: Record<string, any>;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
}

export interface SystemConfiguration {
  security: {
    mfaRequired: boolean;
    sessionTimeout: number;
    passwordPolicy: {
      minLength: number;
      requireNumbers: boolean;
      requireSymbols: boolean;
      requireMixedCase: boolean;
    };
    maxLoginAttempts: number;
    lockoutDuration: number;
  };
  apis: {
    rateLimit: number;
    timeout: number;
    retryAttempts: number;
    healthCheckInterval: number;
  };
  monitoring: {
    logLevel: string;
    metricsRetention: number;
    alertThresholds: {
      cpuUsage: number;
      memoryUsage: number;
      diskUsage: number;
      responseTime: number;
      errorRate: number;
    };
  };
  backup: {
    enabled: boolean;
    frequency: string;
    retention: number;
    encryption: boolean;
  };
}

class AdminApiService {
  private api: AxiosInstance;
  private baseURL: string;

  constructor() {
    this.baseURL = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8080';
    
    this.api = axios.create({
      baseURL: `${this.baseURL}/api/admin`,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json'
      }
    });

    // Request interceptor to add auth token
    this.api.interceptors.request.use(
      (config) => {
        const token = localStorage.getItem('admin_token');
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor for error handling
    this.api.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401) {
          localStorage.removeItem('admin_token');
          localStorage.removeItem('admin_user');
          window.location.href = '/auth/login';
        }
        return Promise.reject(error);
      }
    );
  }

  // Authentication
  async login(email: string, password: string): Promise<{ token: string; user: User }> {
    const response = await axios.post(`${this.baseURL}/api/auth/admin/login`, {
      email,
      password,
      adminAccess: true
    });
    return response.data;
  }

  async refreshToken(): Promise<{ token: string }> {
    const response = await this.api.post('/auth/refresh');
    return response.data;
  }

  async logout(): Promise<void> {
    await this.api.post('/auth/logout');
  }

  // Dashboard & Metrics
  async getSystemMetrics(): Promise<SystemMetrics> {
    const response = await this.api.get('/metrics/system');
    return response.data.data;
  }

  async getDashboardStats(): Promise<any> {
    const response = await this.api.get('/dashboard/stats');
    return response.data.data;
  }

  // User Management
  async getUsers(params?: {
    page?: number;
    limit?: number;
    search?: string;
    role?: string;
    status?: string;
    sortBy?: string;
    sortOrder?: 'asc' | 'desc';
  }): Promise<PaginatedResponse<User>> {
    const response = await this.api.get('/users', { params });
    return response.data;
  }

  async getUserById(userId: string): Promise<User> {
    const response = await this.api.get(`/users/${userId}`);
    return response.data.data;
  }

  async createUser(userData: Partial<User>): Promise<User> {
    const response = await this.api.post('/users', userData);
    return response.data.data;
  }

  async updateUser(userId: string, userData: Partial<User>): Promise<User> {
    const response = await this.api.put(`/users/${userId}`, userData);
    return response.data.data;
  }

  async deleteUser(userId: string): Promise<void> {
    await this.api.delete(`/users/${userId}`);
  }

  async suspendUser(userId: string, reason: string, duration?: number): Promise<void> {
    await this.api.post(`/users/${userId}/suspend`, { reason, duration });
  }

  async activateUser(userId: string): Promise<void> {
    await this.api.post(`/users/${userId}/activate`);
  }

  async resetUserPassword(userId: string): Promise<{ tempPassword: string }> {
    const response = await this.api.post(`/users/${userId}/reset-password`);
    return response.data.data;
  }

  // Security & Alerts
  async getSecurityAlerts(params?: {
    page?: number;
    limit?: number;
    type?: string;
    category?: string;
    resolved?: boolean;
    startDate?: string;
    endDate?: string;
  }): Promise<PaginatedResponse<SecurityAlert>> {
    const response = await this.api.get('/security/alerts', { params });
    return response.data;
  }

  async getSecurityAlertById(alertId: string): Promise<SecurityAlert> {
    const response = await this.api.get(`/security/alerts/${alertId}`);
    return response.data.data;
  }

  async resolveSecurityAlert(alertId: string, resolution: string): Promise<void> {
    await this.api.post(`/security/alerts/${alertId}/resolve`, { resolution });
  }

  async createSecurityAlert(alertData: Partial<SecurityAlert>): Promise<SecurityAlert> {
    const response = await this.api.post('/security/alerts', alertData);
    return response.data.data;
  }

  // Government APIs Monitoring
  async getGovernmentAPIStatus(): Promise<GovernmentAPIStatus[]> {
    const response = await this.api.get('/government-apis/status');
    return response.data.data;
  }

  async testGovernmentAPI(apiName: string): Promise<{ success: boolean; responseTime: number; error?: string }> {
    const response = await this.api.post(`/government-apis/${apiName}/test`);
    return response.data.data;
  }

  async updateAPIConfiguration(apiName: string, config: any): Promise<void> {
    await this.api.put(`/government-apis/${apiName}/config`, config);
  }

  // System Monitoring
  async getSystemHealth(): Promise<any> {
    const response = await this.api.get('/system/health');
    return response.data.data;
  }

  async getSystemLogs(params?: {
    page?: number;
    limit?: number;
    level?: string;
    service?: string;
    startDate?: string;
    endDate?: string;
  }): Promise<PaginatedResponse<any>> {
    const response = await this.api.get('/system/logs', { params });
    return response.data;
  }

  async getPerformanceMetrics(timeRange?: string): Promise<any> {
    const response = await this.api.get('/system/performance', { 
      params: { timeRange } 
    });
    return response.data.data;
  }

  // Audit Logs
  async getAuditLogs(params?: {
    page?: number;
    limit?: number;
    userId?: string;
    action?: string;
    resource?: string;
    startDate?: string;
    endDate?: string;
    riskLevel?: string;
  }): Promise<PaginatedResponse<AuditLog>> {
    const response = await this.api.get('/audit/logs', { params });
    return response.data;
  }

  async getAuditLogById(logId: string): Promise<AuditLog> {
    const response = await this.api.get(`/audit/logs/${logId}`);
    return response.data.data;
  }

  // Configuration Management
  async getSystemConfiguration(): Promise<SystemConfiguration> {
    const response = await this.api.get('/config/system');
    return response.data.data;
  }

  async updateSystemConfiguration(config: Partial<SystemConfiguration>): Promise<SystemConfiguration> {
    const response = await this.api.put('/config/system', config);
    return response.data.data;
  }

  async getBackupStatus(): Promise<any> {
    const response = await this.api.get('/system/backup/status');
    return response.data.data;
  }

  async triggerBackup(type: 'full' | 'incremental' = 'incremental'): Promise<any> {
    const response = await this.api.post('/system/backup/trigger', { type });
    return response.data.data;
  }

  // Reports & Analytics
  async generateUserReport(params: {
    startDate: string;
    endDate: string;
    format?: 'json' | 'csv' | 'pdf';
  }): Promise<Blob | any> {
    const response = await this.api.post('/reports/users', params, {
      responseType: params.format === 'json' ? 'json' : 'blob'
    });
    return response.data;
  }

  async generateSecurityReport(params: {
    startDate: string;
    endDate: string;
    format?: 'json' | 'csv' | 'pdf';
  }): Promise<Blob | any> {
    const response = await this.api.post('/reports/security', params, {
      responseType: params.format === 'json' ? 'json' : 'blob'
    });
    return response.data;
  }

  async generateSystemReport(params: {
    startDate: string;
    endDate: string;
    format?: 'json' | 'csv' | 'pdf';
  }): Promise<Blob | any> {
    const response = await this.api.post('/reports/system', params, {
      responseType: params.format === 'json' ? 'json' : 'blob'
    });
    return response.data;
  }

  // Notifications
  async getNotifications(params?: {
    page?: number;
    limit?: number;
    type?: string;
    category?: string;
    read?: boolean;
    priority?: string;
  }): Promise<PaginatedResponse<any>> {
    const response = await this.api.get('/notifications', { params });
    return response.data;
  }

  async markNotificationAsRead(notificationId: string): Promise<void> {
    await this.api.post(`/notifications/${notificationId}/read`);
  }

  async markAllNotificationsAsRead(): Promise<void> {
    await this.api.post('/notifications/read-all');
  }

  async deleteNotification(notificationId: string): Promise<void> {
    await this.api.delete(`/notifications/${notificationId}`);
  }

  // Government API Integration
  async performGovernmentVerification(userId: string, verificationData: any): Promise<any> {
    const response = await this.api.post(`/verification/government/${userId}`, verificationData);
    return response.data.data;
  }

  async getVerificationHistory(userId: string): Promise<any[]> {
    const response = await this.api.get(`/verification/history/${userId}`);
    return response.data.data;
  }

  // System Maintenance
  async enableMaintenanceMode(message?: string, estimatedDuration?: number): Promise<void> {
    await this.api.post('/system/maintenance/enable', { message, estimatedDuration });
  }

  async disableMaintenanceMode(): Promise<void> {
    await this.api.post('/system/maintenance/disable');
  }

  async restartService(serviceName: string): Promise<void> {
    await this.api.post(`/system/services/${serviceName}/restart`);
  }

  async getServiceStatus(): Promise<any[]> {
    const response = await this.api.get('/system/services/status');
    return response.data.data;
  }

  // Generic API method for custom requests
  async request<T = any>(config: AxiosRequestConfig): Promise<T> {
    const response = await this.api.request(config);
    return response.data;
  }
}

// Create singleton instance
const adminApiService = new AdminApiService();

export default adminApiService;

// Named exports for convenience
export {
  adminApiService as AdminAPI,
  AdminApiService
};