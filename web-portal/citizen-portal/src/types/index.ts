export interface User {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  phoneNumber?: string;
  dateOfBirth?: string;
  address?: {
    street: string;
    city: string;
    postcode: string;
    country: string;
  };
  verificationLevel: 'none' | 'basic' | 'enhanced' | 'enhanced_plus';
  enrolledServices: string[];
  twoFactorEnabled: boolean;
  biometricEnabled: boolean;
  lastLogin?: string;
  createdAt: string;
  updatedAt: string;
}

export interface Credential {
  id: string;
  type: 'passport' | 'driving_license' | 'national_id' | 'birth_certificate' | 'utility_bill' | 'bank_statement' | 'other';
  issuer: string;
  issuedDate: string;
  expiryDate?: string;
  status: 'pending' | 'verified' | 'expired' | 'revoked';
  verificationLevel: 'basic' | 'enhanced' | 'enhanced_plus';
  data: Record<string, any>;
  metadata: {
    uploadedAt: string;
    verifiedAt?: string;
    verifiedBy?: string;
    fileSize?: number;
    fileName?: string;
  };
}

export interface Service {
  id: string;
  name: string;
  description: string;
  provider: string;
  category: 'government' | 'healthcare' | 'financial' | 'education' | 'transport' | 'other';
  requiredVerificationLevel: 'none' | 'basic' | 'enhanced' | 'enhanced_plus';
  isActive: boolean;
  accessUrl?: string;
  iconUrl?: string;
  lastUsed?: string;
}

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
  timestamp: string;
}

export interface LoginCredentials {
  email: string;
  password: string;
  rememberMe?: boolean;
  twoFactorCode?: string;
}

export interface RegisterData {
  email: string;
  password: string;
  confirmPassword: string;
  firstName: string;
  lastName: string;
  phoneNumber?: string;
  dateOfBirth?: string;
  agreeToTerms: boolean;
  agreeToPrivacy: boolean;
}

export interface VerificationData {
  type: 'email' | 'phone' | 'document';
  code?: string;
  documentType?: string;
  documentFile?: File;
}

export interface NotificationPreferences {
  email: boolean;
  sms: boolean;
  push: boolean;
  categories: {
    security: boolean;
    services: boolean;
    updates: boolean;
    marketing: boolean;
  };
}

export interface SecuritySettings {
  twoFactorEnabled: boolean;
  biometricEnabled: boolean;
  sessionTimeout: number;
  loginNotifications: boolean;
  deviceTrust: boolean;
}

export interface Activity {
  id: string;
  type: 'login' | 'logout' | 'credential_added' | 'service_access' | 'profile_update' | 'security_change';
  description: string;
  timestamp: string;
  ipAddress?: string;
  deviceInfo?: string;
  location?: string;
  successful: boolean;
}

export interface DashboardStats {
  totalCredentials: number;
  verifiedCredentials: number;
  activeServices: number;
  recentActivities: number;
  securityScore: number;
  verificationProgress: number;
}

export interface Theme {
  mode: 'light' | 'dark' | 'system';
  colorScheme: 'default' | 'government' | 'accessible' | 'high-contrast';
  primaryColor: string;
  secondaryColor: string;
  fontSize: 'small' | 'medium' | 'large';
  reducedMotion: boolean;
  highContrast: boolean;
}

export interface FormErrors {
  [key: string]: string | undefined;
}

export interface ValidationRule {
  required?: boolean;
  minLength?: number;
  maxLength?: number;
  pattern?: RegExp;
  custom?: (value: any) => string | undefined;
}

export interface UploadProgress {
  loaded: number;
  total: number;
  percentage: number;
}

export interface FilterOptions {
  search?: string;
  category?: string;
  status?: string;
  dateRange?: {
    from: string;
    to: string;
  };
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

export interface PaginationInfo {
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
}

export interface WebSocketMessage {
  type: 'notification' | 'update' | 'sync' | 'error';
  data: any;
  timestamp: string;
}

export interface OfflineData {
  credentials: Credential[];
  user: User;
  lastSync: string;
}

export interface BiometricOptions {
  preferred: 'fingerprint' | 'face' | 'voice';
  fallbackToPassword: boolean;
  requireForSensitiveActions: boolean;
}

export interface AccessibilitySettings {
  screenReaderMode: boolean;
  keyboardNavigation: boolean;
  highContrast: boolean;
  largeText: boolean;
  reduceMotion: boolean;
  voiceAnnouncements: boolean;
}

export interface GovernmentService {
  id: string;
  name: string;
  department: string;
  description: string;
  category: 'tax' | 'healthcare' | 'benefits' | 'driving' | 'passport' | 'voting' | 'other';
  requiredDocuments: string[];
  processingTime: string;
  fees?: {
    amount: number;
    currency: string;
    description: string;
  };
  eligibility: string[];
  onlineAvailable: boolean;
  appointmentRequired: boolean;
  contactInfo: {
    phone?: string;
    email?: string;
    website?: string;
    address?: string;
  };
}

export interface ServiceApplication {
  id: string;
  serviceId: string;
  status: 'draft' | 'submitted' | 'processing' | 'approved' | 'rejected' | 'completed';
  submittedAt?: string;
  completedAt?: string;
  referenceNumber?: string;
  documents: string[];
  paymentStatus?: 'pending' | 'paid' | 'failed' | 'refunded';
  notes?: string;
}