// API Configuration
export const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || 'https://api.digital-identity.gov.uk';
export const WS_URL = process.env.NEXT_PUBLIC_WS_URL || 'wss://api.digital-identity.gov.uk/ws';

// Firebase Configuration
export const FIREBASE_CONFIG = {
  apiKey: process.env.NEXT_PUBLIC_FIREBASE_API_KEY,
  authDomain: process.env.NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN,
  projectId: process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID,
  storageBucket: process.env.NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.NEXT_PUBLIC_FIREBASE_APP_ID,
};

// Feature Flags
export const FEATURES = {
  BIOMETRIC_AUTH: process.env.NEXT_PUBLIC_FEATURE_BIOMETRIC_AUTH === 'true',
  SOCIAL_LOGIN: process.env.NEXT_PUBLIC_FEATURE_SOCIAL_LOGIN === 'true',
  PWA: process.env.NEXT_PUBLIC_FEATURE_PWA === 'true',
  DARK_MODE: process.env.NEXT_PUBLIC_FEATURE_DARK_MODE === 'true',
  OFFLINE_MODE: process.env.NEXT_PUBLIC_FEATURE_OFFLINE_MODE === 'true',
  REAL_TIME_SYNC: process.env.NEXT_PUBLIC_FEATURE_REAL_TIME_SYNC === 'true',
  ANALYTICS: process.env.NEXT_PUBLIC_FEATURE_ANALYTICS === 'true',
  FRAUD_DETECTION: process.env.NEXT_PUBLIC_FEATURE_FRAUD_DETECTION === 'true',
  MULTI_LANGUAGE: process.env.NEXT_PUBLIC_FEATURE_MULTI_LANGUAGE === 'true',
  ACCESSIBILITY_ENHANCED: process.env.NEXT_PUBLIC_FEATURE_ACCESSIBILITY_ENHANCED === 'true',
};

// Security Configuration
export const SECURITY = {
  SESSION_TIMEOUT: parseInt(process.env.NEXT_PUBLIC_SESSION_TIMEOUT || '1800000'), // 30 minutes
  TOKEN_REFRESH_INTERVAL: parseInt(process.env.NEXT_PUBLIC_TOKEN_REFRESH_INTERVAL || '300000'), // 5 minutes
  MAX_LOGIN_ATTEMPTS: parseInt(process.env.NEXT_PUBLIC_MAX_LOGIN_ATTEMPTS || '5'),
  LOCKOUT_DURATION: parseInt(process.env.NEXT_PUBLIC_LOCKOUT_DURATION || '900000'), // 15 minutes
  PASSWORD_MIN_LENGTH: parseInt(process.env.NEXT_PUBLIC_PASSWORD_MIN_LENGTH || '8'),
  ENABLE_CSP: process.env.NEXT_PUBLIC_ENABLE_CSP === 'true',
  ENABLE_HSTS: process.env.NEXT_PUBLIC_ENABLE_HSTS === 'true',
  CERTIFICATE_PINNING: process.env.NEXT_PUBLIC_CERTIFICATE_PINNING === 'true',
};

// Performance Configuration
export const PERFORMANCE = {
  CDN_BASE_URL: process.env.NEXT_PUBLIC_CDN_BASE_URL || 'https://cdn.digital-identity.gov.uk',
  CACHE_DURATION: parseInt(process.env.NEXT_PUBLIC_CACHE_DURATION || '300000'), // 5 minutes
  API_TIMEOUT: parseInt(process.env.NEXT_PUBLIC_API_TIMEOUT || '30000'), // 30 seconds
  RETRY_ATTEMPTS: parseInt(process.env.NEXT_PUBLIC_RETRY_ATTEMPTS || '3'),
  VIRTUAL_SCROLL_THRESHOLD: parseInt(process.env.NEXT_PUBLIC_VIRTUAL_SCROLL_THRESHOLD || '100'),
};

// Monitoring Configuration
export const MONITORING = {
  SENTRY_DSN: process.env.NEXT_PUBLIC_SENTRY_DSN,
  SENTRY_ENVIRONMENT: process.env.NEXT_PUBLIC_SENTRY_ENVIRONMENT || 'production',
  GOOGLE_ANALYTICS_ID: process.env.NEXT_PUBLIC_GOOGLE_ANALYTICS_ID,
  HOTJAR_ID: process.env.NEXT_PUBLIC_HOTJAR_ID,
  ENABLE_PERFORMANCE_MONITORING: process.env.NEXT_PUBLIC_ENABLE_PERFORMANCE_MONITORING === 'true',
};

// Government Service Endpoints
export const GOV_SERVICES = {
  DVLA: process.env.NEXT_PUBLIC_DVLA_ENDPOINT || 'https://dvla.digital-identity.gov.uk',
  HMRC: process.env.NEXT_PUBLIC_HMRC_ENDPOINT || 'https://hmrc.digital-identity.gov.uk',
  NHS: process.env.NEXT_PUBLIC_NHS_ENDPOINT || 'https://nhs.digital-identity.gov.uk',
  DWP: process.env.NEXT_PUBLIC_DWP_ENDPOINT || 'https://dwp.digital-identity.gov.uk',
  HOME_OFFICE: process.env.NEXT_PUBLIC_HOME_OFFICE_ENDPOINT || 'https://homeoffice.digital-identity.gov.uk',
  COMPANIES_HOUSE: process.env.NEXT_PUBLIC_COMPANIES_HOUSE_ENDPOINT || 'https://companieshouse.digital-identity.gov.uk',
};

// Application Constants
export const APP_CONFIG = {
  NAME: 'UK Digital Identity Portal',
  VERSION: '2.0.0',
  DESCRIPTION: 'Secure access to government services',
  SUPPORT_EMAIL: 'support@digital-identity.gov.uk',
  SUPPORT_PHONE: '+44 300 123 1234',
  TERMS_URL: process.env.NEXT_PUBLIC_TERMS_URL || 'https://digital-identity.gov.uk/terms',
  PRIVACY_URL: process.env.NEXT_PUBLIC_PRIVACY_URL || 'https://digital-identity.gov.uk/privacy',
  ACCESSIBILITY_URL: process.env.NEXT_PUBLIC_ACCESSIBILITY_URL || 'https://digital-identity.gov.uk/accessibility',
  HELP_URL: process.env.NEXT_PUBLIC_HELP_URL || 'https://help.digital-identity.gov.uk',
};

// Localization
export const LOCALES = {
  DEFAULT: 'en-GB',
  SUPPORTED: ['en-GB', 'cy-GB'],
  FALLBACK: 'en-GB',
};

// Credential Types
export const CREDENTIAL_TYPES = {
  PASSPORT: 'passport',
  DRIVING_LICENSE: 'driving_license',
  NATIONAL_ID: 'national_id',
  BIRTH_CERTIFICATE: 'birth_certificate',
  UTILITY_BILL: 'utility_bill',
  BANK_STATEMENT: 'bank_statement',
  OTHER: 'other',
} as const;

// Service Categories
export const SERVICE_CATEGORIES = {
  GOVERNMENT: 'government',
  HEALTHCARE: 'healthcare',
  FINANCIAL: 'financial',
  EDUCATION: 'education',
  TRANSPORT: 'transport',
  OTHER: 'other',
} as const;

// Verification Levels
export const VERIFICATION_LEVELS = {
  NONE: 'none',
  BASIC: 'basic',
  ENHANCED: 'enhanced',
  ENHANCED_PLUS: 'enhanced_plus',
} as const;

// Theme Colors
export const THEME_COLORS = {
  GOVERNMENT: {
    PRIMARY: '#1976d2',
    SECONDARY: '#dc004e',
    SUCCESS: '#2e7d32',
    WARNING: '#ed6c02',
    ERROR: '#d32f2f',
    INFO: '#0288d1',
  },
  ACCESSIBLE: {
    PRIMARY: '#0066cc',
    SECONDARY: '#cc0000',
    SUCCESS: '#006600',
    WARNING: '#ff6600',
    ERROR: '#cc0000',
    INFO: '#0066cc',
  },
  HIGH_CONTRAST: {
    PRIMARY: '#000000',
    SECONDARY: '#ffffff',
    SUCCESS: '#00ff00',
    WARNING: '#ffff00',
    ERROR: '#ff0000',
    INFO: '#0000ff',
  },
} as const;

// File Upload Limits
export const UPLOAD_LIMITS = {
  MAX_FILE_SIZE: parseInt(process.env.NEXT_PUBLIC_MAX_FILE_SIZE || '10485760'), // 10MB
  ALLOWED_TYPES: ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'],
  MAX_FILES: parseInt(process.env.NEXT_PUBLIC_MAX_FILES || '5'),
} as const;

// Pagination Defaults
export const PAGINATION = {
  DEFAULT_PAGE_SIZE: 10,
  PAGE_SIZE_OPTIONS: [5, 10, 25, 50, 100],
  MAX_PAGE_SIZE: 100,
} as const;

// Date Formats
export const DATE_FORMATS = {
  DISPLAY: 'dd/MM/yyyy',
  DISPLAY_WITH_TIME: 'dd/MM/yyyy HH:mm',
  API: 'yyyy-MM-dd',
  API_WITH_TIME: 'yyyy-MM-dd\'T\'HH:mm:ss.SSSXXX',
} as const;

// Regular Expressions
export const REGEX_PATTERNS = {
  EMAIL: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  UK_PHONE: /^(\+44|0)[1-9]\d{8,9}$/,
  UK_POSTCODE: /^[A-Z]{1,2}\d[A-Z\d]? ?\d[A-Z]{2}$/i,
  PASSWORD_STRONG: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
  NATIONAL_INSURANCE: /^[A-CEGHJ-PR-TW-Z]{1}[A-CEGHJ-NPR-TW-Z]{1}[0-9]{6}[A-D]{1}$/i,
} as const;

// Error Messages
export const ERROR_MESSAGES = {
  NETWORK_ERROR: 'Network error. Please check your connection and try again.',
  UNAUTHORIZED: 'You are not authorized to perform this action.',
  SESSION_EXPIRED: 'Your session has expired. Please log in again.',
  VALIDATION_ERROR: 'Please check your input and try again.',
  SERVER_ERROR: 'A server error occurred. Please try again later.',
  FILE_TOO_LARGE: 'File size exceeds the maximum limit.',
  INVALID_FILE_TYPE: 'File type is not supported.',
  BIOMETRIC_NOT_SUPPORTED: 'Biometric authentication is not supported on this device.',
  LOCATION_NOT_AVAILABLE: 'Location services are not available.',
} as const;

// Success Messages
export const SUCCESS_MESSAGES = {
  LOGIN_SUCCESS: 'Successfully logged in.',
  REGISTRATION_SUCCESS: 'Account created successfully. Please verify your email.',
  PROFILE_UPDATED: 'Profile updated successfully.',
  PASSWORD_CHANGED: 'Password changed successfully.',
  CREDENTIAL_ADDED: 'Credential added successfully.',
  CREDENTIAL_VERIFIED: 'Credential verified successfully.',
  SETTINGS_SAVED: 'Settings saved successfully.',
  LOGOUT_SUCCESS: 'Successfully logged out.',
} as const;