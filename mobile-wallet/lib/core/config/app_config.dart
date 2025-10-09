/// App Configuration
/// 
/// Central configuration for the UK Digital ID Wallet application
/// Handles environment-specific settings, API endpoints, and feature flags

class AppConfig {
  // App Information
  static const String appName = 'UK Digital ID Wallet';
  static const String appVersion = '2.0.0';
  static const int buildNumber = 10;
  static const String packageName = 'uk.gov.digitalidentity.wallet';
  
  // Environment Configuration
  static const Environment environment = Environment.production; // Change for different builds
  
  // API Configuration
  static String get baseUrl {
    switch (environment) {
      case Environment.development:
        return 'https://dev-api.digital-identity.gov.uk';
      case Environment.staging:
        return 'https://staging-api.digital-identity.gov.uk';
      case Environment.production:
        return 'https://api.digital-identity.gov.uk';
    }
  }
  
  // Core Services URLs
  static String get authServiceUrl => '$baseUrl/auth';
  static String get walletServiceUrl => '$baseUrl/wallet';
  static String get credentialsServiceUrl => '$baseUrl/credentials';
  static String get verificationServiceUrl => '$baseUrl/verification';
  static String get fraudDetectionUrl => '$baseUrl/fraud-detection';
  static String get auditServiceUrl => '$baseUrl/audit';
  
  // WebSocket URLs
  static String get wsBaseUrl => baseUrl.replaceAll('https://', 'wss://');
  static String get notificationSocketUrl => '$wsBaseUrl/notifications';
  static String get fraudAlertSocketUrl => '$wsBaseUrl/fraud-alerts';
  
  // Security Configuration
  static const String jwtIssuer = 'uk.gov.digitalidentity';
  static const Duration tokenExpiration = Duration(hours: 24);
  static const Duration refreshTokenExpiration = Duration(days: 30);
  static const int maxLoginAttempts = 3;
  static const Duration lockoutDuration = Duration(minutes: 15);
  
  // Encryption Configuration
  static const String encryptionAlgorithm = 'AES-256-GCM';
  static const int keyLength = 256;
  static const int ivLength = 96;
  static const int tagLength = 128;
  
  // Biometric Configuration
  static const Duration biometricTimeout = Duration(seconds: 30);
  static const int maxBiometricAttempts = 3;
  static const bool requireBiometricForHighValue = true;
  static const double highValueThreshold = 1000.0;
  
  // Network Configuration
  static const Duration connectionTimeout = Duration(seconds: 30);
  static const Duration receiveTimeout = Duration(seconds: 60);
  static const Duration sendTimeout = Duration(seconds: 30);
  static const int maxRetries = 3;
  static const Duration retryDelay = Duration(seconds: 2);
  
  // Cache Configuration
  static const Duration cacheExpiration = Duration(hours: 6);
  static const int maxCacheSize = 100; // MB
  static const bool enableOfflineMode = true;
  
  // Document Verification
  static const List<String> supportedDocumentTypes = [
    'passport',
    'driving_license',
    'national_id',
    'birth_certificate',
    'proof_of_address',
  ];
  
  static const Map<String, double> documentQualityThresholds = {
    'minimum_resolution': 1080.0,
    'brightness_min': 0.3,
    'brightness_max': 0.9,
    'blur_threshold': 0.1,
    'glare_threshold': 0.2,
  };
  
  // QR Code Configuration
  static const double qrCodeSize = 200.0;
  static const Duration qrCodeExpiration = Duration(minutes: 5);
  static const String qrCodeErrorCorrection = 'M'; // L, M, Q, H
  
  // Fraud Detection Configuration
  static const Duration fraudCheckTimeout = Duration(seconds: 5);
  static const double fraudThreshold = 0.7;
  static const bool enableRealtimeFraudDetection = true;
  
  // Notification Configuration
  static const bool enablePushNotifications = true;
  static const bool enableInAppNotifications = true;
  static const Duration notificationTimeout = Duration(seconds: 10);
  
  // Feature Flags
  static const Map<String, bool> featureFlags = {
    'biometric_login': true,
    'face_recognition': true,
    'document_verification': true,
    'qr_code_sharing': true,
    'offline_mode': true,
    'dark_mode': true,
    'analytics': true,
    'crash_reporting': true,
    'performance_monitoring': true,
    'remote_config': true,
    'a_b_testing': false, // Disabled in production
    'debug_menu': false, // Disabled in production
  };
  
  // Analytics Configuration
  static const bool enableAnalytics = true;
  static const bool enableCrashlytics = true;
  static const bool enablePerformanceMonitoring = true;
  static const Duration sessionTimeout = Duration(minutes: 30);
  
  // Database Configuration
  static const String dbName = 'uk_digital_id_wallet.db';
  static const int dbVersion = 1;
  static const String hiveBoxName = 'wallet_data';
  
  // File Storage Configuration
  static const int maxFileSize = 10 * 1024 * 1024; // 10MB
  static const List<String> allowedImageFormats = ['jpg', 'jpeg', 'png', 'webp'];
  static const List<String> allowedDocumentFormats = ['pdf', 'jpg', 'jpeg', 'png'];
  
  // Accessibility Configuration
  static const bool enableAccessibility = true;
  static const double minFontScale = 0.8;
  static const double maxFontScale = 2.0;
  static const Duration accessibilityTimeout = Duration(seconds: 60);
  
  // Compliance Configuration
  static const bool gdprCompliance = true;
  static const Duration dataRetentionPeriod = Duration(days: 2555); // 7 years
  static const bool enableDataExport = true;
  static const bool enableDataDeletion = true;
  
  // Development Configuration
  static const bool enableLogging = true;
  static const LogLevel logLevel = environment == Environment.production 
      ? LogLevel.warning 
      : LogLevel.debug;
  
  // Rate Limiting
  static const Map<String, int> rateLimits = {
    'login_attempts_per_hour': 10,
    'verification_attempts_per_day': 5,
    'document_uploads_per_hour': 20,
    'api_calls_per_minute': 100,
  };
  
  // Device Security
  static const bool requireDevicePin = true;
  static const bool detectJailbreak = true;
  static const bool preventScreenshots = true;
  static const bool enableCertificatePinning = true;
  
  // Validation Rules
  static const Map<String, dynamic> validationRules = {
    'password_min_length': 8,
    'password_require_uppercase': true,
    'password_require_lowercase': true,
    'password_require_numbers': true,
    'password_require_symbols': true,
    'email_validation_enabled': true,
    'phone_validation_enabled': true,
  };
  
  // UI Configuration
  static const Duration animationDuration = Duration(milliseconds: 300);
  static const Duration splashScreenDuration = Duration(seconds: 3);
  static const double borderRadius = 12.0;
  static const double elevation = 4.0;
  
  // Testing Configuration
  static const bool enableTestMode = false;
  static const String testUserEmail = 'test@digital-identity.gov.uk';
  static const String testUserPassword = 'TestPass123!';
}

enum Environment {
  development,
  staging,
  production,
}

enum LogLevel {
  debug,
  info,
  warning,
  error,
}