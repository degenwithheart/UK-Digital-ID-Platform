/// Core Error Handling System
/// 
/// Comprehensive error handling with categorization, logging, and recovery strategies

import 'dart:io';
import 'package:dio/dio.dart';
import 'package:firebase_crashlytics/firebase_crashlytics.dart';
import 'package:logger/logger.dart';

/// Base application exception
abstract class AppException implements Exception {
  final String message;
  final String? code;
  final dynamic originalError;
  final StackTrace? stackTrace;
  final DateTime timestamp;
  final Map<String, dynamic>? context;

  const AppException(
    this.message, {
    this.code,
    this.originalError,
    this.stackTrace,
    Map<String, dynamic>? context,
  }) : 
    timestamp = DateTime.now(),
    context = context;

  @override
  String toString() {
    return 'AppException: $message${code != null ? ' (Code: $code)' : ''}';
  }

  /// Convert to user-friendly message
  String get userMessage => message;

  /// Check if error is recoverable
  bool get isRecoverable => true;

  /// Get error severity
  ErrorSeverity get severity => ErrorSeverity.medium;
}

/// Network related errors
class NetworkException extends AppException {
  final int? statusCode;
  final String? endpoint;

  const NetworkException(
    String message, {
    String? code,
    this.statusCode,
    this.endpoint,
    dynamic originalError,
    StackTrace? stackTrace,
    Map<String, dynamic>? context,
  }) : super(
    message,
    code: code,
    originalError: originalError,
    stackTrace: stackTrace,
    context: context,
  );

  @override
  String get userMessage {
    if (statusCode == 401) return 'Please log in again';
    if (statusCode == 403) return 'Access denied';
    if (statusCode == 404) return 'Service not found';
    if (statusCode == 429) return 'Too many requests, please try again later';
    if (statusCode != null && statusCode! >= 500) return 'Server error, please try again';
    return 'Network error, please check your connection';
  }

  @override
  bool get isRecoverable => statusCode != 401 && statusCode != 403;

  @override
  ErrorSeverity get severity {
    if (statusCode == 401 || statusCode == 403) return ErrorSeverity.high;
    if (statusCode != null && statusCode! >= 500) return ErrorSeverity.high;
    return ErrorSeverity.medium;
  }
}

/// Authentication related errors
class AuthenticationException extends AppException {
  final AuthErrorType errorType;

  const AuthenticationException(
    String message, {
    String? code,
    required this.errorType,
    dynamic originalError,
    StackTrace? stackTrace,
    Map<String, dynamic>? context,
  }) : super(
    message,
    code: code,
    originalError: originalError,
    stackTrace: stackTrace,
    context: context,
  );

  @override
  String get userMessage {
    switch (errorType) {
      case AuthErrorType.invalidCredentials:
        return 'Invalid email or password';
      case AuthErrorType.accountLocked:
        return 'Account temporarily locked due to multiple failed attempts';
      case AuthErrorType.tokenExpired:
        return 'Session expired, please log in again';
      case AuthErrorType.biometricFailed:
        return 'Biometric authentication failed';
      case AuthErrorType.deviceNotSupported:
        return 'This device is not supported';
      case AuthErrorType.networkError:
        return 'Authentication server unavailable';
    }
  }

  @override
  bool get isRecoverable => errorType != AuthErrorType.deviceNotSupported;

  @override
  ErrorSeverity get severity => ErrorSeverity.high;
}

/// Validation related errors
class ValidationException extends AppException {
  final Map<String, List<String>> fieldErrors;

  const ValidationException(
    String message, {
    String? code,
    this.fieldErrors = const {},
    dynamic originalError,
    StackTrace? stackTrace,
    Map<String, dynamic>? context,
  }) : super(
    message,
    code: code,
    originalError: originalError,
    stackTrace: stackTrace,
    context: context,
  );

  @override
  String get userMessage => fieldErrors.isNotEmpty 
      ? fieldErrors.values.first.first 
      : message;

  @override
  ErrorSeverity get severity => ErrorSeverity.low;
}

/// Business logic errors
class BusinessException extends AppException {
  final BusinessErrorType errorType;

  const BusinessException(
    String message, {
    String? code,
    required this.errorType,
    dynamic originalError,
    StackTrace? stackTrace,
    Map<String, dynamic>? context,
  }) : super(
    message,
    code: code,
    originalError: originalError,
    stackTrace: stackTrace,
    context: context,
  );

  @override
  String get userMessage {
    switch (errorType) {
      case BusinessErrorType.insufficientFunds:
        return 'Insufficient funds for this transaction';
      case BusinessErrorType.invalidDocument:
        return 'Document verification failed';
      case BusinessErrorType.fraudDetected:
        return 'Suspicious activity detected, please contact support';
      case BusinessErrorType.limitExceeded:
        return 'Transaction limit exceeded';
      case BusinessErrorType.serviceUnavailable:
        return 'Service temporarily unavailable';
    }
  }

  @override
  bool get isRecoverable => errorType != BusinessErrorType.fraudDetected;

  @override
  ErrorSeverity get severity {
    if (errorType == BusinessErrorType.fraudDetected) return ErrorSeverity.critical;
    return ErrorSeverity.medium;
  }
}

/// Storage related errors
class StorageException extends AppException {
  final StorageErrorType errorType;

  const StorageException(
    String message, {
    String? code,
    required this.errorType,
    dynamic originalError,
    StackTrace? stackTrace,
    Map<String, dynamic>? context,
  }) : super(
    message,
    code: code,
    originalError: originalError,
    stackTrace: stackTrace,
    context: context,
  );

  @override
  String get userMessage {
    switch (errorType) {
      case StorageErrorType.insufficientSpace:
        return 'Insufficient storage space';
      case StorageErrorType.permissionDenied:
        return 'Storage permission denied';
      case StorageErrorType.corruptedData:
        return 'Data corruption detected';
      case StorageErrorType.encryptionFailed:
        return 'Data encryption failed';
    }
  }

  @override
  ErrorSeverity get severity {
    if (errorType == StorageErrorType.corruptedData) return ErrorSeverity.high;
    return ErrorSeverity.medium;
  }
}

/// System related errors
class SystemException extends AppException {
  final SystemErrorType errorType;

  const SystemException(
    String message, {
    String? code,
    required this.errorType,
    dynamic originalError,
    StackTrace? stackTrace,
    Map<String, dynamic>? context,
  }) : super(
    message,
    code: code,
    originalError: originalError,
    stackTrace: stackTrace,
    context: context,
  );

  @override
  String get userMessage {
    switch (errorType) {
      case SystemErrorType.memoryLow:
        return 'Device memory is low, please close other apps';
      case SystemErrorType.batteryLow:
        return 'Battery is too low for biometric operations';
      case SystemErrorType.deviceJailbroken:
        return 'This app cannot run on jailbroken devices';
      case SystemErrorType.osNotSupported:
        return 'Operating system not supported';
    }
  }

  @override
  bool get isRecoverable => 
      errorType != SystemErrorType.deviceJailbroken && 
      errorType != SystemErrorType.osNotSupported;

  @override
  ErrorSeverity get severity => ErrorSeverity.high;
}

/// Error Handler Service
class ErrorHandler {
  static final Logger _logger = Logger(
    printer: PrettyPrinter(
      methodCount: 2,
      errorMethodCount: 8,
      lineLength: 120,
      colors: true,
      printEmojis: true,
    ),
  );

  /// Handle and process errors
  static Future<void> handleError(
    dynamic error, {
    StackTrace? stackTrace,
    Map<String, dynamic>? context,
    bool reportToCrashlytics = true,
    bool showToUser = true,
  }) async {
    final appError = _convertToAppException(error, stackTrace, context);
    
    // Log the error
    await _logError(appError);
    
    // Report to crashlytics if enabled
    if (reportToCrashlytics && appError.severity.index >= ErrorSeverity.medium.index) {
      await _reportToCrashlytics(appError);
    }
    
    // Store error for analytics
    await _storeErrorAnalytics(appError);
    
    // Show to user if needed
    if (showToUser) {
      await _showErrorToUser(appError);
    }
  }

  /// Convert any error to AppException
  static AppException _convertToAppException(
    dynamic error,
    StackTrace? stackTrace,
    Map<String, dynamic>? context,
  ) {
    if (error is AppException) return error;
    
    if (error is DioError) {
      return NetworkException(
        error.message,
        statusCode: error.response?.statusCode,
        endpoint: error.requestOptions.path,
        originalError: error,
        stackTrace: stackTrace,
        context: context,
      );
    }
    
    if (error is SocketException) {
      return NetworkException(
        'Network connection failed',
        originalError: error,
        stackTrace: stackTrace,
        context: context,
      );
    }
    
    if (error is FormatException) {
      return ValidationException(
        'Invalid data format: ${error.message}',
        originalError: error,
        stackTrace: stackTrace,
        context: context,
      );
    }
    
    return SystemException(
      error?.toString() ?? 'Unknown error occurred',
      errorType: SystemErrorType.unknown,
      originalError: error,
      stackTrace: stackTrace,
      context: context,
    );
  }

  /// Log error with appropriate level
  static Future<void> _logError(AppException error) async {
    final logMessage = '''
Error: ${error.message}
Code: ${error.code ?? 'N/A'}
Type: ${error.runtimeType}
Severity: ${error.severity}
Timestamp: ${error.timestamp}
Context: ${error.context}
''';

    switch (error.severity) {
      case ErrorSeverity.low:
        _logger.i(logMessage);
        break;
      case ErrorSeverity.medium:
        _logger.w(logMessage);
        break;
      case ErrorSeverity.high:
        _logger.e(logMessage);
        break;
      case ErrorSeverity.critical:
        _logger.f(logMessage);
        break;
    }
  }

  /// Report to Firebase Crashlytics
  static Future<void> _reportToCrashlytics(AppException error) async {
    try {
      await FirebaseCrashlytics.instance.recordError(
        error,
        error.stackTrace,
        information: [
          DiagnosticsProperty('errorType', error.runtimeType.toString()),
          DiagnosticsProperty('code', error.code),
          DiagnosticsProperty('severity', error.severity.toString()),
          DiagnosticsProperty('context', error.context),
        ],
        fatal: error.severity == ErrorSeverity.critical,
      );
    } catch (e) {
      _logger.e('Failed to report to Crashlytics: $e');
    }
  }

  /// Store error for analytics
  static Future<void> _storeErrorAnalytics(AppException error) async {
    // TODO: Implement error analytics storage
    // This could be stored in local database for later analysis
  }

  /// Show error to user
  static Future<void> _showErrorToUser(AppException error) async {
    // TODO: Implement user notification
    // This would typically show a snackbar, dialog, or toast
  }

  /// Get recovery actions for error
  static List<ErrorRecoveryAction> getRecoveryActions(AppException error) {
    final actions = <ErrorRecoveryAction>[];
    
    if (error is NetworkException) {
      actions.add(ErrorRecoveryAction.retry);
      actions.add(ErrorRecoveryAction.checkConnection);
    }
    
    if (error is AuthenticationException) {
      actions.add(ErrorRecoveryAction.login);
      actions.add(ErrorRecoveryAction.contactSupport);
    }
    
    if (error is ValidationException) {
      actions.add(ErrorRecoveryAction.correctInput);
    }
    
    if (error is StorageException && 
        error.errorType == StorageErrorType.insufficientSpace) {
      actions.add(ErrorRecoveryAction.freeSpace);
    }
    
    // Always offer contact support for high/critical errors
    if (error.severity.index >= ErrorSeverity.high.index) {
      actions.add(ErrorRecoveryAction.contactSupport);
    }
    
    return actions;
  }
}

/// Error types and enums
enum ErrorSeverity { low, medium, high, critical }

enum AuthErrorType {
  invalidCredentials,
  accountLocked,
  tokenExpired,
  biometricFailed,
  deviceNotSupported,
  networkError,
}

enum BusinessErrorType {
  insufficientFunds,
  invalidDocument,
  fraudDetected,
  limitExceeded,
  serviceUnavailable,
}

enum StorageErrorType {
  insufficientSpace,
  permissionDenied,
  corruptedData,
  encryptionFailed,
}

enum SystemErrorType {
  memoryLow,
  batteryLow,
  deviceJailbroken,
  osNotSupported,
  unknown,
}

enum ErrorRecoveryAction {
  retry,
  login,
  checkConnection,
  correctInput,
  freeSpace,
  contactSupport,
}

/// Error boundary mixin for widgets
mixin ErrorBoundaryMixin {
  void handleWidgetError(dynamic error, StackTrace stackTrace) {
    ErrorHandler.handleError(
      error,
      stackTrace: stackTrace,
      context: {'widget': runtimeType.toString()},
    );
  }
}

/// Extension for handling Future errors
extension FutureErrorHandler<T> on Future<T> {
  Future<T> handleError({
    Map<String, dynamic>? context,
    bool showToUser = true,
  }) {
    return catchError((error, stackTrace) async {
      await ErrorHandler.handleError(
        error,
        stackTrace: stackTrace,
        context: context,
        showToUser: showToUser,
      );
      rethrow;
    });
  }
}