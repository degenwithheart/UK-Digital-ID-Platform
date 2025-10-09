/// Security Service
/// 
/// Comprehensive security implementation with encryption, biometric authentication,
/// device security checks, and secure storage management

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';
import 'package:device_info_plus/device_info_plus.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:root_jailbreak_sniffer/rjsniffer.dart';
import '../config/app_config.dart';
import '../error/error_handler.dart';

/// Security Service Implementation
class SecurityService {
  static SecurityService? _instance;
  static SecurityService get instance => _instance ??= SecurityService._();
  SecurityService._();

  final LocalAuthentication _localAuth = LocalAuthentication();
  final DeviceInfoPlugin _deviceInfo = DeviceInfoPlugin();
  
  static const FlutterSecureStorage _secureStorage = FlutterSecureStorage(
    aOptions: AndroidOptions(
      encryptedSharedPreferences: true,
      sharedPreferencesName: 'uk_digital_id_secure_prefs',
      preferencesKeyPrefix: 'uk_gov_',
    ),
    iOptions: IOSOptions(
      groupId: 'group.uk.gov.digitalidentity',
      accountName: 'UK Digital Identity',
      accessibility: IOSAccessibility.first_unlock_this_device,
    ),
  );

  late final Encrypter _encrypter;
  late final IV _iv;
  String? _masterKey;
  bool _isInitialized = false;

  /// Initialize security service
  Future<void> initialize() async {
    try {
      if (_isInitialized) return;

      // Perform security checks
      await _performSecurityChecks();
      
      // Initialize encryption
      await _initializeEncryption();
      
      // Setup biometric authentication
      await _setupBiometrics();
      
      _isInitialized = true;
    } catch (error, stackTrace) {
      throw SystemException(
        'Failed to initialize security service: ${error.toString()}',
        errorType: SystemErrorType.unknown,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Perform comprehensive security checks
  Future<void> _performSecurityChecks() async {
    // Check for jailbreak/root
    if (AppConfig.detectJailbreak) {
      final isJailbroken = await RjSniffer.amICompromised() ?? false;
      if (isJailbroken) {
        throw SystemException(
          'Device is jailbroken/rooted',
          errorType: SystemErrorType.deviceJailbroken,
        );
      }
    }

    // Check device compatibility
    await _checkDeviceCompatibility();
    
    // Verify app integrity
    await _verifyAppIntegrity();
    
    // Check for debugging tools
    await _checkDebuggingTools();
  }

  /// Check device compatibility
  Future<void> _checkDeviceCompatibility() async {
    final deviceInfo = await _deviceInfo.deviceInfo;
    
    if (deviceInfo is AndroidDeviceInfo) {
      // Check minimum Android version
      if (deviceInfo.version.sdkInt < 23) { // Android 6.0
        throw SystemException(
          'Android version not supported',
          errorType: SystemErrorType.osNotSupported,
        );
      }
      
      // Check for hardware security features
      if (!deviceInfo.isPhysicalDevice) {
        throw SystemException(
          'Emulators are not supported',
          errorType: SystemErrorType.deviceNotSupported,
        );
      }
    } else if (deviceInfo is IosDeviceInfo) {
      // Check minimum iOS version
      final version = deviceInfo.systemVersion.split('.').first;
      if (int.parse(version) < 12) {
        throw SystemException(
          'iOS version not supported',
          errorType: SystemErrorType.osNotSupported,
        );
      }
    }
  }

  /// Verify app integrity
  Future<void> _verifyAppIntegrity() async {
    final packageInfo = await PackageInfo.fromPlatform();
    
    // Verify package name
    if (packageInfo.packageName != AppConfig.packageName) {
      throw SystemException(
        'App integrity check failed',
        errorType: SystemErrorType.unknown,
      );
    }
    
    // Additional integrity checks can be added here
    // such as certificate pinning verification
  }

  /// Check for debugging tools
  Future<void> _checkDebuggingTools() async {
    // Check for debugging in release mode
    bool inDebugMode = false;
    assert(inDebugMode = true);
    
    if (inDebugMode && AppConfig.environment == Environment.production) {
      throw SystemException(
        'Debug mode detected in production',
        errorType: SystemErrorType.unknown,
      );
    }
  }

  /// Initialize encryption system
  Future<void> _initializeEncryption() async {
    // Get or generate master key
    _masterKey = await _getMasterKey();
    if (_masterKey == null) {
      _masterKey = await _generateMasterKey();
      await _storeMasterKey(_masterKey!);
    }

    // Initialize encrypter
    final key = Key.fromSecureRandom(32);
    _encrypter = Encrypter(AES(key));
    _iv = IV.fromSecureRandom(16);
  }

  /// Setup biometric authentication
  Future<void> _setupBiometrics() async {
    final isAvailable = await _localAuth.canCheckBiometrics;
    if (!isAvailable) return;

    final availableBiometrics = await _localAuth.getAvailableBiometrics();
    
    // Store available biometric types
    await _secureStorage.write(
      key: 'available_biometrics',
      value: json.encode(availableBiometrics.map((e) => e.name).toList()),
    );
  }

  /// Authenticate with biometrics
  Future<bool> authenticateWithBiometrics({
    required String reason,
    bool fallbackToDeviceCredentials = true,
  }) async {
    try {
      if (!_isInitialized) await initialize();

      final isAvailable = await _localAuth.canCheckBiometrics;
      if (!isAvailable) {
        throw AuthenticationException(
          'Biometric authentication not available',
          errorType: AuthErrorType.biometricFailed,
        );
      }

      final result = await _localAuth.authenticate(
        localizedFallbackTitle: 'Use Device Password',
        biometricOnly: !fallbackToDeviceCredentials,
        options: const AuthenticationOptions(
          biometricOnly: false,
          stickyAuth: true,
        ),
      );

      return result;
    } catch (error, stackTrace) {
      if (error is PlatformException) {
        switch (error.code) {
          case 'NotAvailable':
            throw AuthenticationException(
              'Biometric authentication not available',
              errorType: AuthErrorType.biometricFailed,
              originalError: error,
              stackTrace: stackTrace,
            );
          case 'NotEnrolled':
            throw AuthenticationException(
              'No biometrics enrolled on device',
              errorType: AuthErrorType.biometricFailed,
              originalError: error,
              stackTrace: stackTrace,
            );
          case 'LockedOut':
            throw AuthenticationException(
              'Biometric authentication locked out',
              errorType: AuthErrorType.accountLocked,
              originalError: error,
              stackTrace: stackTrace,
            );
          default:
            throw AuthenticationException(
              'Biometric authentication failed',
              errorType: AuthErrorType.biometricFailed,
              originalError: error,
              stackTrace: stackTrace,
            );
        }
      }
      rethrow;
    }
  }

  /// Check if biometric authentication is available
  Future<bool> isBiometricAvailable() async {
    final isAvailable = await _localAuth.canCheckBiometrics;
    if (!isAvailable) return false;

    final availableBiometrics = await _localAuth.getAvailableBiometrics();
    return availableBiometrics.isNotEmpty;
  }

  /// Get available biometric types
  Future<List<BiometricType>> getAvailableBiometrics() async {
    return await _localAuth.getAvailableBiometrics();
  }

  /// Encrypt sensitive data
  Future<String> encrypt(String data) async {
    if (!_isInitialized) await initialize();
    
    try {
      final encrypted = _encrypter.encrypt(data, iv: _iv);
      return encrypted.base64;
    } catch (error, stackTrace) {
      throw StorageException(
        'Encryption failed',
        errorType: StorageErrorType.encryptionFailed,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Decrypt sensitive data
  Future<String> decrypt(String encryptedData) async {
    if (!_isInitialized) await initialize();
    
    try {
      final encrypted = Encrypted.fromBase64(encryptedData);
      return _encrypter.decrypt(encrypted, iv: _iv);
    } catch (error, stackTrace) {
      throw StorageException(
        'Decryption failed',
        errorType: StorageErrorType.corruptedData,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Store data securely
  Future<void> storeSecurely(String key, String value) async {
    try {
      final encryptedValue = await encrypt(value);
      await _secureStorage.write(key: key, value: encryptedValue);
    } catch (error, stackTrace) {
      throw StorageException(
        'Failed to store data securely',
        errorType: StorageErrorType.encryptionFailed,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Retrieve data securely
  Future<String?> retrieveSecurely(String key) async {
    try {
      final encryptedValue = await _secureStorage.read(key: key);
      if (encryptedValue == null) return null;
      
      return await decrypt(encryptedValue);
    } catch (error, stackTrace) {
      throw StorageException(
        'Failed to retrieve data securely',
        errorType: StorageErrorType.corruptedData,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Delete secure data
  Future<void> deleteSecurely(String key) async {
    try {
      await _secureStorage.delete(key: key);
    } catch (error, stackTrace) {
      throw StorageException(
        'Failed to delete secure data',
        errorType: StorageErrorType.permissionDenied,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Clear all secure storage
  Future<void> clearSecureStorage() async {
    try {
      await _secureStorage.deleteAll();
    } catch (error, stackTrace) {
      throw StorageException(
        'Failed to clear secure storage',
        errorType: StorageErrorType.permissionDenied,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Generate secure hash
  String generateHash(String data, {String? salt}) {
    final saltBytes = salt != null 
        ? utf8.encode(salt) 
        : _generateSecureRandom(16);
    
    final dataBytes = utf8.encode(data);
    final combined = Uint8List.fromList([...dataBytes, ...saltBytes]);
    
    final digest = sha256.convert(combined);
    return digest.toString();
  }

  /// Verify hash
  bool verifyHash(String data, String hash, {String? salt}) {
    final generatedHash = generateHash(data, salt: salt);
    return generatedHash == hash;
  }

  /// Generate secure random string
  String generateSecureRandomString(int length) {
    final random = Random.secure();
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    
    return String.fromCharCodes(
      Iterable.generate(
        length,
        (_) => chars.codeUnitAt(random.nextInt(chars.length)),
      ),
    );
  }

  /// Generate secure random bytes
  Uint8List _generateSecureRandom(int length) {
    final random = Random.secure();
    return Uint8List.fromList(
      List.generate(length, (_) => random.nextInt(256)),
    );
  }

  /// Get or generate master key
  Future<String?> _getMasterKey() async {
    return await _secureStorage.read(key: 'master_key');
  }

  /// Generate new master key
  Future<String> _generateMasterKey() async {
    return generateSecureRandomString(64);
  }

  /// Store master key securely
  Future<void> _storeMasterKey(String key) async {
    await _secureStorage.write(key: 'master_key', value: key);
  }

  /// Validate password strength
  PasswordStrength validatePasswordStrength(String password) {
    int score = 0;
    final checks = <String, bool>{
      'length': password.length >= AppConfig.validationRules['password_min_length'],
      'uppercase': !AppConfig.validationRules['password_require_uppercase'] || 
                   password.contains(RegExp(r'[A-Z]')),
      'lowercase': !AppConfig.validationRules['password_require_lowercase'] || 
                   password.contains(RegExp(r'[a-z]')),
      'numbers': !AppConfig.validationRules['password_require_numbers'] || 
                 password.contains(RegExp(r'[0-9]')),
      'symbols': !AppConfig.validationRules['password_require_symbols'] || 
                 password.contains(RegExp(r'[!@#$%^&*(),.?":{}|<>]')),
    };

    score = checks.values.where((check) => check).length;
    
    if (score == 5) return PasswordStrength.strong;
    if (score >= 3) return PasswordStrength.medium;
    return PasswordStrength.weak;
  }

  /// Generate secure PIN
  String generateSecurePIN(int length) {
    final random = Random.secure();
    return List.generate(length, (_) => random.nextInt(10)).join();
  }

  /// Check if device has secure lock screen
  Future<bool> hasSecureLockScreen() async {
    try {
      return await _localAuth.isDeviceSupported();
    } catch (e) {
      return false;
    }
  }

  /// Get device security info
  Future<DeviceSecurityInfo> getDeviceSecurityInfo() async {
    final isJailbroken = await RjSniffer.amICompromised() ?? false;
    final hasBiometrics = await isBiometricAvailable();
    final hasSecureLock = await hasSecureLockScreen();
    final availableBiometrics = await getAvailableBiometrics();

    return DeviceSecurityInfo(
      isJailbroken: isJailbroken,
      hasBiometrics: hasBiometrics,
      hasSecureLockScreen: hasSecureLock,
      availableBiometrics: availableBiometrics,
    );
  }

  /// Dispose resources
  void dispose() {
    _instance = null;
  }
}

/// Password strength levels
enum PasswordStrength {
  weak,
  medium,
  strong,
}

/// Device security information
class DeviceSecurityInfo {
  final bool isJailbroken;
  final bool hasBiometrics;
  final bool hasSecureLockScreen;
  final List<BiometricType> availableBiometrics;

  const DeviceSecurityInfo({
    required this.isJailbroken,
    required this.hasBiometrics,
    required this.hasSecureLockScreen,
    required this.availableBiometrics,
  });

  Map<String, dynamic> toJson() {
    return {
      'isJailbroken': isJailbroken,
      'hasBiometrics': hasBiometrics,
      'hasSecureLockScreen': hasSecureLockScreen,
      'availableBiometrics': availableBiometrics.map((e) => e.name).toList(),
    };
  }
}

/// Security context for operations
class SecurityContext {
  final String operation;
  final Map<String, dynamic> parameters;
  final DateTime timestamp;
  final String? userId;

  SecurityContext({
    required this.operation,
    this.parameters = const {},
    DateTime? timestamp,
    this.userId,
  }) : timestamp = timestamp ?? DateTime.now();

  Map<String, dynamic> toJson() {
    return {
      'operation': operation,
      'parameters': parameters,
      'timestamp': timestamp.toIso8601String(),
      'userId': userId,
    };
  }
}