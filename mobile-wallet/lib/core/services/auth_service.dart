/// Authentication Service
/// 
/// Comprehensive authentication service with multiple authentication methods,
/// session management, biometric authentication, and security features

import 'dart:async';
import 'dart:convert';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:google_sign_in/google_sign_in.dart';
import 'package:sign_in_with_apple/sign_in_with_apple.dart';
import 'package:crypto/crypto.dart';
import '../config/app_config.dart';
import '../error/error_handler.dart';
import 'api_service.dart';
import 'security_service.dart';

/// Authentication Service Implementation
class AuthService {
  static AuthService? _instance;
  static AuthService get instance => _instance ??= AuthService._();
  AuthService._();

  final FirebaseAuth _firebaseAuth = FirebaseAuth.instance;
  final GoogleSignIn _googleSignIn = GoogleSignIn(
    scopes: ['email', 'profile'],
  );

  final StreamController<AuthState> _authStateController = 
      StreamController<AuthState>.broadcast();
  
  Timer? _sessionTimer;
  Timer? _lockoutTimer;
  int _failedAttempts = 0;
  DateTime? _lockoutUntil;
  bool _isInitialized = false;

  /// Stream of authentication state changes
  Stream<AuthState> get authStateStream => _authStateController.stream;

  /// Current authentication state
  AuthState get currentState => _currentState;
  AuthState _currentState = AuthState.unauthenticated;

  /// Initialize authentication service
  Future<void> initialize() async {
    try {
      if (_isInitialized) return;

      // Listen to Firebase auth changes
      _firebaseAuth.authStateChanges().listen(_handleAuthStateChange);
      
      // Check existing authentication
      await _checkExistingAuth();
      
      // Setup session management
      _setupSessionManagement();
      
      _isInitialized = true;
    } catch (error, stackTrace) {
      throw AuthenticationException(
        'Failed to initialize authentication service: ${error.toString()}',
        errorType: AuthErrorType.networkError,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Handle Firebase auth state changes
  void _handleAuthStateChange(User? user) {
    if (user != null) {
      _updateAuthState(AuthState.authenticated);
    } else {
      _updateAuthState(AuthState.unauthenticated);
    }
  }

  /// Update authentication state
  void _updateAuthState(AuthState newState) {
    if (_currentState != newState) {
      _currentState = newState;
      _authStateController.add(newState);
    }
  }

  /// Check existing authentication
  Future<void> _checkExistingAuth() async {
    try {
      final token = await SecurityService.instance.retrieveSecurely('auth_token');
      if (token != null) {
        final isValid = await _validateToken(token);
        if (isValid) {
          _updateAuthState(AuthState.authenticated);
          return;
        }
      }
      
      // Try refresh token
      final refreshToken = await SecurityService.instance
          .retrieveSecurely('refresh_token');
      if (refreshToken != null) {
        final refreshed = await _refreshAuthToken();
        if (refreshed) {
          _updateAuthState(AuthState.authenticated);
          return;
        }
      }
      
      _updateAuthState(AuthState.unauthenticated);
    } catch (e) {
      _updateAuthState(AuthState.unauthenticated);
    }
  }

  /// Setup session management
  void _setupSessionManagement() {
    _sessionTimer = Timer.periodic(
      const Duration(minutes: 5),
      (timer) => _checkSessionValidity(),
    );
  }

  /// Check session validity
  Future<void> _checkSessionValidity() async {
    if (_currentState != AuthState.authenticated) return;
    
    try {
      final lastActivity = await SecurityService.instance
          .retrieveSecurely('last_activity');
      
      if (lastActivity != null) {
        final lastActivityTime = DateTime.parse(lastActivity);
        final now = DateTime.now();
        
        if (now.difference(lastActivityTime) > AppConfig.sessionTimeout) {
          await logout(reason: 'Session timeout');
        }
      }
    } catch (e) {
      // Handle session check error
    }
  }

  /// Update last activity timestamp
  Future<void> updateLastActivity() async {
    await SecurityService.instance.storeSecurely(
      'last_activity',
      DateTime.now().toIso8601String(),
    );
  }

  /// Login with email and password
  Future<AuthResult> loginWithEmailPassword(
    String email,
    String password, {
    bool rememberMe = false,
  }) async {
    try {
      if (!_isInitialized) await initialize();
      
      // Check if account is locked
      if (_isAccountLocked()) {
        throw AuthenticationException(
          'Account is temporarily locked',
          errorType: AuthErrorType.accountLocked,
        );
      }

      // Validate inputs
      _validateEmail(email);
      _validatePassword(password);

      // Attempt login
      final response = await ApiService.instance.post<Map<String, dynamic>>(
        '${AppConfig.authServiceUrl}/login',
        data: {
          'email': email,
          'password': _hashPassword(password),
          'remember_me': rememberMe,
          'device_info': await _getDeviceInfo(),
        },
        requiresAuth: false,
      );

      if (response.isSuccess && response.data != null) {
        final userData = response.data!;
        await _handleSuccessfulLogin(userData, rememberMe);
        
        return AuthResult(
          success: true,
          user: AuthUser.fromJson(userData['user']),
          message: 'Login successful',
        );
      } else {
        _handleFailedLogin();
        throw AuthenticationException(
          response.message,
          errorType: AuthErrorType.invalidCredentials,
        );
      }
    } catch (error, stackTrace) {
      _handleFailedLogin();
      
      if (error is AuthenticationException) rethrow;
      
      throw AuthenticationException(
        'Login failed: ${error.toString()}',
        errorType: AuthErrorType.networkError,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Login with biometrics
  Future<AuthResult> loginWithBiometrics() async {
    try {
      if (!_isInitialized) await initialize();
      
      // Check biometric availability
      final isAvailable = await SecurityService.instance.isBiometricAvailable();
      if (!isAvailable) {
        throw AuthenticationException(
          'Biometric authentication not available',
          errorType: AuthErrorType.biometricFailed,
        );
      }

      // Authenticate with biometrics
      final authenticated = await SecurityService.instance
          .authenticateWithBiometrics(
        reason: 'Authenticate to access your UK Digital ID',
      );

      if (!authenticated) {
        throw AuthenticationException(
          'Biometric authentication failed',
          errorType: AuthErrorType.biometricFailed,
        );
      }

      // Get stored biometric token
      final biometricToken = await SecurityService.instance
          .retrieveSecurely('biometric_token');
      
      if (biometricToken == null) {
        throw AuthenticationException(
          'No biometric credentials found',
          errorType: AuthErrorType.biometricFailed,
        );
      }

      // Validate biometric token
      final response = await ApiService.instance.post<Map<String, dynamic>>(
        '${AppConfig.authServiceUrl}/biometric-login',
        data: {
          'biometric_token': biometricToken,
          'device_info': await _getDeviceInfo(),
        },
        requiresAuth: false,
      );

      if (response.isSuccess && response.data != null) {
        final userData = response.data!;
        await _handleSuccessfulLogin(userData, true);
        
        return AuthResult(
          success: true,
          user: AuthUser.fromJson(userData['user']),
          message: 'Biometric login successful',
        );
      } else {
        throw AuthenticationException(
          'Biometric authentication failed',
          errorType: AuthErrorType.biometricFailed,
        );
      }
    } catch (error, stackTrace) {
      if (error is AuthenticationException) rethrow;
      
      throw AuthenticationException(
        'Biometric login failed: ${error.toString()}',
        errorType: AuthErrorType.biometricFailed,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Login with Google
  Future<AuthResult> loginWithGoogle() async {
    try {
      if (!_isInitialized) await initialize();
      
      final googleUser = await _googleSignIn.signIn();
      if (googleUser == null) {
        throw AuthenticationException(
          'Google sign-in was cancelled',
          errorType: AuthErrorType.invalidCredentials,
        );
      }

      final googleAuth = await googleUser.authentication;
      final credential = GoogleAuthProvider.credential(
        accessToken: googleAuth.accessToken,
        idToken: googleAuth.idToken,
      );

      final userCredential = await _firebaseAuth.signInWithCredential(credential);
      
      if (userCredential.user != null) {
        final idToken = await userCredential.user!.getIdToken();
        
        // Send to backend for validation
        final response = await ApiService.instance.post<Map<String, dynamic>>(
          '${AppConfig.authServiceUrl}/google-login',
          data: {
            'id_token': idToken,
            'device_info': await _getDeviceInfo(),
          },
          requiresAuth: false,
        );

        if (response.isSuccess && response.data != null) {
          final userData = response.data!;
          await _handleSuccessfulLogin(userData, true);
          
          return AuthResult(
            success: true,
            user: AuthUser.fromJson(userData['user']),
            message: 'Google login successful',
          );
        }
      }
      
      throw AuthenticationException(
        'Google authentication failed',
        errorType: AuthErrorType.invalidCredentials,
      );
    } catch (error, stackTrace) {
      if (error is AuthenticationException) rethrow;
      
      throw AuthenticationException(
        'Google login failed: ${error.toString()}',
        errorType: AuthErrorType.networkError,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Login with Apple
  Future<AuthResult> loginWithApple() async {
    try {
      if (!_isInitialized) await initialize();
      
      final appleCredential = await SignInWithApple.getAppleIDCredential(
        scopes: [
          AppleIDAuthorizationScopes.email,
          AppleIDAuthorizationScopes.fullName,
        ],
        webAuthenticationOptions: WebAuthenticationOptions(
          clientId: 'uk.gov.digitalidentity.wallet',
          redirectUri: Uri.parse('https://api.digital-identity.gov.uk/auth/apple/callback'),
        ),
      );

      final oauthCredential = OAuthProvider("apple.com").credential(
        idToken: appleCredential.identityToken,
        accessToken: appleCredential.authorizationCode,
      );

      final userCredential = await _firebaseAuth.signInWithCredential(oauthCredential);
      
      if (userCredential.user != null) {
        final idToken = await userCredential.user!.getIdToken();
        
        // Send to backend for validation
        final response = await ApiService.instance.post<Map<String, dynamic>>(
          '${AppConfig.authServiceUrl}/apple-login',
          data: {
            'id_token': idToken,
            'authorization_code': appleCredential.authorizationCode,
            'device_info': await _getDeviceInfo(),
          },
          requiresAuth: false,
        );

        if (response.isSuccess && response.data != null) {
          final userData = response.data!;
          await _handleSuccessfulLogin(userData, true);
          
          return AuthResult(
            success: true,
            user: AuthUser.fromJson(userData['user']),
            message: 'Apple login successful',
          );
        }
      }
      
      throw AuthenticationException(
        'Apple authentication failed',
        errorType: AuthErrorType.invalidCredentials,
      );
    } catch (error, stackTrace) {
      if (error is AuthenticationException) rethrow;
      
      throw AuthenticationException(
        'Apple login failed: ${error.toString()}',
        errorType: AuthErrorType.networkError,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Register new user
  Future<AuthResult> register({
    required String email,
    required String password,
    required String firstName,
    required String lastName,
    required String phoneNumber,
    Map<String, dynamic>? additionalData,
  }) async {
    try {
      if (!_isInitialized) await initialize();
      
      // Validate inputs
      _validateEmail(email);
      _validatePassword(password);
      _validateName(firstName);
      _validateName(lastName);
      _validatePhoneNumber(phoneNumber);

      final response = await ApiService.instance.post<Map<String, dynamic>>(
        '${AppConfig.authServiceUrl}/register',
        data: {
          'email': email,
          'password': _hashPassword(password),
          'first_name': firstName,
          'last_name': lastName,
          'phone_number': phoneNumber,
          'device_info': await _getDeviceInfo(),
          if (additionalData != null) ...additionalData,
        },
        requiresAuth: false,
      );

      if (response.isSuccess && response.data != null) {
        return AuthResult(
          success: true,
          user: AuthUser.fromJson(response.data!['user']),
          message: 'Registration successful. Please verify your email.',
          requiresVerification: true,
        );
      } else {
        throw AuthenticationException(
          response.message,
          errorType: AuthErrorType.invalidCredentials,
        );
      }
    } catch (error, stackTrace) {
      if (error is AuthenticationException) rethrow;
      
      throw AuthenticationException(
        'Registration failed: ${error.toString()}',
        errorType: AuthErrorType.networkError,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Verify email
  Future<bool> verifyEmail(String verificationCode) async {
    try {
      final response = await ApiService.instance.post<Map<String, dynamic>>(
        '${AppConfig.authServiceUrl}/verify-email',
        data: {'verification_code': verificationCode},
        requiresAuth: false,
      );

      return response.isSuccess;
    } catch (error, stackTrace) {
      throw AuthenticationException(
        'Email verification failed: ${error.toString()}',
        errorType: AuthErrorType.networkError,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Send password reset email
  Future<bool> sendPasswordResetEmail(String email) async {
    try {
      _validateEmail(email);
      
      final response = await ApiService.instance.post<Map<String, dynamic>>(
        '${AppConfig.authServiceUrl}/password-reset',
        data: {'email': email},
        requiresAuth: false,
      );

      return response.isSuccess;
    } catch (error, stackTrace) {
      throw AuthenticationException(
        'Password reset failed: ${error.toString()}',
        errorType: AuthErrorType.networkError,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Reset password with code
  Future<bool> resetPassword({
    required String email,
    required String resetCode,
    required String newPassword,
  }) async {
    try {
      _validateEmail(email);
      _validatePassword(newPassword);
      
      final response = await ApiService.instance.post<Map<String, dynamic>>(
        '${AppConfig.authServiceUrl}/password-reset/confirm',
        data: {
          'email': email,
          'reset_code': resetCode,
          'new_password': _hashPassword(newPassword),
        },
        requiresAuth: false,
      );

      return response.isSuccess;
    } catch (error, stackTrace) {
      throw AuthenticationException(
        'Password reset failed: ${error.toString()}',
        errorType: AuthErrorType.networkError,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Change password
  Future<bool> changePassword({
    required String currentPassword,
    required String newPassword,
  }) async {
    try {
      _validatePassword(newPassword);
      
      final response = await ApiService.instance.post<Map<String, dynamic>>(
        '${AppConfig.authServiceUrl}/change-password',
        data: {
          'current_password': _hashPassword(currentPassword),
          'new_password': _hashPassword(newPassword),
        },
      );

      return response.isSuccess;
    } catch (error, stackTrace) {
      throw AuthenticationException(
        'Password change failed: ${error.toString()}',
        errorType: AuthErrorType.networkError,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Enable biometric authentication
  Future<bool> enableBiometricAuth() async {
    try {
      final authenticated = await SecurityService.instance
          .authenticateWithBiometrics(
        reason: 'Enable biometric authentication for your account',
      );

      if (!authenticated) return false;

      // Generate biometric token
      final biometricToken = SecurityService.instance.generateSecureRandomString(64);
      
      final response = await ApiService.instance.post<Map<String, dynamic>>(
        '${AppConfig.authServiceUrl}/enable-biometric',
        data: {'biometric_token': biometricToken},
      );

      if (response.isSuccess) {
        await SecurityService.instance.storeSecurely(
          'biometric_token',
          biometricToken,
        );
        return true;
      }

      return false;
    } catch (error, stackTrace) {
      throw AuthenticationException(
        'Failed to enable biometric authentication: ${error.toString()}',
        errorType: AuthErrorType.biometricFailed,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Disable biometric authentication
  Future<bool> disableBiometricAuth() async {
    try {
      final response = await ApiService.instance.post<Map<String, dynamic>>(
        '${AppConfig.authServiceUrl}/disable-biometric',
        data: {},
      );

      if (response.isSuccess) {
        await SecurityService.instance.deleteSecurely('biometric_token');
        return true;
      }

      return false;
    } catch (error, stackTrace) {
      throw AuthenticationException(
        'Failed to disable biometric authentication: ${error.toString()}',
        errorType: AuthErrorType.networkError,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Logout
  Future<void> logout({String? reason}) async {
    try {
      // Call logout endpoint
      await ApiService.instance.post<void>(
        '${AppConfig.authServiceUrl}/logout',
        data: {'reason': reason},
      );
    } catch (e) {
      // Continue with logout even if API call fails
    } finally {
      // Clear local data
      await _clearAuthData();
      
      // Sign out from Firebase
      await _firebaseAuth.signOut();
      
      // Sign out from Google
      await _googleSignIn.signOut();
      
      // Update state
      _updateAuthState(AuthState.unauthenticated);
    }
  }

  /// Get current user
  Future<AuthUser?> getCurrentUser() async {
    try {
      if (_currentState != AuthState.authenticated) return null;
      
      final userJson = await SecurityService.instance.retrieveSecurely('user_data');
      if (userJson != null) {
        return AuthUser.fromJson(json.decode(userJson));
      }
      
      return null;
    } catch (e) {
      return null;
    }
  }

  /// Refresh authentication token
  Future<bool> _refreshAuthToken() async {
    try {
      // This is handled by ApiService interceptor
      return true;
    } catch (e) {
      return false;
    }
  }

  /// Validate token
  Future<bool> _validateToken(String token) async {
    try {
      final response = await ApiService.instance.get<Map<String, dynamic>>(
        '${AppConfig.authServiceUrl}/validate',
      );
      
      return response.isSuccess;
    } catch (e) {
      return false;
    }
  }

  /// Handle successful login
  Future<void> _handleSuccessfulLogin(
    Map<String, dynamic> userData,
    bool rememberMe,
  ) async {
    // Store tokens
    await SecurityService.instance.storeSecurely(
      'auth_token',
      userData['access_token'],
    );
    
    if (userData['refresh_token'] != null) {
      await SecurityService.instance.storeSecurely(
        'refresh_token',
        userData['refresh_token'],
      );
    }
    
    // Store user data
    await SecurityService.instance.storeSecurely(
      'user_data',
      json.encode(userData['user']),
    );
    
    // Update last activity
    await updateLastActivity();
    
    // Reset failed attempts
    _failedAttempts = 0;
    _lockoutUntil = null;
    
    // Update state
    _updateAuthState(AuthState.authenticated);
  }

  /// Handle failed login
  void _handleFailedLogin() {
    _failedAttempts++;
    
    if (_failedAttempts >= AppConfig.maxLoginAttempts) {
      _lockoutUntil = DateTime.now().add(AppConfig.lockoutDuration);
      _startLockoutTimer();
    }
  }

  /// Check if account is locked
  bool _isAccountLocked() {
    if (_lockoutUntil == null) return false;
    
    if (DateTime.now().isAfter(_lockoutUntil!)) {
      _lockoutUntil = null;
      _failedAttempts = 0;
      return false;
    }
    
    return true;
  }

  /// Start lockout timer
  void _startLockoutTimer() {
    _lockoutTimer?.cancel();
    _lockoutTimer = Timer(AppConfig.lockoutDuration, () {
      _lockoutUntil = null;
      _failedAttempts = 0;
    });
  }

  /// Clear authentication data
  Future<void> _clearAuthData() async {
    await SecurityService.instance.deleteSecurely('auth_token');
    await SecurityService.instance.deleteSecurely('refresh_token');
    await SecurityService.instance.deleteSecurely('user_data');
    await SecurityService.instance.deleteSecurely('last_activity');
  }

  /// Get device information
  Future<Map<String, dynamic>> _getDeviceInfo() async {
    final deviceSecurity = await SecurityService.instance.getDeviceSecurityInfo();
    
    return {
      'device_id': SecurityService.instance.generateSecureRandomString(32),
      'platform': Platform.isAndroid ? 'android' : 'ios',
      'app_version': AppConfig.appVersion,
      'security_info': deviceSecurity.toJson(),
    };
  }

  /// Hash password
  String _hashPassword(String password) {
    final bytes = utf8.encode(password + AppConfig.jwtIssuer);
    final digest = sha256.convert(bytes);
    return digest.toString();
  }

  /// Validation methods
  void _validateEmail(String email) {
    if (!AppConfig.validationRules['email_validation_enabled']) return;
    
    final emailRegex = RegExp(r'^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$');
    if (!emailRegex.hasMatch(email)) {
      throw ValidationException(
        'Invalid email format',
        fieldErrors: {'email': ['Please enter a valid email address']},
      );
    }
  }

  void _validatePassword(String password) {
    final strength = SecurityService.instance.validatePasswordStrength(password);
    if (strength == PasswordStrength.weak) {
      throw ValidationException(
        'Password is too weak',
        fieldErrors: {'password': ['Password does not meet security requirements']},
      );
    }
  }

  void _validateName(String name) {
    if (name.trim().isEmpty || name.length < 2) {
      throw ValidationException(
        'Invalid name',
        fieldErrors: {'name': ['Name must be at least 2 characters long']},
      );
    }
  }

  void _validatePhoneNumber(String phone) {
    if (!AppConfig.validationRules['phone_validation_enabled']) return;
    
    final phoneRegex = RegExp(r'^\+?[\d\s\-\(\)]+$');
    if (!phoneRegex.hasMatch(phone) || phone.replaceAll(RegExp(r'\D'), '').length < 10) {
      throw ValidationException(
        'Invalid phone number',
        fieldErrors: {'phone': ['Please enter a valid phone number']},
      );
    }
  }

  /// Dispose resources
  void dispose() {
    _sessionTimer?.cancel();
    _lockoutTimer?.cancel();
    _authStateController.close();
    _instance = null;
  }
}

/// Authentication state
enum AuthState {
  unauthenticated,
  authenticated,
  verificationRequired,
  locked,
}

/// Authentication result
class AuthResult {
  final bool success;
  final AuthUser? user;
  final String message;
  final bool requiresVerification;
  final Map<String, dynamic>? metadata;

  AuthResult({
    required this.success,
    this.user,
    required this.message,
    this.requiresVerification = false,
    this.metadata,
  });
}

/// Authenticated user
class AuthUser {
  final String id;
  final String email;
  final String firstName;
  final String lastName;
  final String? phoneNumber;
  final bool isVerified;
  final bool biometricEnabled;
  final DateTime createdAt;
  final DateTime lastLogin;

  AuthUser({
    required this.id,
    required this.email,
    required this.firstName,
    required this.lastName,
    this.phoneNumber,
    required this.isVerified,
    required this.biometricEnabled,
    required this.createdAt,
    required this.lastLogin,
  });

  factory AuthUser.fromJson(Map<String, dynamic> json) {
    return AuthUser(
      id: json['id'],
      email: json['email'],
      firstName: json['first_name'],
      lastName: json['last_name'],
      phoneNumber: json['phone_number'],
      isVerified: json['is_verified'] ?? false,
      biometricEnabled: json['biometric_enabled'] ?? false,
      createdAt: DateTime.parse(json['created_at']),
      lastLogin: DateTime.parse(json['last_login']),
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'email': email,
      'first_name': firstName,
      'last_name': lastName,
      'phone_number': phoneNumber,
      'is_verified': isVerified,
      'biometric_enabled': biometricEnabled,
      'created_at': createdAt.toIso8601String(),
      'last_login': lastLogin.toIso8601String(),
    };
  }

  String get fullName => '$firstName $lastName';
}