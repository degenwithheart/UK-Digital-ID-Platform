/// Authentication Provider
/// 
/// Comprehensive state management for authentication with 
/// reactive UI updates and error handling

import 'package:flutter/foundation.dart';
import '../../core/services/auth_service.dart';
import '../../core/error/error_handler.dart';

class AuthProvider with ChangeNotifier {
  AuthState _authState = AuthState.unauthenticated;
  AuthUser? _currentUser;
  bool _isLoading = false;
  String? _errorMessage;
  
  // Getters
  AuthState get authState => _authState;
  AuthUser? get currentUser => _currentUser;
  bool get isLoading => _isLoading;
  String? get errorMessage => _errorMessage;
  bool get isAuthenticated => _authState == AuthState.authenticated;

  /// Initialize provider
  Future<void> initialize() async {
    try {
      await AuthService.instance.initialize();
      
      // Listen to auth state changes
      AuthService.instance.authStateStream.listen(_handleAuthStateChange);
      
      // Check current authentication status
      _currentUser = await AuthService.instance.getCurrentUser();
      if (_currentUser != null) {
        _authState = AuthState.authenticated;
      }
      
      notifyListeners();
    } catch (error) {
      _setError('Failed to initialize authentication');
    }
  }

  /// Handle auth state changes from service
  void _handleAuthStateChange(AuthState newState) {
    _authState = newState;
    
    if (newState == AuthState.unauthenticated) {
      _currentUser = null;
    }
    
    notifyListeners();
  }

  /// Login with email and password
  Future<AuthResult> loginWithEmailPassword(
    String email,
    String password, {
    bool rememberMe = false,
  }) async {
    _setLoading(true);
    _clearError();
    
    try {
      final result = await AuthService.instance.loginWithEmailPassword(
        email,
        password,
        rememberMe: rememberMe,
      );
      
      if (result.success && result.user != null) {
        _currentUser = result.user;
        _authState = AuthState.authenticated;
        await AuthService.instance.updateLastActivity();
      }
      
      return result;
    } catch (error) {
      final errorMessage = _getErrorMessage(error);
      _setError(errorMessage);
      
      return AuthResult(
        success: false,
        message: errorMessage,
      );
    } finally {
      _setLoading(false);
    }
  }

  /// Login with biometrics
  Future<AuthResult> loginWithBiometrics() async {
    _setLoading(true);
    _clearError();
    
    try {
      final result = await AuthService.instance.loginWithBiometrics();
      
      if (result.success && result.user != null) {
        _currentUser = result.user;
        _authState = AuthState.authenticated;
        await AuthService.instance.updateLastActivity();
      }
      
      return result;
    } catch (error) {
      final errorMessage = _getErrorMessage(error);
      _setError(errorMessage);
      
      return AuthResult(
        success: false,
        message: errorMessage,
      );
    } finally {
      _setLoading(false);
    }
  }

  /// Login with Google
  Future<AuthResult> loginWithGoogle() async {
    _setLoading(true);
    _clearError();
    
    try {
      final result = await AuthService.instance.loginWithGoogle();
      
      if (result.success && result.user != null) {
        _currentUser = result.user;
        _authState = AuthState.authenticated;
        await AuthService.instance.updateLastActivity();
      }
      
      return result;
    } catch (error) {
      final errorMessage = _getErrorMessage(error);
      _setError(errorMessage);
      
      return AuthResult(
        success: false,
        message: errorMessage,
      );
    } finally {
      _setLoading(false);
    }
  }

  /// Login with Apple
  Future<AuthResult> loginWithApple() async {
    _setLoading(true);
    _clearError();
    
    try {
      final result = await AuthService.instance.loginWithApple();
      
      if (result.success && result.user != null) {
        _currentUser = result.user;
        _authState = AuthState.authenticated;
        await AuthService.instance.updateLastActivity();
      }
      
      return result;
    } catch (error) {
      final errorMessage = _getErrorMessage(error);
      _setError(errorMessage);
      
      return AuthResult(
        success: false,
        message: errorMessage,
      );
    } finally {
      _setLoading(false);
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
    _setLoading(true);
    _clearError();
    
    try {
      final result = await AuthService.instance.register(
        email: email,
        password: password,
        firstName: firstName,
        lastName: lastName,
        phoneNumber: phoneNumber,
        additionalData: additionalData,
      );
      
      if (result.requiresVerification) {
        _authState = AuthState.verificationRequired;
      }
      
      return result;
    } catch (error) {
      final errorMessage = _getErrorMessage(error);
      _setError(errorMessage);
      
      return AuthResult(
        success: false,
        message: errorMessage,
      );
    } finally {
      _setLoading(false);
    }
  }

  /// Verify email
  Future<bool> verifyEmail(String verificationCode) async {
    _setLoading(true);
    _clearError();
    
    try {
      final result = await AuthService.instance.verifyEmail(verificationCode);
      
      if (result) {
        _authState = AuthState.unauthenticated;
      }
      
      return result;
    } catch (error) {
      _setError(_getErrorMessage(error));
      return false;
    } finally {
      _setLoading(false);
    }
  }

  /// Send password reset email
  Future<bool> sendPasswordResetEmail(String email) async {
    _setLoading(true);
    _clearError();
    
    try {
      return await AuthService.instance.sendPasswordResetEmail(email);
    } catch (error) {
      _setError(_getErrorMessage(error));
      return false;
    } finally {
      _setLoading(false);
    }
  }

  /// Reset password with code
  Future<bool> resetPassword({
    required String email,
    required String resetCode,
    required String newPassword,
  }) async {
    _setLoading(true);
    _clearError();
    
    try {
      return await AuthService.instance.resetPassword(
        email: email,
        resetCode: resetCode,
        newPassword: newPassword,
      );
    } catch (error) {
      _setError(_getErrorMessage(error));
      return false;
    } finally {
      _setLoading(false);
    }
  }

  /// Change password
  Future<bool> changePassword({
    required String currentPassword,
    required String newPassword,
  }) async {
    _setLoading(true);
    _clearError();
    
    try {
      return await AuthService.instance.changePassword(
        currentPassword: currentPassword,
        newPassword: newPassword,
      );
    } catch (error) {
      _setError(_getErrorMessage(error));
      return false;
    } finally {
      _setLoading(false);
    }
  }

  /// Enable biometric authentication
  Future<bool> enableBiometricAuth() async {
    _setLoading(true);
    _clearError();
    
    try {
      final result = await AuthService.instance.enableBiometricAuth();
      
      if (result && _currentUser != null) {
        _currentUser = AuthUser(
          id: _currentUser!.id,
          email: _currentUser!.email,
          firstName: _currentUser!.firstName,
          lastName: _currentUser!.lastName,
          phoneNumber: _currentUser!.phoneNumber,
          isVerified: _currentUser!.isVerified,
          biometricEnabled: true,
          createdAt: _currentUser!.createdAt,
          lastLogin: _currentUser!.lastLogin,
        );
        notifyListeners();
      }
      
      return result;
    } catch (error) {
      _setError(_getErrorMessage(error));
      return false;
    } finally {
      _setLoading(false);
    }
  }

  /// Disable biometric authentication
  Future<bool> disableBiometricAuth() async {
    _setLoading(true);
    _clearError();
    
    try {
      final result = await AuthService.instance.disableBiometricAuth();
      
      if (result && _currentUser != null) {
        _currentUser = AuthUser(
          id: _currentUser!.id,
          email: _currentUser!.email,
          firstName: _currentUser!.firstName,
          lastName: _currentUser!.lastName,
          phoneNumber: _currentUser!.phoneNumber,
          isVerified: _currentUser!.isVerified,
          biometricEnabled: false,
          createdAt: _currentUser!.createdAt,
          lastLogin: _currentUser!.lastLogin,
        );
        notifyListeners();
      }
      
      return result;
    } catch (error) {
      _setError(_getErrorMessage(error));
      return false;
    } finally {
      _setLoading(false);
    }
  }

  /// Logout
  Future<void> logout({String? reason}) async {
    _setLoading(true);
    
    try {
      await AuthService.instance.logout(reason: reason);
      
      _currentUser = null;
      _authState = AuthState.unauthenticated;
      _clearError();
    } catch (error) {
      // Continue with logout even if API call fails
      _currentUser = null;
      _authState = AuthState.unauthenticated;
      _clearError();
    } finally {
      _setLoading(false);
    }
  }

  /// Update last activity
  Future<void> updateLastActivity() async {
    try {
      await AuthService.instance.updateLastActivity();
    } catch (error) {
      // Silently handle activity update errors
    }
  }

  /// Refresh user data
  Future<void> refreshUser() async {
    try {
      _currentUser = await AuthService.instance.getCurrentUser();
      notifyListeners();
    } catch (error) {
      _setError('Failed to refresh user data');
    }
  }

  /// Check session validity
  Future<bool> checkSessionValidity() async {
    try {
      final user = await AuthService.instance.getCurrentUser();
      
      if (user != null) {
        _currentUser = user;
        _authState = AuthState.authenticated;
        notifyListeners();
        return true;
      } else {
        _currentUser = null;
        _authState = AuthState.unauthenticated;
        notifyListeners();
        return false;
      }
    } catch (error) {
      _currentUser = null;
      _authState = AuthState.unauthenticated;
      notifyListeners();
      return false;
    }
  }

  /// Get error message from exception
  String _getErrorMessage(dynamic error) {
    if (error is AuthenticationException) {
      return error.userMessage;
    } else if (error is ValidationException) {
      return error.userMessage;
    } else if (error is NetworkException) {
      return error.userMessage;
    } else {
      return 'An unexpected error occurred';
    }
  }

  /// Set loading state
  void _setLoading(bool loading) {
    _isLoading = loading;
    notifyListeners();
  }

  /// Set error message
  void _setError(String message) {
    _errorMessage = message;
    notifyListeners();
  }

  /// Clear error message
  void _clearError() {
    _errorMessage = null;
    notifyListeners();
  }

  /// Clear all data on dispose
  @override
  void dispose() {
    _currentUser = null;
    _authState = AuthState.unauthenticated;
    _isLoading = false;
    _errorMessage = null;
    super.dispose();
  }
}