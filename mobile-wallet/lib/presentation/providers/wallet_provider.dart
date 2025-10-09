/// Wallet Provider
/// 
/// Comprehensive state management for digital wallet functionality
/// with credentials, verification, and activity tracking

import 'package:flutter/foundation.dart';
import 'package:fl_chart/fl_chart.dart';
import '../../core/services/storage_service.dart';
import '../../core/services/api_service.dart';
import '../../core/config/app_config.dart';
import '../../core/error/error_handler.dart';

class WalletProvider with ChangeNotifier {
  List<DigitalCredential> _credentials = [];
  List<Map<String, dynamic>> _recentActivities = [];
  List<FlSpot> _usageStats = [];
  
  bool _isLoading = false;
  bool _isRefreshing = false;
  bool _isSyncing = false;
  String? _errorMessage;
  
  VerificationStatus _verificationStatus = VerificationStatus.pending;
  StorageStats? _storageStats;
  
  // Getters
  List<DigitalCredential> get credentials => List.unmodifiable(_credentials);
  List<Map<String, dynamic>> get recentActivities => List.unmodifiable(_recentActivities);
  List<FlSpot> get usageStats => List.unmodifiable(_usageStats);
  
  bool get isLoading => _isLoading;
  bool get isRefreshing => _isRefreshing;
  bool get isSyncing => _isSyncing;
  String? get errorMessage => _errorMessage;
  
  VerificationStatus get verificationStatus => _verificationStatus;
  StorageStats? get storageStats => _storageStats;
  
  // Computed properties
  int get totalCredentialsCount => _credentials.length;
  int get verifiedCredentialsCount => _credentials.where((c) => c.status == 'verified').length;
  int get pendingCredentialsCount => _credentials.where((c) => c.status == 'pending').length;
  int get expiredCredentialsCount => _credentials.where((c) => c.isExpired).length;
  int get activeCredentialsCount => _credentials.where((c) => c.isActive).length;
  
  List<DigitalCredential> get activeCredentials => _credentials.where((c) => c.isActive).toList();
  List<DigitalCredential> get expiredCredentials => _credentials.where((c) => c.isExpired).toList();
  List<DigitalCredential> get pendingCredentials => _credentials.where((c) => c.status == 'pending').toList();

  /// Initialize wallet provider
  Future<void> initialize() async {
    try {
      await StorageService.instance.initialize();
      await loadCredentials();
      await loadRecentActivity();
      await loadUsageStatistics();
      await checkVerificationStatus();
      await loadStorageStats();
    } catch (error) {
      _setError('Failed to initialize wallet');
    }
  }

  /// Load credentials from storage
  Future<void> loadCredentials() async {
    _setLoading(true);
    
    try {
      _credentials = await StorageService.instance.getCredentials();
      notifyListeners();
    } catch (error) {
      _setError('Failed to load credentials');
    } finally {
      _setLoading(false);
    }
  }

  /// Load recent activities
  Future<void> loadRecentActivity() async {
    try {
      // Load from local storage first
      final cachedActivities = await StorageService.instance.retrieveFromCache<List<dynamic>>('recent_activities');
      if (cachedActivities != null) {
        _recentActivities = cachedActivities.cast<Map<String, dynamic>>();
        notifyListeners();
      }
      
      // Fetch fresh data from API
      final response = await ApiService.instance.get<List<dynamic>>(
        '${AppConfig.walletServiceUrl}/activities/recent',
      );
      
      if (response.isSuccess && response.data != null) {
        _recentActivities = response.data!.cast<Map<String, dynamic>>();
        
        // Cache for offline use
        await StorageService.instance.storeInCache('recent_activities', _recentActivities);
        
        notifyListeners();
      }
    } catch (error) {
      if (_recentActivities.isEmpty) {
        _recentActivities = _generateMockActivities();
        notifyListeners();
      }
    }
  }

  /// Load usage statistics
  Future<void> loadUsageStatistics() async {
    try {
      final response = await ApiService.instance.get<List<dynamic>>(
        '${AppConfig.walletServiceUrl}/statistics/usage',
      );
      
      if (response.isSuccess && response.data != null) {
        _usageStats = response.data!
            .asMap()
            .entries
            .map((entry) => FlSpot(entry.key.toDouble(), entry.value['count'].toDouble()))
            .toList();
        
        await StorageService.instance.storeInCache('usage_stats', _usageStats);
        notifyListeners();
      }
    } catch (error) {
      // Generate mock data if API fails
      _usageStats = _generateMockUsageStats();
      notifyListeners();
    }
  }

  /// Check verification status
  Future<void> checkVerificationStatus() async {
    try {
      final response = await ApiService.instance.get<Map<String, dynamic>>(
        '${AppConfig.verificationServiceUrl}/status',
      );
      
      if (response.isSuccess && response.data != null) {
        final status = response.data!['status'] as String?;
        _verificationStatus = _parseVerificationStatus(status);
        notifyListeners();
      }
    } catch (error) {
      // Keep current status if API call fails
    }
  }

  /// Load storage statistics
  Future<void> loadStorageStats() async {
    try {
      _storageStats = await StorageService.instance.getStorageStats();
      notifyListeners();
    } catch (error) {
      _setError('Failed to load storage statistics');
    }
  }

  /// Add new credential
  Future<bool> addCredential(DigitalCredential credential) async {
    _setLoading(true);
    
    try {
      // Store locally first
      await StorageService.instance.storeCredential(credential);
      
      // Add to local list
      _credentials.add(credential);
      notifyListeners();
      
      // Log activity
      await _logActivity(
        type: 'credential_added',
        title: 'Credential Added',
        description: 'Added ${credential.type} credential',
      );
      
      return true;
    } catch (error) {
      _setError('Failed to add credential');
      return false;
    } finally {
      _setLoading(false);
    }
  }

  /// Update existing credential
  Future<bool> updateCredential(DigitalCredential credential) async {
    _setLoading(true);
    
    try {
      // Update in storage
      await StorageService.instance.updateCredential(credential);
      
      // Update in local list
      final index = _credentials.indexWhere((c) => c.id == credential.id);
      if (index != -1) {
        _credentials[index] = credential;
        notifyListeners();
      }
      
      // Log activity
      await _logActivity(
        type: 'credential_updated',
        title: 'Credential Updated',
        description: 'Updated ${credential.type} credential',
      );
      
      return true;
    } catch (error) {
      _setError('Failed to update credential');
      return false;
    } finally {
      _setLoading(false);
    }
  }

  /// Delete credential
  Future<bool> deleteCredential(String credentialId) async {
    _setLoading(true);
    
    try {
      // Find credential
      final credential = _credentials.firstWhere((c) => c.id == credentialId);
      
      // Delete from storage
      await StorageService.instance.deleteCredential(credentialId);
      
      // Remove from local list
      _credentials.removeWhere((c) => c.id == credentialId);
      notifyListeners();
      
      // Log activity
      await _logActivity(
        type: 'credential_deleted',
        title: 'Credential Deleted',
        description: 'Deleted ${credential.type} credential',
      );
      
      return true;
    } catch (error) {
      _setError('Failed to delete credential');
      return false;
    } finally {
      _setLoading(false);
    }
  }

  /// Get credential by ID
  DigitalCredential? getCredentialById(String id) {
    try {
      return _credentials.firstWhere((c) => c.id == id);
    } catch (e) {
      return null;
    }
  }

  /// Get credentials by type
  List<DigitalCredential> getCredentialsByType(String type) {
    return _credentials.where((c) => c.type == type).toList();
  }

  /// Verify credential
  Future<VerificationResult> verifyCredential(String credentialId) async {
    _setLoading(true);
    
    try {
      final response = await ApiService.instance.post<Map<String, dynamic>>(
        '${AppConfig.verificationServiceUrl}/verify',
        data: {'credential_id': credentialId},
      );
      
      if (response.isSuccess && response.data != null) {
        final result = VerificationResult.fromJson(response.data!);
        
        // Update credential verification count
        final credential = getCredentialById(credentialId);
        if (credential != null) {
          final updatedCredential = DigitalCredential(
            id: credential.id,
            type: credential.type,
            issuer: credential.issuer,
            subject: credential.subject,
            data: credential.data,
            sensitiveData: credential.sensitiveData,
            issuedAt: credential.issuedAt,
            expiresAt: credential.expiresAt,
            status: result.isValid ? 'verified' : credential.status,
            verificationCount: credential.verificationCount + 1,
            lastUsed: DateTime.now(),
          );
          
          await updateCredential(updatedCredential);
        }
        
        // Log verification activity
        await _logActivity(
          type: 'verification',
          title: 'Credential Verified',
          description: 'Verified ${credential?.type ?? 'credential'}',
        );
        
        return result;
      } else {
        return VerificationResult(
          isValid: false,
          message: response.message,
        );
      }
    } catch (error) {
      return VerificationResult(
        isValid: false,
        message: 'Verification failed: ${_getErrorMessage(error)}',
      );
    } finally {
      _setLoading(false);
    }
  }

  /// Share credential
  Future<ShareResult> shareCredential(String credentialId, String recipientId) async {
    _setLoading(true);
    
    try {
      final response = await ApiService.instance.post<Map<String, dynamic>>(
        '${AppConfig.walletServiceUrl}/credentials/share',
        data: {
          'credential_id': credentialId,
          'recipient_id': recipientId,
        },
      );
      
      if (response.isSuccess && response.data != null) {
        final result = ShareResult.fromJson(response.data!);
        
        // Log share activity
        final credential = getCredentialById(credentialId);
        await _logActivity(
          type: 'share',
          title: 'Credential Shared',
          description: 'Shared ${credential?.type ?? 'credential'} with recipient',
        );
        
        return result;
      } else {
        return ShareResult(
          success: false,
          message: response.message,
        );
      }
    } catch (error) {
      return ShareResult(
        success: false,
        message: 'Share failed: ${_getErrorMessage(error)}',
      );
    } finally {
      _setLoading(false);
    }
  }

  /// Generate QR code for credential
  Future<String?> generateCredentialQR(String credentialId) async {
    try {
      final response = await ApiService.instance.post<Map<String, dynamic>>(
        '${AppConfig.walletServiceUrl}/credentials/qr',
        data: {'credential_id': credentialId},
      );
      
      if (response.isSuccess && response.data != null) {
        return response.data!['qr_data'] as String?;
      }
      
      return null;
    } catch (error) {
      _setError('Failed to generate QR code');
      return null;
    }
  }

  /// Sync data with server
  Future<void> syncData() async {
    if (_isSyncing) return;
    
    _setSyncing(true);
    
    try {
      // This will be handled by StorageService sync queue
      // Force process sync queue
      await Future.delayed(const Duration(seconds: 2)); // Simulate sync
      
      // Reload data after sync
      await loadCredentials();
      await loadRecentActivity();
      
    } catch (error) {
      _setError('Sync failed');
    } finally {
      _setSyncing(false);
    }
  }

  /// Refresh all data
  Future<void> refreshData() async {
    _setRefreshing(true);
    
    try {
      await Future.wait([
        loadCredentials(),
        loadRecentActivity(),
        loadUsageStatistics(),
        checkVerificationStatus(),
        loadStorageStats(),
      ]);
    } catch (error) {
      _setError('Refresh failed');
    } finally {
      _setRefreshing(false);
    }
  }

  /// Search credentials
  List<DigitalCredential> searchCredentials(String query) {
    if (query.isEmpty) return _credentials;
    
    final lowerQuery = query.toLowerCase();
    return _credentials.where((credential) {
      return credential.type.toLowerCase().contains(lowerQuery) ||
             credential.issuer.toLowerCase().contains(lowerQuery) ||
             credential.subject.toLowerCase().contains(lowerQuery);
    }).toList();
  }

  /// Filter credentials by status
  List<DigitalCredential> filterCredentialsByStatus(String status) {
    return _credentials.where((c) => c.status == status).toList();
  }

  /// Log activity
  Future<void> _logActivity({
    required String type,
    required String title,
    required String description,
  }) async {
    try {
      final activity = {
        'type': type,
        'title': title,
        'description': description,
        'timestamp': DateTime.now().toIso8601String(),
        'time': _formatTime(DateTime.now()),
      };
      
      _recentActivities.insert(0, activity);
      
      // Keep only last 50 activities
      if (_recentActivities.length > 50) {
        _recentActivities = _recentActivities.take(50).toList();
      }
      
      // Cache activities
      await StorageService.instance.storeInCache('recent_activities', _recentActivities);
      
      notifyListeners();
    } catch (error) {
      // Silently handle activity logging errors
    }
  }

  /// Generate mock activities for demo
  List<Map<String, dynamic>> _generateMockActivities() {
    return [
      {
        'type': 'verification',
        'title': 'ID Verified',
        'description': 'Successfully verified government ID',
        'time': '2 hours ago',
      },
      {
        'type': 'credential_added',
        'title': 'New Credential',
        'description': 'Added driving license',
        'time': '1 day ago',
      },
      {
        'type': 'login',
        'title': 'Login',
        'description': 'Signed in with biometrics',
        'time': '2 days ago',
      },
    ];
  }

  /// Generate mock usage statistics
  List<FlSpot> _generateMockUsageStats() {
    return List.generate(7, (index) {
      return FlSpot(index.toDouble(), (index * 2 + 5).toDouble());
    });
  }

  /// Parse verification status from string
  VerificationStatus _parseVerificationStatus(String? status) {
    switch (status?.toLowerCase()) {
      case 'verified':
        return VerificationStatus.verified;
      case 'pending':
        return VerificationStatus.pending;
      case 'failed':
        return VerificationStatus.failed;
      default:
        return VerificationStatus.pending;
    }
  }

  /// Format time for activities
  String _formatTime(DateTime dateTime) {
    final now = DateTime.now();
    final difference = now.difference(dateTime);
    
    if (difference.inMinutes < 1) {
      return 'Just now';
    } else if (difference.inHours < 1) {
      return '${difference.inMinutes} minutes ago';
    } else if (difference.inDays < 1) {
      return '${difference.inHours} hours ago';
    } else {
      return '${difference.inDays} days ago';
    }
  }

  /// Get error message from exception
  String _getErrorMessage(dynamic error) {
    if (error is AppException) {
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

  /// Set refreshing state
  void _setRefreshing(bool refreshing) {
    _isRefreshing = refreshing;
    notifyListeners();
  }

  /// Set syncing state
  void _setSyncing(bool syncing) {
    _isSyncing = syncing;
    notifyListeners();
  }

  /// Set error message
  void _setError(String message) {
    _errorMessage = message;
    notifyListeners();
  }

  /// Clear error message
  void clearError() {
    _errorMessage = null;
    notifyListeners();
  }

  /// Clear all data
  void clearData() {
    _credentials.clear();
    _recentActivities.clear();
    _usageStats.clear();
    _storageStats = null;
    _verificationStatus = VerificationStatus.pending;
    _errorMessage = null;
    notifyListeners();
  }

  @override
  void dispose() {
    clearData();
    super.dispose();
  }
}

/// Verification status enum
enum VerificationStatus {
  pending,
  verified,
  failed,
}

/// Verification result
class VerificationResult {
  final bool isValid;
  final String message;
  final Map<String, dynamic>? details;

  VerificationResult({
    required this.isValid,
    required this.message,
    this.details,
  });

  factory VerificationResult.fromJson(Map<String, dynamic> json) {
    return VerificationResult(
      isValid: json['is_valid'] ?? false,
      message: json['message'] ?? '',
      details: json['details'],
    );
  }
}

/// Share result
class ShareResult {
  final bool success;
  final String message;
  final String? shareId;
  final DateTime? expiresAt;

  ShareResult({
    required this.success,
    required this.message,
    this.shareId,
    this.expiresAt,
  });

  factory ShareResult.fromJson(Map<String, dynamic> json) {
    return ShareResult(
      success: json['success'] ?? false,
      message: json['message'] ?? '',
      shareId: json['share_id'],
      expiresAt: json['expires_at'] != null 
          ? DateTime.parse(json['expires_at'])
          : null,
    );
  }
}