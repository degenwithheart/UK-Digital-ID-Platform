/// API Service
/// 
/// Comprehensive networking service with retry logic, caching, authentication,
/// error handling, and real-time capabilities

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:dio/dio.dart';
import 'package:dio_cache_interceptor/dio_cache_interceptor.dart';
import 'package:dio_certificate_pinning/dio_certificate_pinning.dart';
import 'package:connectivity_plus/connectivity_plus.dart';
import 'package:web_socket_channel/web_socket_channel.dart';
import '../config/app_config.dart';
import '../error/error_handler.dart';
import 'security_service.dart';

/// API Service Implementation
class ApiService {
  static ApiService? _instance;
  static ApiService get instance => _instance ??= ApiService._();
  ApiService._();

  late final Dio _dio;
  late final CacheStore _cacheStore;
  final Connectivity _connectivity = Connectivity();
  
  final Map<String, WebSocketChannel> _wsConnections = {};
  final Map<String, StreamController> _wsStreams = {};
  
  Timer? _retryTimer;
  bool _isInitialized = false;

  /// Initialize API service
  Future<void> initialize() async {
    try {
      if (_isInitialized) return;

      await _setupDio();
      await _setupCache();
      await _setupInterceptors();
      
      _isInitialized = true;
    } catch (error, stackTrace) {
      throw NetworkException(
        'Failed to initialize API service: ${error.toString()}',
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Setup Dio HTTP client
  Future<void> _setupDio() async {
    _dio = Dio(BaseOptions(
      baseUrl: AppConfig.baseUrl,
      connectTimeout: AppConfig.connectionTimeout,
      receiveTimeout: AppConfig.receiveTimeout,
      sendTimeout: AppConfig.sendTimeout,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': '${AppConfig.appName}/${AppConfig.appVersion}',
        'X-App-Version': AppConfig.appVersion,
        'X-Platform': Platform.isAndroid ? 'android' : 'ios',
      },
    ));
  }

  /// Setup caching
  Future<void> _setupCache() async {
    _cacheStore = MemCacheStore(
      maxSize: AppConfig.maxCacheSize * 1024 * 1024, // Convert MB to bytes
      maxEntrySize: 1024 * 1024, // 1MB max per entry
    );
  }

  /// Setup interceptors
  Future<void> _setupInterceptors() async {
    // Authentication interceptor
    _dio.interceptors.add(InterceptorsWrapper(
      onRequest: (options, handler) async {
        await _addAuthHeaders(options);
        handler.next(options);
      },
      onError: (error, handler) async {
        if (error.response?.statusCode == 401) {
          // Try to refresh token
          final refreshed = await _refreshToken();
          if (refreshed) {
            // Retry original request
            final retryResponse = await _retryRequest(error.requestOptions);
            handler.resolve(retryResponse);
            return;
          }
        }
        handler.next(error);
      },
    ));

    // Cache interceptor
    _dio.interceptors.add(DioCacheInterceptor(
      options: CacheOptions(
        store: _cacheStore,
        policy: CachePolicy.request,
        hitCacheOnErrorExcept: [401, 403, 500, 502, 503],
        maxStale: AppConfig.cacheExpiration,
        priority: CachePriority.normal,
        cipher: null,
        keyBuilder: (request) {
          return CacheOptions.defaultCacheKeyBuilder(request);
        },
      ),
    ));

    // Retry interceptor
    _dio.interceptors.add(InterceptorsWrapper(
      onError: (error, handler) async {
        if (_shouldRetry(error)) {
          final retryResponse = await _retryWithBackoff(error.requestOptions);
          if (retryResponse != null) {
            handler.resolve(retryResponse);
            return;
          }
        }
        handler.next(error);
      },
    ));

    // Certificate pinning (if enabled)
    if (AppConfig.enableCertificatePinning) {
      _dio.interceptors.add(CertificatePinningInterceptor(
        allowedSHAFingerprints: ['YOUR_CERTIFICATE_SHA_FINGERPRINT'],
      ));
    }

    // Logging interceptor (development only)
    if (AppConfig.environment != Environment.production) {
      _dio.interceptors.add(LogInterceptor(
        requestHeader: true,
        requestBody: true,
        responseHeader: true,
        responseBody: true,
        error: true,
        logPrint: (obj) => print('[API] $obj'),
      ));
    }
  }

  /// Add authentication headers
  Future<void> _addAuthHeaders(RequestOptions options) async {
    final token = await SecurityService.instance.retrieveSecurely('auth_token');
    if (token != null) {
      options.headers['Authorization'] = 'Bearer $token';
    }

    // Add request ID for tracing
    options.headers['X-Request-ID'] = SecurityService.instance
        .generateSecureRandomString(16);

    // Add timestamp
    options.headers['X-Timestamp'] = DateTime.now().millisecondsSinceEpoch.toString();
  }

  /// Refresh authentication token
  Future<bool> _refreshToken() async {
    try {
      final refreshToken = await SecurityService.instance
          .retrieveSecurely('refresh_token');
      
      if (refreshToken == null) return false;

      final response = await _dio.post(
        '${AppConfig.authServiceUrl}/refresh',
        data: {'refresh_token': refreshToken},
        options: Options(
          headers: {'Authorization': null}, // Remove auth header for refresh
        ),
      );

      if (response.statusCode == 200) {
        final data = response.data;
        await SecurityService.instance.storeSecurely(
          'auth_token', 
          data['access_token'],
        );
        
        if (data['refresh_token'] != null) {
          await SecurityService.instance.storeSecurely(
            'refresh_token', 
            data['refresh_token'],
          );
        }
        
        return true;
      }
      
      return false;
    } catch (e) {
      return false;
    }
  }

  /// Retry request
  Future<Response> _retryRequest(RequestOptions options) async {
    return await _dio.request(
      options.path,
      data: options.data,
      queryParameters: options.queryParameters,
      options: Options(
        method: options.method,
        headers: options.headers,
        responseType: options.responseType,
        contentType: options.contentType,
      ),
    );
  }

  /// Check if request should be retried
  bool _shouldRetry(DioError error) {
    // Don't retry client errors (4xx)
    if (error.response?.statusCode != null && 
        error.response!.statusCode! >= 400 && 
        error.response!.statusCode! < 500) {
      return false;
    }

    // Retry network errors and server errors (5xx)
    return error.type == DioErrorType.connectionTimeout ||
           error.type == DioErrorType.receiveTimeout ||
           error.type == DioErrorType.sendTimeout ||
           error.type == DioErrorType.unknown ||
           (error.response?.statusCode != null && 
            error.response!.statusCode! >= 500);
  }

  /// Retry with exponential backoff
  Future<Response?> _retryWithBackoff(RequestOptions options) async {
    int attempts = 0;
    
    while (attempts < AppConfig.maxRetries) {
      attempts++;
      
      // Wait with exponential backoff
      final delay = AppConfig.retryDelay * (1 << (attempts - 1));
      await Future.delayed(delay);
      
      try {
        return await _retryRequest(options);
      } catch (e) {
        if (attempts == AppConfig.maxRetries) {
          rethrow;
        }
      }
    }
    
    return null;
  }

  /// Check network connectivity
  Future<bool> hasInternetConnection() async {
    final connectivityResult = await _connectivity.checkConnectivity();
    return connectivityResult != ConnectivityResult.none;
  }

  /// GET request
  Future<ApiResponse<T>> get<T>(
    String path, {
    Map<String, dynamic>? queryParameters,
    Options? options,
    bool requiresAuth = true,
    bool useCache = true,
  }) async {
    try {
      if (!_isInitialized) await initialize();
      
      final response = await _dio.get(
        path,
        queryParameters: queryParameters,
        options: _buildOptions(options, requiresAuth, useCache),
      );
      
      return ApiResponse<T>.fromResponse(response);
    } catch (error, stackTrace) {
      throw _handleApiError(error, stackTrace, 'GET $path');
    }
  }

  /// POST request
  Future<ApiResponse<T>> post<T>(
    String path, {
    dynamic data,
    Map<String, dynamic>? queryParameters,
    Options? options,
    bool requiresAuth = true,
  }) async {
    try {
      if (!_isInitialized) await initialize();
      
      final response = await _dio.post(
        path,
        data: data,
        queryParameters: queryParameters,
        options: _buildOptions(options, requiresAuth, false),
      );
      
      return ApiResponse<T>.fromResponse(response);
    } catch (error, stackTrace) {
      throw _handleApiError(error, stackTrace, 'POST $path');
    }
  }

  /// PUT request
  Future<ApiResponse<T>> put<T>(
    String path, {
    dynamic data,
    Map<String, dynamic>? queryParameters,
    Options? options,
    bool requiresAuth = true,
  }) async {
    try {
      if (!_isInitialized) await initialize();
      
      final response = await _dio.put(
        path,
        data: data,
        queryParameters: queryParameters,
        options: _buildOptions(options, requiresAuth, false),
      );
      
      return ApiResponse<T>.fromResponse(response);
    } catch (error, stackTrace) {
      throw _handleApiError(error, stackTrace, 'PUT $path');
    }
  }

  /// PATCH request
  Future<ApiResponse<T>> patch<T>(
    String path, {
    dynamic data,
    Map<String, dynamic>? queryParameters,
    Options? options,
    bool requiresAuth = true,
  }) async {
    try {
      if (!_isInitialized) await initialize();
      
      final response = await _dio.patch(
        path,
        data: data,
        queryParameters: queryParameters,
        options: _buildOptions(options, requiresAuth, false),
      );
      
      return ApiResponse<T>.fromResponse(response);
    } catch (error, stackTrace) {
      throw _handleApiError(error, stackTrace, 'PATCH $path');
    }
  }

  /// DELETE request
  Future<ApiResponse<T>> delete<T>(
    String path, {
    dynamic data,
    Map<String, dynamic>? queryParameters,
    Options? options,
    bool requiresAuth = true,
  }) async {
    try {
      if (!_isInitialized) await initialize();
      
      final response = await _dio.delete(
        path,
        data: data,
        queryParameters: queryParameters,
        options: _buildOptions(options, requiresAuth, false),
      );
      
      return ApiResponse<T>.fromResponse(response);
    } catch (error, stackTrace) {
      throw _handleApiError(error, stackTrace, 'DELETE $path');
    }
  }

  /// Upload file
  Future<ApiResponse<T>> uploadFile<T>(
    String path,
    String filePath, {
    String fieldName = 'file',
    Map<String, dynamic>? data,
    ProgressCallback? onProgress,
    Options? options,
    bool requiresAuth = true,
  }) async {
    try {
      if (!_isInitialized) await initialize();
      
      final formData = FormData.fromMap({
        if (data != null) ...data,
        fieldName: await MultipartFile.fromFile(filePath),
      });
      
      final response = await _dio.post(
        path,
        data: formData,
        onSendProgress: onProgress,
        options: _buildOptions(options, requiresAuth, false)
            .copyWith(contentType: 'multipart/form-data'),
      );
      
      return ApiResponse<T>.fromResponse(response);
    } catch (error, stackTrace) {
      throw _handleApiError(error, stackTrace, 'UPLOAD $path');
    }
  }

  /// Download file
  Future<ApiResponse<String>> downloadFile(
    String path,
    String savePath, {
    Map<String, dynamic>? queryParameters,
    ProgressCallback? onProgress,
    Options? options,
    bool requiresAuth = true,
  }) async {
    try {
      if (!_isInitialized) await initialize();
      
      final response = await _dio.download(
        path,
        savePath,
        queryParameters: queryParameters,
        onReceiveProgress: onProgress,
        options: _buildOptions(options, requiresAuth, false),
      );
      
      return ApiResponse<String>(
        data: savePath,
        statusCode: response.statusCode ?? 200,
        message: 'File downloaded successfully',
      );
    } catch (error, stackTrace) {
      throw _handleApiError(error, stackTrace, 'DOWNLOAD $path');
    }
  }

  /// Connect to WebSocket
  Future<Stream<dynamic>> connectWebSocket(
    String endpoint, {
    Map<String, String>? headers,
    Duration? pingInterval,
  }) async {
    try {
      final wsUrl = '${AppConfig.wsBaseUrl}$endpoint';
      final token = await SecurityService.instance.retrieveSecurely('auth_token');
      
      final wsHeaders = <String, String>{
        if (headers != null) ...headers,
        if (token != null) 'Authorization': 'Bearer $token',
      };
      
      final channel = WebSocketChannel.connect(
        Uri.parse(wsUrl),
        protocols: ['echo-protocol'],
      );
      
      _wsConnections[endpoint] = channel;
      
      final streamController = StreamController<dynamic>.broadcast();
      _wsStreams[endpoint] = streamController;
      
      // Listen to messages
      channel.stream.listen(
        (message) {
          final data = json.decode(message);
          streamController.add(data);
        },
        onError: (error) {
          streamController.addError(error);
        },
        onDone: () {
          streamController.close();
          _wsConnections.remove(endpoint);
          _wsStreams.remove(endpoint);
        },
      );
      
      // Setup ping if specified
      if (pingInterval != null) {
        Timer.periodic(pingInterval, (timer) {
          if (_wsConnections.containsKey(endpoint)) {
            channel.sink.add(json.encode({'type': 'ping'}));
          } else {
            timer.cancel();
          }
        });
      }
      
      return streamController.stream;
    } catch (error, stackTrace) {
      throw NetworkException(
        'Failed to connect to WebSocket: ${error.toString()}',
        endpoint: endpoint,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Send WebSocket message
  void sendWebSocketMessage(String endpoint, dynamic message) {
    final channel = _wsConnections[endpoint];
    if (channel != null) {
      channel.sink.add(json.encode(message));
    } else {
      throw NetworkException(
        'WebSocket connection not found for endpoint: $endpoint',
        endpoint: endpoint,
      );
    }
  }

  /// Disconnect WebSocket
  void disconnectWebSocket(String endpoint) {
    final channel = _wsConnections[endpoint];
    final stream = _wsStreams[endpoint];
    
    if (channel != null) {
      channel.sink.close();
      _wsConnections.remove(endpoint);
    }
    
    if (stream != null) {
      stream.close();
      _wsStreams.remove(endpoint);
    }
  }

  /// Disconnect all WebSockets
  void disconnectAllWebSockets() {
    for (final endpoint in _wsConnections.keys.toList()) {
      disconnectWebSocket(endpoint);
    }
  }

  /// Build request options
  Options _buildOptions(Options? options, bool requiresAuth, bool useCache) {
    final baseOptions = options ?? Options();
    
    final headers = <String, dynamic>{
      ...?baseOptions.headers,
    };
    
    if (!useCache) {
      headers['Cache-Control'] = 'no-cache';
    }
    
    return baseOptions.copyWith(headers: headers);
  }

  /// Handle API errors
  AppException _handleApiError(
    dynamic error,
    StackTrace stackTrace,
    String operation,
  ) {
    if (error is DioError) {
      return NetworkException(
        error.message ?? 'Network request failed',
        statusCode: error.response?.statusCode,
        endpoint: operation,
        originalError: error,
        stackTrace: stackTrace,
        context: {
          'operation': operation,
          'request_data': error.requestOptions.data,
          'response_data': error.response?.data,
        },
      );
    }
    
    return NetworkException(
      'Unknown network error: ${error.toString()}',
      originalError: error,
      stackTrace: stackTrace,
      context: {'operation': operation},
    );
  }

  /// Clear cache
  Future<void> clearCache() async {
    await _cacheStore.clean();
  }

  /// Dispose resources
  void dispose() {
    disconnectAllWebSockets();
    _retryTimer?.cancel();
    _dio.close(force: true);
    _instance = null;
  }
}

/// API Response wrapper
class ApiResponse<T> {
  final T? data;
  final int statusCode;
  final String message;
  final Map<String, dynamic>? metadata;

  ApiResponse({
    this.data,
    required this.statusCode,
    required this.message,
    this.metadata,
  });

  factory ApiResponse.fromResponse(Response response) {
    final responseData = response.data;
    
    return ApiResponse<T>(
      data: responseData is Map<String, dynamic> 
          ? responseData['data'] as T? 
          : responseData as T?,
      statusCode: response.statusCode ?? 200,
      message: responseData is Map<String, dynamic> 
          ? responseData['message'] ?? 'Success'
          : 'Success',
      metadata: responseData is Map<String, dynamic> 
          ? responseData['metadata']
          : null,
    );
  }

  bool get isSuccess => statusCode >= 200 && statusCode < 300;
  bool get isError => !isSuccess;
}

/// Network status
enum NetworkStatus {
  connected,
  disconnected,
  poor,
}

/// Request priority
enum RequestPriority {
  low,
  normal,
  high,
  critical,
}