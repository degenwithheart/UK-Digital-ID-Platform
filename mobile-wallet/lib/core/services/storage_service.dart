/// Storage Service
/// 
/// Comprehensive offline-first storage service with Hive database,
/// secure storage, file management, and data synchronization

import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';
import 'package:hive_flutter/hive_flutter.dart';
import 'package:path_provider/path_provider.dart';
import 'package:sqflite/sqflite.dart';
import '../config/app_config.dart';
import '../error/error_handler.dart';
import 'security_service.dart';
import 'api_service.dart';

/// Storage Service Implementation
class StorageService {
  static StorageService? _instance;
  static StorageService get instance => _instance ??= StorageService._();
  StorageService._();

  Database? _database;
  late Box<dynamic> _cacheBox;
  late Box<dynamic> _userBox;
  late Box<dynamic> _credentialsBox;
  late Box<dynamic> _settingsBox;
  
  bool _isInitialized = false;
  final Set<String> _pendingSyncOperations = <String>{};

  /// Initialize storage service
  Future<void> initialize() async {
    try {
      if (_isInitialized) return;

      // Initialize Hive
      await _initializeHive();
      
      // Initialize SQLite
      await _initializeSQLite();
      
      // Setup data synchronization
      _setupSyncScheduler();
      
      _isInitialized = true;
    } catch (error, stackTrace) {
      throw StorageException(
        'Failed to initialize storage service: ${error.toString()}',
        errorType: StorageErrorType.unknown,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Initialize Hive database
  Future<void> _initializeHive() async {
    await Hive.initFlutter();
    
    // Register adapters for custom objects
    _registerHiveAdapters();
    
    // Open boxes with encryption
    final encryptionKey = await _getEncryptionKey();
    
    _cacheBox = await Hive.openBox(
      'cache_box',
      encryptionCipher: HiveAesCipher(encryptionKey),
    );
    
    _userBox = await Hive.openBox(
      'user_box',
      encryptionCipher: HiveAesCipher(encryptionKey),
    );
    
    _credentialsBox = await Hive.openBox(
      'credentials_box',
      encryptionCipher: HiveAesCipher(encryptionKey),
    );
    
    _settingsBox = await Hive.openBox(
      'settings_box',
      encryptionCipher: HiveAesCipher(encryptionKey),
    );
  }

  /// Initialize SQLite database
  Future<void> _initializeSQLite() async {
    final documentsDirectory = await getApplicationDocumentsDirectory();
    final path = '${documentsDirectory.path}/${AppConfig.dbName}';
    
    _database = await openDatabase(
      path,
      version: AppConfig.dbVersion,
      onCreate: _createDatabase,
      onUpgrade: _upgradeDatabase,
      onConfigure: (db) async {
        await db.execute('PRAGMA foreign_keys = ON');
        await db.execute('PRAGMA journal_mode = WAL');
      },
    );
  }

  /// Create database tables
  Future<void> _createDatabase(Database db, int version) async {
    // Credentials table
    await db.execute('''
      CREATE TABLE credentials (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        issuer TEXT NOT NULL,
        subject TEXT NOT NULL,
        data TEXT NOT NULL,
        encrypted_data TEXT,
        issued_at INTEGER NOT NULL,
        expires_at INTEGER,
        revoked_at INTEGER,
        status TEXT DEFAULT 'active',
        verification_count INTEGER DEFAULT 0,
        last_used INTEGER,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        synced INTEGER DEFAULT 0
      )
    ''');

    // Verification history table
    await db.execute('''
      CREATE TABLE verification_history (
        id TEXT PRIMARY KEY,
        credential_id TEXT NOT NULL,
        verifier_id TEXT NOT NULL,
        verification_type TEXT NOT NULL,
        result TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        location TEXT,
        metadata TEXT,
        created_at INTEGER NOT NULL,
        synced INTEGER DEFAULT 0,
        FOREIGN KEY (credential_id) REFERENCES credentials (id)
      )
    ''');

    // Audit logs table
    await db.execute('''
      CREATE TABLE audit_logs (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        action TEXT NOT NULL,
        resource_type TEXT NOT NULL,
        resource_id TEXT,
        old_values TEXT,
        new_values TEXT,
        ip_address TEXT,
        user_agent TEXT,
        timestamp INTEGER NOT NULL,
        synced INTEGER DEFAULT 0
      )
    ''');

    // Sync queue table
    await db.execute('''
      CREATE TABLE sync_queue (
        id TEXT PRIMARY KEY,
        operation_type TEXT NOT NULL,
        table_name TEXT NOT NULL,
        record_id TEXT NOT NULL,
        data TEXT NOT NULL,
        attempts INTEGER DEFAULT 0,
        max_attempts INTEGER DEFAULT 3,
        created_at INTEGER NOT NULL,
        scheduled_at INTEGER NOT NULL,
        last_error TEXT
      )
    ''');

    // File metadata table
    await db.execute('''
      CREATE TABLE file_metadata (
        id TEXT PRIMARY KEY,
        file_path TEXT NOT NULL,
        file_name TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        mime_type TEXT NOT NULL,
        hash TEXT NOT NULL,
        encrypted INTEGER DEFAULT 0,
        uploaded INTEGER DEFAULT 0,
        upload_url TEXT,
        created_at INTEGER NOT NULL,
        synced INTEGER DEFAULT 0
      )
    ''');

    // Create indexes
    await _createIndexes(db);
  }

  /// Create database indexes
  Future<void> _createIndexes(Database db) async {
    await db.execute('CREATE INDEX idx_credentials_type ON credentials(type)');
    await db.execute('CREATE INDEX idx_credentials_status ON credentials(status)');
    await db.execute('CREATE INDEX idx_credentials_expires ON credentials(expires_at)');
    await db.execute('CREATE INDEX idx_verification_credential ON verification_history(credential_id)');
    await db.execute('CREATE INDEX idx_verification_timestamp ON verification_history(timestamp)');
    await db.execute('CREATE INDEX idx_audit_user ON audit_logs(user_id)');
    await db.execute('CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp)');
    await db.execute('CREATE INDEX idx_sync_queue_scheduled ON sync_queue(scheduled_at)');
  }

  /// Upgrade database schema
  Future<void> _upgradeDatabase(Database db, int oldVersion, int newVersion) async {
    // Handle database migrations based on version
    // Implementation would depend on specific migration needs
  }

  /// Register Hive adapters
  void _registerHiveAdapters() {
    // Register custom type adapters if needed
    // Hive.registerAdapter(CustomObjectAdapter());
  }

  /// Get encryption key for Hive
  Future<List<int>> _getEncryptionKey() async {
    String? keyString = await SecurityService.instance.retrieveSecurely('hive_key');
    
    if (keyString == null) {
      // Generate new key
      final key = Hive.generateSecureKey();
      keyString = base64.encode(key);
      await SecurityService.instance.storeSecurely('hive_key', keyString);
      return key;
    }
    
    return base64.decode(keyString);
  }

  /// Store data in cache
  Future<void> storeInCache(String key, dynamic data, {Duration? ttl}) async {
    try {
      if (!_isInitialized) await initialize();
      
      final cacheEntry = CacheEntry(
        data: data,
        timestamp: DateTime.now(),
        ttl: ttl ?? AppConfig.cacheExpiration,
      );
      
      await _cacheBox.put(key, cacheEntry.toJson());
    } catch (error, stackTrace) {
      throw StorageException(
        'Failed to store cache data: ${error.toString()}',
        errorType: StorageErrorType.unknown,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Retrieve data from cache
  Future<T?> retrieveFromCache<T>(String key) async {
    try {
      if (!_isInitialized) await initialize();
      
      final cacheData = _cacheBox.get(key);
      if (cacheData == null) return null;
      
      final cacheEntry = CacheEntry.fromJson(cacheData);
      
      // Check if cache entry has expired
      if (cacheEntry.isExpired) {
        await _cacheBox.delete(key);
        return null;
      }
      
      return cacheEntry.data as T?;
    } catch (error, stackTrace) {
      throw StorageException(
        'Failed to retrieve cache data: ${error.toString()}',
        errorType: StorageErrorType.corruptedData,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Store user data
  Future<void> storeUserData(String key, dynamic data) async {
    try {
      if (!_isInitialized) await initialize();
      await _userBox.put(key, data);
    } catch (error, stackTrace) {
      throw StorageException(
        'Failed to store user data: ${error.toString()}',
        errorType: StorageErrorType.unknown,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Retrieve user data
  Future<T?> retrieveUserData<T>(String key) async {
    try {
      if (!_isInitialized) await initialize();
      return _userBox.get(key) as T?;
    } catch (error, stackTrace) {
      throw StorageException(
        'Failed to retrieve user data: ${error.toString()}',
        errorType: StorageErrorType.corruptedData,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Store credential
  Future<void> storeCredential(DigitalCredential credential) async {
    try {
      if (!_isInitialized) await initialize();
      
      final encryptedData = await SecurityService.instance.encrypt(
        json.encode(credential.sensitiveData),
      );
      
      await _database!.insert(
        'credentials',
        {
          'id': credential.id,
          'type': credential.type,
          'issuer': credential.issuer,
          'subject': credential.subject,
          'data': json.encode(credential.toJson()),
          'encrypted_data': encryptedData,
          'issued_at': credential.issuedAt.millisecondsSinceEpoch,
          'expires_at': credential.expiresAt?.millisecondsSinceEpoch,
          'status': credential.status,
          'created_at': DateTime.now().millisecondsSinceEpoch,
          'updated_at': DateTime.now().millisecondsSinceEpoch,
          'synced': 0,
        },
        conflictAlgorithm: ConflictAlgorithm.replace,
      );
      
      // Add to sync queue
      await _addToSyncQueue('INSERT', 'credentials', credential.id, credential.toJson());
      
    } catch (error, stackTrace) {
      throw StorageException(
        'Failed to store credential: ${error.toString()}',
        errorType: StorageErrorType.unknown,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Retrieve credentials
  Future<List<DigitalCredential>> getCredentials({
    String? type,
    String? status,
    int? limit,
    int? offset,
  }) async {
    try {
      if (!_isInitialized) await initialize();
      
      String whereClause = '1=1';
      List<dynamic> whereArgs = [];
      
      if (type != null) {
        whereClause += ' AND type = ?';
        whereArgs.add(type);
      }
      
      if (status != null) {
        whereClause += ' AND status = ?';
        whereArgs.add(status);
      }
      
      final result = await _database!.query(
        'credentials',
        where: whereClause,
        whereArgs: whereArgs.isNotEmpty ? whereArgs : null,
        orderBy: 'created_at DESC',
        limit: limit,
        offset: offset,
      );
      
      final credentials = <DigitalCredential>[];
      
      for (final row in result) {
        final credentialData = json.decode(row['data'] as String);
        
        // Decrypt sensitive data
        if (row['encrypted_data'] != null) {
          final decryptedData = await SecurityService.instance.decrypt(
            row['encrypted_data'] as String,
          );
          credentialData['sensitiveData'] = json.decode(decryptedData);
        }
        
        credentials.add(DigitalCredential.fromJson(credentialData));
      }
      
      return credentials;
    } catch (error, stackTrace) {
      throw StorageException(
        'Failed to retrieve credentials: ${error.toString()}',
        errorType: StorageErrorType.corruptedData,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Update credential
  Future<void> updateCredential(DigitalCredential credential) async {
    try {
      if (!_isInitialized) await initialize();
      
      final encryptedData = await SecurityService.instance.encrypt(
        json.encode(credential.sensitiveData),
      );
      
      await _database!.update(
        'credentials',
        {
          'data': json.encode(credential.toJson()),
          'encrypted_data': encryptedData,
          'status': credential.status,
          'updated_at': DateTime.now().millisecondsSinceEpoch,
          'synced': 0,
        },
        where: 'id = ?',
        whereArgs: [credential.id],
      );
      
      // Add to sync queue
      await _addToSyncQueue('UPDATE', 'credentials', credential.id, credential.toJson());
      
    } catch (error, stackTrace) {
      throw StorageException(
        'Failed to update credential: ${error.toString()}',
        errorType: StorageErrorType.unknown,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Delete credential
  Future<void> deleteCredential(String credentialId) async {
    try {
      if (!_isInitialized) await initialize();
      
      await _database!.delete(
        'credentials',
        where: 'id = ?',
        whereArgs: [credentialId],
      );
      
      // Add to sync queue
      await _addToSyncQueue('DELETE', 'credentials', credentialId, {});
      
    } catch (error, stackTrace) {
      throw StorageException(
        'Failed to delete credential: ${error.toString()}',
        errorType: StorageErrorType.unknown,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Store file
  Future<String> storeFile(
    String fileName,
    Uint8List fileData, {
    bool encrypt = true,
    String? mimeType,
  }) async {
    try {
      if (!_isInitialized) await initialize();
      
      // Check file size
      if (fileData.length > AppConfig.maxFileSize) {
        throw StorageException(
          'File size exceeds maximum limit',
          errorType: StorageErrorType.insufficientSpace,
        );
      }
      
      final documentsDirectory = await getApplicationDocumentsDirectory();
      final filesDirectory = Directory('${documentsDirectory.path}/files');
      
      if (!await filesDirectory.exists()) {
        await filesDirectory.create(recursive: true);
      }
      
      final fileId = SecurityService.instance.generateSecureRandomString(32);
      final filePath = '${filesDirectory.path}/$fileId';
      
      Uint8List dataToWrite = fileData;
      
      // Encrypt file if required
      if (encrypt) {
        final encryptedData = await SecurityService.instance.encrypt(
          base64.encode(fileData),
        );
        dataToWrite = utf8.encode(encryptedData);
      }
      
      // Write file
      final file = File(filePath);
      await file.writeAsBytes(dataToWrite);
      
      // Calculate hash
      final hash = SecurityService.instance.generateHash(base64.encode(fileData));
      
      // Store metadata
      await _database!.insert('file_metadata', {
        'id': fileId,
        'file_path': filePath,
        'file_name': fileName,
        'file_size': fileData.length,
        'mime_type': mimeType ?? 'application/octet-stream',
        'hash': hash,
        'encrypted': encrypt ? 1 : 0,
        'created_at': DateTime.now().millisecondsSinceEpoch,
        'synced': 0,
      });
      
      return fileId;
    } catch (error, stackTrace) {
      throw StorageException(
        'Failed to store file: ${error.toString()}',
        errorType: StorageErrorType.unknown,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Retrieve file
  Future<Uint8List?> retrieveFile(String fileId) async {
    try {
      if (!_isInitialized) await initialize();
      
      final metadata = await _database!.query(
        'file_metadata',
        where: 'id = ?',
        whereArgs: [fileId],
      );
      
      if (metadata.isEmpty) return null;
      
      final filePath = metadata.first['file_path'] as String;
      final isEncrypted = (metadata.first['encrypted'] as int) == 1;
      
      final file = File(filePath);
      if (!await file.exists()) return null;
      
      final fileData = await file.readAsBytes();
      
      if (isEncrypted) {
        final encryptedString = utf8.decode(fileData);
        final decryptedString = await SecurityService.instance.decrypt(encryptedString);
        return base64.decode(decryptedString);
      }
      
      return fileData;
    } catch (error, stackTrace) {
      throw StorageException(
        'Failed to retrieve file: ${error.toString()}',
        errorType: StorageErrorType.corruptedData,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Log audit event
  Future<void> logAuditEvent({
    required String userId,
    required String action,
    required String resourceType,
    String? resourceId,
    Map<String, dynamic>? oldValues,
    Map<String, dynamic>? newValues,
    String? ipAddress,
    String? userAgent,
  }) async {
    try {
      if (!_isInitialized) await initialize();
      
      final auditId = SecurityService.instance.generateSecureRandomString(32);
      
      await _database!.insert('audit_logs', {
        'id': auditId,
        'user_id': userId,
        'action': action,
        'resource_type': resourceType,
        'resource_id': resourceId,
        'old_values': oldValues != null ? json.encode(oldValues) : null,
        'new_values': newValues != null ? json.encode(newValues) : null,
        'ip_address': ipAddress,
        'user_agent': userAgent,
        'timestamp': DateTime.now().millisecondsSinceEpoch,
        'synced': 0,
      });
      
      // Add to sync queue
      await _addToSyncQueue('INSERT', 'audit_logs', auditId, {
        'user_id': userId,
        'action': action,
        'resource_type': resourceType,
        'resource_id': resourceId,
        'old_values': oldValues,
        'new_values': newValues,
        'ip_address': ipAddress,
        'user_agent': userAgent,
      });
      
    } catch (error, stackTrace) {
      throw StorageException(
        'Failed to log audit event: ${error.toString()}',
        errorType: StorageErrorType.unknown,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Add to sync queue
  Future<void> _addToSyncQueue(
    String operationType,
    String tableName,
    String recordId,
    Map<String, dynamic> data,
  ) async {
    final syncId = SecurityService.instance.generateSecureRandomString(32);
    
    await _database!.insert('sync_queue', {
      'id': syncId,
      'operation_type': operationType,
      'table_name': tableName,
      'record_id': recordId,
      'data': json.encode(data),
      'created_at': DateTime.now().millisecondsSinceEpoch,
      'scheduled_at': DateTime.now().millisecondsSinceEpoch,
    });
  }

  /// Setup sync scheduler
  void _setupSyncScheduler() {
    Timer.periodic(const Duration(minutes: 5), (timer) {
      _processSyncQueue();
    });
  }

  /// Process sync queue
  Future<void> _processSyncQueue() async {
    try {
      if (_pendingSyncOperations.isNotEmpty) return; // Already syncing
      
      final pendingSync = await _database!.query(
        'sync_queue',
        where: 'scheduled_at <= ?',
        whereArgs: [DateTime.now().millisecondsSinceEpoch],
        orderBy: 'created_at ASC',
        limit: 10,
      );
      
      for (final syncItem in pendingSync) {
        final syncId = syncItem['id'] as String;
        _pendingSyncOperations.add(syncId);
        
        try {
          await _syncItem(syncItem);
          
          // Remove from queue on success
          await _database!.delete(
            'sync_queue',
            where: 'id = ?',
            whereArgs: [syncId],
          );
        } catch (e) {
          // Update error and attempts
          final attempts = (syncItem['attempts'] as int) + 1;
          final maxAttempts = syncItem['max_attempts'] as int;
          
          if (attempts >= maxAttempts) {
            // Remove failed item after max attempts
            await _database!.delete(
              'sync_queue',
              where: 'id = ?',
              whereArgs: [syncId],
            );
          } else {
            // Update attempts and reschedule
            await _database!.update(
              'sync_queue',
              {
                'attempts': attempts,
                'last_error': e.toString(),
                'scheduled_at': DateTime.now()
                    .add(Duration(minutes: attempts * 5))
                    .millisecondsSinceEpoch,
              },
              where: 'id = ?',
              whereArgs: [syncId],
            );
          }
        } finally {
          _pendingSyncOperations.remove(syncId);
        }
      }
    } catch (e) {
      // Handle sync processing error
    }
  }

  /// Sync individual item
  Future<void> _syncItem(Map<String, Object?> syncItem) async {
    final operationType = syncItem['operation_type'] as String;
    final tableName = syncItem['table_name'] as String;
    final recordId = syncItem['record_id'] as String;
    final data = json.decode(syncItem['data'] as String);
    
    switch (tableName) {
      case 'credentials':
        await _syncCredential(operationType, recordId, data);
        break;
      case 'audit_logs':
        await _syncAuditLog(operationType, recordId, data);
        break;
      // Add more table sync handlers as needed
    }
  }

  /// Sync credential
  Future<void> _syncCredential(
    String operationType,
    String recordId,
    Map<String, dynamic> data,
  ) async {
    switch (operationType) {
      case 'INSERT':
        await ApiService.instance.post(
          '${AppConfig.credentialsServiceUrl}/credentials',
          data: data,
        );
        break;
      case 'UPDATE':
        await ApiService.instance.put(
          '${AppConfig.credentialsServiceUrl}/credentials/$recordId',
          data: data,
        );
        break;
      case 'DELETE':
        await ApiService.instance.delete(
          '${AppConfig.credentialsServiceUrl}/credentials/$recordId',
        );
        break;
    }
  }

  /// Sync audit log
  Future<void> _syncAuditLog(
    String operationType,
    String recordId,
    Map<String, dynamic> data,
  ) async {
    await ApiService.instance.post(
      '${AppConfig.auditServiceUrl}/logs',
      data: data,
    );
  }

  /// Clear all data
  Future<void> clearAllData() async {
    try {
      if (!_isInitialized) await initialize();
      
      // Clear Hive boxes
      await _cacheBox.clear();
      await _userBox.clear();
      await _credentialsBox.clear();
      await _settingsBox.clear();
      
      // Clear SQLite database
      await _database!.delete('credentials');
      await _database!.delete('verification_history');
      await _database!.delete('audit_logs');
      await _database!.delete('sync_queue');
      await _database!.delete('file_metadata');
      
    } catch (error, stackTrace) {
      throw StorageException(
        'Failed to clear all data: ${error.toString()}',
        errorType: StorageErrorType.unknown,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Get storage statistics
  Future<StorageStats> getStorageStats() async {
    try {
      if (!_isInitialized) await initialize();
      
      final credentialsCount = Sqflite.firstIntValue(
        await _database!.rawQuery('SELECT COUNT(*) FROM credentials'),
      ) ?? 0;
      
      final filesCount = Sqflite.firstIntValue(
        await _database!.rawQuery('SELECT COUNT(*) FROM file_metadata'),
      ) ?? 0;
      
      final totalFileSize = Sqflite.firstIntValue(
        await _database!.rawQuery('SELECT SUM(file_size) FROM file_metadata'),
      ) ?? 0;
      
      return StorageStats(
        credentialsCount: credentialsCount,
        filesCount: filesCount,
        totalFileSize: totalFileSize,
        cacheSize: _cacheBox.length,
      );
    } catch (error, stackTrace) {
      throw StorageException(
        'Failed to get storage stats: ${error.toString()}',
        errorType: StorageErrorType.unknown,
        originalError: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Dispose resources
  Future<void> dispose() async {
    await _database?.close();
    await _cacheBox.close();
    await _userBox.close();
    await _credentialsBox.close();
    await _settingsBox.close();
    _instance = null;
  }
}

/// Cache entry with TTL
class CacheEntry {
  final dynamic data;
  final DateTime timestamp;
  final Duration ttl;

  CacheEntry({
    required this.data,
    required this.timestamp,
    required this.ttl,
  });

  bool get isExpired => DateTime.now().difference(timestamp) > ttl;

  Map<String, dynamic> toJson() {
    return {
      'data': data,
      'timestamp': timestamp.toIso8601String(),
      'ttl_seconds': ttl.inSeconds,
    };
  }

  factory CacheEntry.fromJson(Map<String, dynamic> json) {
    return CacheEntry(
      data: json['data'],
      timestamp: DateTime.parse(json['timestamp']),
      ttl: Duration(seconds: json['ttl_seconds']),
    );
  }
}

/// Digital credential model
class DigitalCredential {
  final String id;
  final String type;
  final String issuer;
  final String subject;
  final Map<String, dynamic> data;
  final Map<String, dynamic> sensitiveData;
  final DateTime issuedAt;
  final DateTime? expiresAt;
  final String status;
  final int verificationCount;
  final DateTime? lastUsed;

  DigitalCredential({
    required this.id,
    required this.type,
    required this.issuer,
    required this.subject,
    required this.data,
    required this.sensitiveData,
    required this.issuedAt,
    this.expiresAt,
    this.status = 'active',
    this.verificationCount = 0,
    this.lastUsed,
  });

  factory DigitalCredential.fromJson(Map<String, dynamic> json) {
    return DigitalCredential(
      id: json['id'],
      type: json['type'],
      issuer: json['issuer'],
      subject: json['subject'],
      data: Map<String, dynamic>.from(json['data'] ?? {}),
      sensitiveData: Map<String, dynamic>.from(json['sensitiveData'] ?? {}),
      issuedAt: DateTime.parse(json['issuedAt']),
      expiresAt: json['expiresAt'] != null ? DateTime.parse(json['expiresAt']) : null,
      status: json['status'] ?? 'active',
      verificationCount: json['verificationCount'] ?? 0,
      lastUsed: json['lastUsed'] != null ? DateTime.parse(json['lastUsed']) : null,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'type': type,
      'issuer': issuer,
      'subject': subject,
      'data': data,
      'sensitiveData': sensitiveData,
      'issuedAt': issuedAt.toIso8601String(),
      'expiresAt': expiresAt?.toIso8601String(),
      'status': status,
      'verificationCount': verificationCount,
      'lastUsed': lastUsed?.toIso8601String(),
    };
  }

  bool get isExpired => expiresAt != null && DateTime.now().isAfter(expiresAt!);
  bool get isActive => status == 'active' && !isExpired;
}

/// Storage statistics
class StorageStats {
  final int credentialsCount;
  final int filesCount;
  final int totalFileSize;
  final int cacheSize;

  StorageStats({
    required this.credentialsCount,
    required this.filesCount,
    required this.totalFileSize,
    required this.cacheSize,
  });
}