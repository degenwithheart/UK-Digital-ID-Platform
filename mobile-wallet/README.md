# 📱 Mobile Wallet (Flutter)

Cross-platform digital identity wallet application with advanced security, biometric authentication, and comprehensive credential management for iOS and Android.

## 🎯 Features

- **Flutter 3.13+**: Modern cross-platform framework with Material Design 3.0 and Cupertino widgets
- **Multi-Platform Security**: Local Auth biometrics, Secure Storage, Firebase Auth integration, Google Sign-In
- **Real-time Sync**: WebSocket integration for live credential updates and government feed synchronization
- **Advanced Storage**: Hive NoSQL database, SQLite relational database, encrypted SharedPreferences with AES
- **QR Code Integration**: Built-in scanner and generator for credential verification and sharing
- **Rich UI**: Lottie animations, staggered animations, responsive design with ScreenUtil
- **State Management**: BLoC pattern with Provider, reactive programming with GetX navigation

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  Flutter Presentation Layer                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Screens   │  │   Widgets   │  │ Animations  │         │
│  │ (Material3) │  │ (Cupertino) │  │  (Lottie)   │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
         │                      │                      │
┌─────────▼──────────┐  ┌───────▼────────┐  ┌─────────▼────────┐
│   State Mgmt       │  │   Navigation   │  │     Camera       │
│ • BLoC + Provider  │  │ • GetX Router  │  │ • QR Scanner     │
│ • Reactive Streams │  │ • Deep Linking │  │ • QR Generator   │
└────────────────────┘  └────────────────┘  └──────────────────┘
         │                      │                      │
┌─────────▼──────────────────────▼──────────────────────▼──────┐
│                     Service Layer                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │    Auth     │  │   Network   │  │   Storage   │         │
│  │ • Local     │  │ • Dio HTTP  │  │ • Hive DB   │         │
│  │ • Firebase  │  │ • WebSocket │  │ • SQLite    │         │
│  │ • Google    │  │ • Retrofit  │  │ • Secure    │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │   API Gateway       │
                    │ (Go Backend 8081)   │
                    └─────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │   WebSocket Sync    │
                    │ (Real-time Events)  │
                    └─────────────────────┘
```

## 📦 Key Dependencies & Capabilities

| Category | Package | Purpose | Version |
|----------|---------|---------|---------|
| **UI Framework** | flutter | Cross-platform UI toolkit | 3.13+ |
| **State Management** | flutter_bloc, provider | Reactive state with BLoC pattern | 8.1.3, 6.1.1 |
| **Navigation** | get | Advanced routing and dependency injection | 4.6.6 |
| **Networking** | dio, retrofit, http, web_socket_channel | HTTP client with WebSocket sync | 5.3.2, 4.0.3, latest, 2.4.0 |
| **Authentication** | local_auth, firebase_auth | Biometric + Firebase integration | 2.1.7, 4.15.3 |
| **Storage** | hive, sqflite, flutter_secure_storage | NoSQL + SQL + encrypted storage | 2.2.3, 2.3.0, 9.0.0 |
| **Camera** | camera, qr_code_scanner | Camera access + QR scanning | 0.10.5, 1.0.1 |
| **UI Components** | flutter_screenutil, lottie | Responsive design + animations | 5.9.0, 2.7.0 |

## Core Screens

### Authentication Flow
- **Login Screen**: Email/password authentication with biometric option
- **Registration Screen**: New user account creation
- **Biometric Setup**: Configure fingerprint/Face ID authentication
- **Dashboard**: Main credential overview and quick actions

### Credential Management
- **Credential List**: Display all stored digital credentials
- **Credential Detail**: View specific credential information
- **QR Code Display**: Generate QR codes for credential sharing
- **Verification History**: Track credential usage and verifications

## Security Features

### Biometric Authentication
```dart
Future<bool> _authenticateBiometric() async {
  return await _localAuth.authenticate(
    localizedReason: 'Authenticate to access your digital ID',
    options: AuthenticationOptions(
      stickyAuth: true,
      biometricOnly: true,
    ),
  );
}
```

### Secure Storage
```dart
// Store AES-encrypted credentials locally
await _secureStorage.write(key: 'credential_$id', value: encryptedData);

// Retrieve and decrypt credentials
String? credential = await _secureStorage.read(key: 'credential_$id');
```

### Network Security
- **HTTPS Only**: All API communication uses TLS encryption
- **Certificate Pinning**: Prevent man-in-the-middle attacks
- **Request Timeouts**: 5-second timeouts prevent hanging connections
- **Error Sanitization**: Sensitive data not exposed in error messages

## 🔄 Sync Capabilities

- **WebSocket Integration**: Real-time synchronization with government feed updates
- **Event-Driven Updates**: Live credential status changes and verification notifications
- **Provider Event Handling**: BLoC pattern integration for reactive sync state management
- **Background Sync**: Automatic credential updates without user interaction
- **Offline-Online Transition**: Seamless sync resumption when connectivity returns

## API Integration

### Authentication Endpoints
```dart
// User login
final response = await http.post(
  Uri.parse('https://gateway:8080/login'),
  headers: {'Content-Type': 'application/json'},
  body: jsonEncode({
    'email': email,
    'password': password,
  }),
).timeout(Duration(seconds: 5));
```

### Credential Operations
```dart
// Fetch user credentials
final response = await http.get(
  Uri.parse('https://gateway:8080/credential/$id'),
  headers: {
    'Authorization': 'Bearer $token',
    'Content-Type': 'application/json',
  },
).timeout(Duration(seconds: 5));
```

## UI Components

### Custom Widgets
- **CredentialCard**: Displays credential information with status indicators
- **BiometricButton**: Biometric authentication trigger with fallback
- **SecureTextField**: Password input with visibility toggle
- **LoadingOverlay**: Network operation progress indication

### Navigation
```dart
// Route definitions
MaterialPageRoute(builder: (context) => DashboardScreen())
MaterialPageRoute(builder: (context) => CredentialDetailScreen(credential))
MaterialPageRoute(builder: (context) => SettingsScreen())
```

## State Management

### Local State
- **StatefulWidget**: Screen-level state management
- **TextEditingController**: Form input handling
- **FutureBuilder**: Async operation UI updates

### Persistent State
- **SharedPreferences**: User settings and preferences
- **SecureStorage**: Sensitive data (tokens, credentials)
- **Local Database**: Offline credential caching (sqflite)

## Offline Capabilities

### Credential Caching
- **Local Storage**: Encrypted credentials stored on device
- **Sync Strategy**: Background sync when network available
- **Conflict Resolution**: Server-side changes take precedence
- **Offline Verification**: Local credential validation without network

### Data Synchronization
```dart
Future<void> syncCredentials() async {
  // Check network connectivity
  if (await Connectivity().checkConnectivity() == ConnectivityResult.none) {
    return; // Skip sync if offline
  }
  
  // Fetch latest credentials from server
  final serverCredentials = await fetchCredentialsFromServer();
  
  // Update local storage
  await updateLocalCredentials(serverCredentials);
}
```

## Error Handling

### Network Errors
```dart
try {
  final response = await http.post(...).timeout(Duration(seconds: 5));
} on TimeoutException {
  showError('Request timeout - please try again');
} on SocketException {
  showError('Network error - check your connection');
} catch (e) {
  showError('An unexpected error occurred');
}
```

### User Feedback
- **SnackBar Messages**: Non-intrusive error/success notifications
- **Loading Indicators**: Visual feedback during network operations
- **Error Screens**: Dedicated screens for critical failures
- **Retry Mechanisms**: Allow users to retry failed operations

## Platform-Specific Features

### iOS Integration
- **Face ID**: Native biometric authentication
- **Keychain**: Secure credential storage
- **App Transport Security**: Enforced HTTPS connections
- **Background Processing**: Limited background sync capabilities

### Android Integration
- **Fingerprint**: Native biometric authentication  
- **Keystore**: Hardware-backed secure storage
- **Network Security Config**: Certificate pinning configuration
- **Background Tasks**: Scheduled credential sync

## Building & Deployment

### Development
```bash
flutter pub get              # Install dependencies
flutter run                  # Debug build
flutter test                 # Run unit tests
flutter analyze             # Static analysis
```

### Production
```bash
# iOS Release
flutter build ios --release

# Android Release  
flutter build apk --release
flutter build appbundle --release
```

## Dependencies

### Core Flutter
- **flutter/material.dart**: Material Design components
- **flutter/services.dart**: Platform channel communication

### Networking
- **http**: HTTP client for API communication
- **connectivity_plus**: Network connectivity detection

### Security
- **flutter_secure_storage**: Encrypted local storage
- **local_auth**: Biometric authentication
- **crypto**: Cryptographic operations

### UI/UX
- **shared_preferences**: User preferences storage
- **path_provider**: File system path access

## Performance Optimizations

- **Lazy Loading**: Load credentials on-demand
- **Image Caching**: Cache profile pictures and QR codes
- **Memory Management**: Dispose controllers and streams
- **Build Optimizations**: Tree shaking and code splitting
- **Network Caching**: Cache API responses where appropriate

## Testing Strategy

### Unit Tests
```dart
testWidgets('Login form validation', (WidgetTester tester) async {
  await tester.pumpWidget(MyApp());
  
  // Test empty form submission
  await tester.tap(find.byType(ElevatedButton));
  await tester.pump();
  
  expect(find.text('Please enter email'), findsOneWidget);
});
```

### Integration Tests
- **API Integration**: Test network request/response handling
- **Biometric Flow**: Test authentication with mock biometrics
- **Offline Mode**: Test offline credential access
- **Error Recovery**: Test error state transitions

## Security Considerations

- **Data Encryption**: All stored credentials encrypted at rest
- **Certificate Validation**: Validate server certificates
- **Input Sanitization**: Prevent injection attacks in forms
- **Session Management**: Automatic token refresh and logout
- **Biometric Fallback**: PIN/password fallback when biometrics fail