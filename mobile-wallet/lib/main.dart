import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_screenutil/flutter_screenutil.dart';
import 'package:get/get.dart';
import 'package:provider/provider.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_crashlytics/firebase_crashlytics.dart';
import 'package:hive_flutter/hive_flutter.dart';
import 'package:logger/logger.dart';

// Core imports
import 'core/config/app_config.dart';
import 'core/config/theme_config.dart';
import 'core/services/dependency_injection.dart';
import 'core/services/notification_service.dart';
import 'core/services/biometric_service.dart';
import 'core/services/security_service.dart';
import 'core/services/api_service.dart';
import 'core/utils/app_constants.dart';
import 'core/utils/logger_config.dart';

// Feature imports
import 'features/authentication/presentation/providers/auth_provider.dart';
import 'features/wallet/presentation/providers/wallet_provider.dart';
import 'features/credentials/presentation/providers/credentials_provider.dart';
import 'features/verification/presentation/providers/verification_provider.dart';
import 'features/settings/presentation/providers/settings_provider.dart';

// Presentation imports
import 'presentation/routes/app_routes.dart';
import 'presentation/pages/splash_screen.dart';
import 'presentation/widgets/error_boundary.dart';

// Initialize logger
final Logger logger = LoggerConfig.getLogger('main');

Future<void> main() async {
  // Ensure Flutter is initialized
  WidgetsFlutterBinding.ensureInitialized();
  
  try {
    // Initialize core services
    await _initializeApp();
    
    // Run the app with error handling
    FlutterError.onError = (FlutterErrorDetails errorDetails) {
      FirebaseCrashlytics.instance.recordFlutterFatalError(errorDetails);
      logger.e('Flutter Fatal Error: ${errorDetails.exceptionAsString()}');
    };
    
    PlatformDispatcher.instance.onError = (error, stack) {
      FirebaseCrashlytics.instance.recordError(error, stack, fatal: true);
      logger.e('Platform Error: $error\nStack: $stack');
      return true;
    };
    
    runApp(const UKDigitalIDWalletApp());
    
  } catch (e, stackTrace) {
    logger.e('App initialization failed: $e\nStack: $stackTrace');
    // Show error dialog or fallback UI
    runApp(MaterialApp(
      home: Scaffold(
        body: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(Icons.error_outline, size: 64, color: Colors.red),
              const SizedBox(height: 16),
              const Text(
                'App Initialization Failed',
                style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 8),
              Text('Error: ${e.toString()}'),
              const SizedBox(height: 16),
              ElevatedButton(
                onPressed: () => SystemNavigator.pop(),
                child: const Text('Exit App'),
              ),
            ],
          ),
        ),
      ),
    ));
  }
}

Future<void> _initializeApp() async {
  logger.i('Initializing UK Digital ID Wallet App...');
  
  // Set system UI overlay style
  SystemChrome.setSystemUIOverlayStyle(const SystemUiOverlayStyle(
    statusBarColor: Colors.transparent,
    statusBarIconBrightness: Brightness.dark,
  ));
  
  // Lock orientation to portrait
  await SystemChrome.setPreferredOrientations([
    DeviceOrientation.portraitUp,
  ]);
  
  // Initialize Firebase
  await Firebase.initializeApp();
  
  // Initialize Hive local database
  await Hive.initFlutter();
  await _initializeHiveBoxes();
  
  // Initialize dependency injection
  await DependencyInjection.init();
  
  // Initialize core services
  await Get.find<SecurityService>().initialize();
  await Get.find<NotificationService>().initialize();
  await Get.find<BiometricService>().initialize();
  
  logger.i('App initialization completed successfully');
}

Future<void> _initializeHiveBoxes() async {
  // Register adapters if needed
  // Hive.registerAdapter(UserModelAdapter());
  
  // Open boxes
  await Hive.openBox(AppConstants.userBox);
  await Hive.openBox(AppConstants.credentialsBox);
  await Hive.openBox(AppConstants.settingsBox);
  await Hive.openBox(AppConstants.cacheBox);
}

class UKDigitalIDWalletApp extends StatelessWidget {
  const UKDigitalIDWalletApp({super.key});

  @override
  Widget build(BuildContext context) {
    return ScreenUtilInit(
      designSize: const Size(375, 812), // iPhone 13 Pro design size
      minTextAdapt: true,
      splitScreenMode: true,
      builder: (context, child) {
        return MultiProvider(
          providers: [
            ChangeNotifierProvider(create: (_) => Get.find<AuthProvider>()),
            ChangeNotifierProvider(create: (_) => Get.find<WalletProvider>()),
            ChangeNotifierProvider(create: (_) => Get.find<CredentialsProvider>()),
            ChangeNotifierProvider(create: (_) => Get.find<VerificationProvider>()),
            ChangeNotifierProvider(create: (_) => Get.find<SettingsProvider>()),
          ],
          child: GetMaterialApp(
            title: 'UK Digital ID Wallet',
            
            // Theme configuration
            theme: ThemeConfig.lightTheme,
            darkTheme: ThemeConfig.darkTheme,
            themeMode: ThemeMode.system,
            
            // Localization
            locale: const Locale('en', 'GB'),
            fallbackLocale: const Locale('en', 'GB'),
            
            // Navigation
            initialRoute: AppRoutes.splash,
            getPages: AppRoutes.routes,
            
            // Error handling
            builder: (context, widget) {
              return ErrorBoundary(
                child: widget ?? const SizedBox.shrink(),
              );
            },
            
            // Debug configuration
            debugShowCheckedModeBanner: false,
            
            // Performance optimizations
            smartManagement: SmartManagement.full,
            
            // Default transitions
            defaultTransition: Transition.cupertino,
            transitionDuration: const Duration(milliseconds: 300),
            
            home: const SplashScreen(),
          ),
        );
      },
    );
  }
}

class AuthScreen extends StatefulWidget {
  const AuthScreen({super.key});

  @override
  _AuthScreenState createState() => _AuthScreenState();
}

class _AuthScreenState extends State<AuthScreen> {
  final TextEditingController _emailController = TextEditingController();
  final TextEditingController _passwordController = TextEditingController();
  final FlutterSecureStorage _secureStorage = const FlutterSecureStorage();
  final LocalAuthentication _localAuth = LocalAuthentication();

  Future<void> _login() async {
    try {
      final response = await http.post(
        Uri.parse('https://10.0.2.2:8080/login'), // HTTPS
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'email': _emailController.text.trim(),
          'password': _passwordController.text.trim(),
        }),
      ).timeout(const Duration(seconds: 5)); // Timeout

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        await _secureStorage.write(key: 'token', value: data['token']);
        Navigator.pushReplacement(
          context,
          MaterialPageRoute(builder: (context) => DashboardScreen()),
        );
      } else {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Login failed: ${response.body}')),
        );
      }
    } catch (e) {
      print('Login error: $e');
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Network error')),
      );
    }
  }

  Future<void> _biometricAuth() async {
    bool authenticated = false;
    try {
      authenticated = await _localAuth.authenticate(
        localizedReason: 'Authenticate to access your digital ID',
        options: const AuthenticationOptions(
          stickyAuth: true,
          biometricOnly: true,
        ),
      );
    } catch (e) {
      print(e);
    }

    if (authenticated) {
      final token = await _secureStorage.read(key: 'token');
      if (token != null) {
        Navigator.pushReplacement(
          context,
          MaterialPageRoute(builder: (context) => DashboardScreen()),
        );
      } else {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('No stored credentials')),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Login')),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          children: [
            TextField(
              controller: _emailController,
              decoration: const InputDecoration(labelText: 'Email'),
              keyboardType: TextInputType.emailAddress,
            ),
            TextField(
              controller: _passwordController,
              decoration: const InputDecoration(labelText: 'Password'),
              obscureText: true,
            ),
            ElevatedButton(
              onPressed: _login,
              child: const Text('Login'),
            ),
            ElevatedButton(
              onPressed: _biometricAuth,
              child: const Text('Biometric Login'),
            ),
          ],
        ),
      ),
    );
  }
}

class DashboardScreen extends StatelessWidget {
  const DashboardScreen({super.key});

  Future<void> _verifyIdentity(BuildContext context) async {
    const storage = FlutterSecureStorage();
    final token = await storage.read(key: 'token');
    if (token == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('No token found')),
      );
      return;
    }

    final response = await http.post(
      Uri.parse('https://10.0.2.2:8080/verify'),
      headers: {'Authorization': token},
    ).timeout(const Duration(seconds: 5));

    if (response.statusCode == 200) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Identity verified')),
      );
    } else {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Verification failed')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Dashboard')),
      body: Center(
        child: ElevatedButton(
          onPressed: () => _verifyIdentity(context),
          child: const Text('Verify Identity'),
        ),
      ),
    );
  }
}