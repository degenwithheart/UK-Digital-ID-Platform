/// Login Screen
/// 
/// Modern login interface with biometric authentication, social login,
/// and comprehensive form validation

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import 'package:animate_do/animate_do.dart';
import 'package:lottie/lottie.dart';
import 'package:local_auth/local_auth.dart';
import '../../core/config/app_config.dart';
import '../../core/services/auth_service.dart';
import '../../core/services/security_service.dart';
import '../../core/error/error_handler.dart';
import '../providers/auth_provider.dart';
import '../widgets/custom_button.dart';
import '../widgets/custom_text_field.dart';
import '../widgets/loading_overlay.dart';
import '../utils/ui_helpers.dart';
import '../utils/validators.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({Key? key}) : super(key: key);

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen>
    with TickerProviderStateMixin {
  final _formKey = GlobalKey<FormState>();
  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();
  
  late AnimationController _animationController;
  late Animation<double> _fadeAnimation;
  late Animation<Offset> _slideAnimation;
  
  bool _obscurePassword = true;
  bool _rememberMe = false;
  bool _isLoading = false;
  bool _biometricAvailable = false;
  List<BiometricType> _availableBiometrics = [];

  @override
  void initState() {
    super.initState();
    _setupAnimations();
    _checkBiometricAvailability();
    _loadSavedCredentials();
  }

  @override
  void dispose() {
    _animationController.dispose();
    _emailController.dispose();
    _passwordController.dispose();
    super.dispose();
  }

  void _setupAnimations() {
    _animationController = AnimationController(
      duration: const Duration(milliseconds: 1500),
      vsync: this,
    );
    
    _fadeAnimation = Tween<double>(
      begin: 0.0,
      end: 1.0,
    ).animate(CurvedAnimation(
      parent: _animationController,
      curve: const Interval(0.0, 0.6, curve: Curves.easeOut),
    ));
    
    _slideAnimation = Tween<Offset>(
      begin: const Offset(0.0, 0.3),
      end: Offset.zero,
    ).animate(CurvedAnimation(
      parent: _animationController,
      curve: const Interval(0.3, 1.0, curve: Curves.easeOut),
    ));
    
    _animationController.forward();
  }

  Future<void> _checkBiometricAvailability() async {
    try {
      final available = await SecurityService.instance.isBiometricAvailable();
      final biometrics = await SecurityService.instance.getAvailableBiometrics();
      
      if (mounted) {
        setState(() {
          _biometricAvailable = available;
          _availableBiometrics = biometrics;
        });
      }
    } catch (e) {
      // Biometrics not available
    }
  }

  Future<void> _loadSavedCredentials() async {
    try {
      final savedEmail = await SecurityService.instance.retrieveSecurely('saved_email');
      if (savedEmail != null && mounted) {
        _emailController.text = savedEmail;
        setState(() => _rememberMe = true);
      }
    } catch (e) {
      // No saved credentials
    }
  }

  Future<void> _handleEmailLogin() async {
    if (!_formKey.currentState!.validate()) return;
    
    setState(() => _isLoading = true);
    
    try {
      final authProvider = Provider.of<AuthProvider>(context, listen: false);
      
      final result = await authProvider.loginWithEmailPassword(
        _emailController.text.trim(),
        _passwordController.text,
        rememberMe: _rememberMe,
      );
      
      if (result.success) {
        // Save email if remember me is checked
        if (_rememberMe) {
          await SecurityService.instance.storeSecurely(
            'saved_email',
            _emailController.text.trim(),
          );
        } else {
          await SecurityService.instance.deleteSecurely('saved_email');
        }
        
        // Navigate to main app
        if (mounted) {
          Navigator.of(context).pushReplacementNamed('/home');
        }
      } else {
        _showErrorMessage(result.message);
      }
    } catch (error) {
      _handleError(error);
    } finally {
      if (mounted) {
        setState(() => _isLoading = false);
      }
    }
  }

  Future<void> _handleBiometricLogin() async {
    if (!_biometricAvailable) {
      _showErrorMessage('Biometric authentication is not available');
      return;
    }
    
    setState(() => _isLoading = true);
    
    try {
      final authProvider = Provider.of<AuthProvider>(context, listen: false);
      
      final result = await authProvider.loginWithBiometrics();
      
      if (result.success) {
        // Navigate to main app
        if (mounted) {
          Navigator.of(context).pushReplacementNamed('/home');
        }
      } else {
        _showErrorMessage(result.message);
      }
    } catch (error) {
      _handleError(error);
    } finally {
      if (mounted) {
        setState(() => _isLoading = false);
      }
    }
  }

  Future<void> _handleGoogleLogin() async {
    setState(() => _isLoading = true);
    
    try {
      final authProvider = Provider.of<AuthProvider>(context, listen: false);
      
      final result = await authProvider.loginWithGoogle();
      
      if (result.success) {
        if (mounted) {
          Navigator.of(context).pushReplacementNamed('/home');
        }
      } else {
        _showErrorMessage(result.message);
      }
    } catch (error) {
      _handleError(error);
    } finally {
      if (mounted) {
        setState(() => _isLoading = false);
      }
    }
  }

  Future<void> _handleAppleLogin() async {
    setState(() => _isLoading = true);
    
    try {
      final authProvider = Provider.of<AuthProvider>(context, listen: false);
      
      final result = await authProvider.loginWithApple();
      
      if (result.success) {
        if (mounted) {
          Navigator.of(context).pushReplacementNamed('/home');
        }
      } else {
        _showErrorMessage(result.message);
      }
    } catch (error) {
      _handleError(error);
    } finally {
      if (mounted) {
        setState(() => _isLoading = false);
      }
    }
  }

  void _handleError(dynamic error) {
    String message = 'An unexpected error occurred';
    
    if (error is AuthenticationException) {
      message = error.userMessage;
    } else if (error is NetworkException) {
      message = error.userMessage;
    }
    
    _showErrorMessage(message);
  }

  void _showErrorMessage(String message) {
    if (!mounted) return;
    
    HapticFeedback.lightImpact();
    
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        backgroundColor: Theme.of(context).colorScheme.error,
        behavior: SnackBarBehavior.floating,
        action: SnackBarAction(
          label: 'OK',
          textColor: Colors.white,
          onPressed: () {
            ScaffoldMessenger.of(context).hideCurrentSnackBar();
          },
        ),
      ),
    );
  }

  Widget _buildBiometricIcon() {
    if (_availableBiometrics.contains(BiometricType.face)) {
      return const Icon(Icons.face, size: 24);
    } else if (_availableBiometrics.contains(BiometricType.fingerprint)) {
      return const Icon(Icons.fingerprint, size: 24);
    } else {
      return const Icon(Icons.security, size: 24);
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final size = MediaQuery.of(context).size;
    
    return Scaffold(
      body: LoadingOverlay(
        isLoading: _isLoading,
        child: SafeArea(
          child: SingleChildScrollView(
            padding: const EdgeInsets.symmetric(horizontal: 24.0),
            child: SizedBox(
              height: size.height - MediaQuery.of(context).padding.top,
              child: Column(
                children: [
                  // Logo and Animation
                  Expanded(
                    flex: 2,
                    child: FadeInDown(
                      duration: const Duration(milliseconds: 1000),
                      child: Column(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Container(
                            width: 120,
                            height: 120,
                            decoration: BoxDecoration(
                              color: theme.colorScheme.primary.withOpacity(0.1),
                              borderRadius: BorderRadius.circular(60),
                            ),
                            child: Lottie.asset(
                              'assets/animations/uk_logo.json',
                              width: 80,
                              height: 80,
                              fit: BoxFit.contain,
                              errorBuilder: (context, error, stackTrace) {
                                return Icon(
                                  Icons.account_balance,
                                  size: 60,
                                  color: theme.colorScheme.primary,
                                );
                              },
                            ),
                          ),
                          const SizedBox(height: 24),
                          Text(
                            'UK Digital ID',
                            style: theme.textTheme.headlineLarge?.copyWith(
                              fontWeight: FontWeight.bold,
                              color: theme.colorScheme.onBackground,
                            ),
                          ),
                          const SizedBox(height: 8),
                          Text(
                            'Secure access to government services',
                            style: theme.textTheme.bodyLarge?.copyWith(
                              color: theme.colorScheme.onBackground.withOpacity(0.7),
                            ),
                            textAlign: TextAlign.center,
                          ),
                        ],
                      ),
                    ),
                  ),
                  
                  // Login Form
                  Expanded(
                    flex: 3,
                    child: FadeTransition(
                      opacity: _fadeAnimation,
                      child: SlideTransition(
                        position: _slideAnimation,
                        child: Form(
                          key: _formKey,
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.stretch,
                            children: [
                              // Email Field
                              CustomTextField(
                                controller: _emailController,
                                label: 'Email Address',
                                prefixIcon: Icons.email_outlined,
                                keyboardType: TextInputType.emailAddress,
                                textInputAction: TextInputAction.next,
                                validator: Validators.email,
                                onChanged: (value) {
                                  // Clear errors on input
                                },
                              ),
                              
                              const SizedBox(height: 16),
                              
                              // Password Field
                              CustomTextField(
                                controller: _passwordController,
                                label: 'Password',
                                prefixIcon: Icons.lock_outline,
                                obscureText: _obscurePassword,
                                textInputAction: TextInputAction.done,
                                validator: Validators.password,
                                suffixIcon: IconButton(
                                  icon: Icon(
                                    _obscurePassword 
                                        ? Icons.visibility_off_outlined 
                                        : Icons.visibility_outlined,
                                  ),
                                  onPressed: () {
                                    setState(() {
                                      _obscurePassword = !_obscurePassword;
                                    });
                                  },
                                ),
                                onFieldSubmitted: (_) => _handleEmailLogin(),
                              ),
                              
                              const SizedBox(height: 16),
                              
                              // Remember Me & Forgot Password
                              Row(
                                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                                children: [
                                  Row(
                                    children: [
                                      Checkbox(
                                        value: _rememberMe,
                                        onChanged: (value) {
                                          setState(() {
                                            _rememberMe = value ?? false;
                                          });
                                        },
                                      ),
                                      Text(
                                        'Remember me',
                                        style: theme.textTheme.bodyMedium,
                                      ),
                                    ],
                                  ),
                                  TextButton(
                                    onPressed: () {
                                      Navigator.of(context).pushNamed('/forgot-password');
                                    },
                                    child: Text(
                                      'Forgot password?',
                                      style: TextStyle(
                                        color: theme.colorScheme.primary,
                                      ),
                                    ),
                                  ),
                                ],
                              ),
                              
                              const SizedBox(height: 24),
                              
                              // Login Button
                              CustomButton(
                                text: 'Sign In',
                                onPressed: _handleEmailLogin,
                                isLoading: _isLoading,
                              ),
                              
                              const SizedBox(height: 16),
                              
                              // Biometric Login (if available)
                              if (_biometricAvailable) ...[
                                Row(
                                  children: [
                                    Expanded(child: Divider(color: theme.dividerColor)),
                                    Padding(
                                      padding: const EdgeInsets.symmetric(horizontal: 16),
                                      child: Text(
                                        'or',
                                        style: theme.textTheme.bodyMedium?.copyWith(
                                          color: theme.colorScheme.onBackground.withOpacity(0.6),
                                        ),
                                      ),
                                    ),
                                    Expanded(child: Divider(color: theme.dividerColor)),
                                  ],
                                ),
                                
                                const SizedBox(height: 16),
                                
                                CustomButton(
                                  text: 'Use Biometric Authentication',
                                  onPressed: _handleBiometricLogin,
                                  variant: ButtonVariant.outlined,
                                  prefixIcon: _buildBiometricIcon(),
                                ),
                                
                                const SizedBox(height: 16),
                              ],
                              
                              // Social Login
                              if (AppConfig.featureFlags['social_login'] == true) ...[
                                Row(
                                  children: [
                                    Expanded(child: Divider(color: theme.dividerColor)),
                                    Padding(
                                      padding: const EdgeInsets.symmetric(horizontal: 16),
                                      child: Text(
                                        'or continue with',
                                        style: theme.textTheme.bodyMedium?.copyWith(
                                          color: theme.colorScheme.onBackground.withOpacity(0.6),
                                        ),
                                      ),
                                    ),
                                    Expanded(child: Divider(color: theme.dividerColor)),
                                  ],
                                ),
                                
                                const SizedBox(height: 16),
                                
                                Row(
                                  children: [
                                    Expanded(
                                      child: CustomButton(
                                        text: 'Google',
                                        onPressed: _handleGoogleLogin,
                                        variant: ButtonVariant.outlined,
                                        prefixIcon: const Icon(Icons.g_mobiledata, size: 24),
                                      ),
                                    ),
                                    const SizedBox(width: 12),
                                    if (Theme.of(context).platform == TargetPlatform.iOS)
                                      Expanded(
                                        child: CustomButton(
                                          text: 'Apple',
                                          onPressed: _handleAppleLogin,
                                          variant: ButtonVariant.outlined,
                                          prefixIcon: const Icon(Icons.apple, size: 24),
                                        ),
                                      ),
                                  ],
                                ),
                              ],
                            ],
                          ),
                        ),
                      ),
                    ),
                  ),
                  
                  // Sign Up Link
                  FadeInUp(
                    duration: const Duration(milliseconds: 1000),
                    delay: const Duration(milliseconds: 500),
                    child: Padding(
                      padding: const EdgeInsets.only(bottom: 24),
                      child: Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Text(
                            "Don't have an account? ",
                            style: theme.textTheme.bodyMedium,
                          ),
                          TextButton(
                            onPressed: () {
                              Navigator.of(context).pushNamed('/register');
                            },
                            child: Text(
                              'Sign Up',
                              style: TextStyle(
                                color: theme.colorScheme.primary,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}