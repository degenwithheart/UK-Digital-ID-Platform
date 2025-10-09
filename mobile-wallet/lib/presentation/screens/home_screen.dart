/// Home Screen - Main Dashboard
/// 
/// Comprehensive dashboard with digital credentials, quick actions,
/// verification status, and seamless navigation

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import 'package:animate_do/animate_do.dart';
import 'package:lottie/lottie.dart';
import 'package:fl_chart/fl_chart.dart';
import 'package:qr_flutter/qr_flutter.dart';
import '../../core/services/storage_service.dart';
import '../../core/services/auth_service.dart';
import '../providers/wallet_provider.dart';
import '../providers/auth_provider.dart';
import '../widgets/credential_card.dart';
import '../widgets/quick_action_card.dart';
import '../widgets/status_indicator.dart';
import '../widgets/animated_counter.dart';
import '../utils/ui_helpers.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({Key? key}) : super(key: key);

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> 
    with TickerProviderStateMixin, AutomaticKeepAliveClientMixin {
  
  late AnimationController _refreshController;
  late AnimationController _fabController;
  late Animation<double> _fabAnimation;
  
  final ScrollController _scrollController = ScrollController();
  bool _showFab = false;
  
  @override
  bool get wantKeepAlive => true;

  @override
  void initState() {
    super.initState();
    _setupAnimations();
    _setupScrollListener();
    _loadInitialData();
  }

  @override
  void dispose() {
    _refreshController.dispose();
    _fabController.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  void _setupAnimations() {
    _refreshController = AnimationController(
      duration: const Duration(seconds: 1),
      vsync: this,
    );
    
    _fabController = AnimationController(
      duration: const Duration(milliseconds: 300),
      vsync: this,
    );
    
    _fabAnimation = Tween<double>(
      begin: 0.0,
      end: 1.0,
    ).animate(CurvedAnimation(
      parent: _fabController,
      curve: Curves.easeInOut,
    ));
  }

  void _setupScrollListener() {
    _scrollController.addListener(() {
      final shouldShow = _scrollController.offset > 200;
      if (shouldShow != _showFab) {
        setState(() => _showFab = shouldShow);
        if (_showFab) {
          _fabController.forward();
        } else {
          _fabController.reverse();
        }
      }
    });
  }

  Future<void> _loadInitialData() async {
    final walletProvider = Provider.of<WalletProvider>(context, listen: false);
    await walletProvider.loadCredentials();
    await walletProvider.loadRecentActivity();
    await walletProvider.checkVerificationStatus();
  }

  Future<void> _refreshData() async {
    _refreshController.repeat();
    
    try {
      final walletProvider = Provider.of<WalletProvider>(context, listen: false);
      
      await Future.wait([
        walletProvider.loadCredentials(),
        walletProvider.loadRecentActivity(),
        walletProvider.checkVerificationStatus(),
        walletProvider.syncData(),
      ]);
      
      // Show success feedback
      HapticFeedback.lightImpact();
      
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: const Text('Data refreshed successfully'),
            backgroundColor: Colors.green,
            behavior: SnackBarBehavior.floating,
            duration: const Duration(seconds: 2),
          ),
        );
      }
    } catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to refresh: ${error.toString()}'),
            backgroundColor: Colors.red,
            behavior: SnackBarBehavior.floating,
          ),
        );
      }
    } finally {
      _refreshController.stop();
    }
  }

  void _scrollToTop() {
    _scrollController.animateTo(
      0,
      duration: const Duration(milliseconds: 500),
      curve: Curves.easeInOut,
    );
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    
    final theme = Theme.of(context);
    
    return Scaffold(
      body: RefreshIndicator(
        onRefresh: _refreshData,
        child: CustomScrollView(
          controller: _scrollController,
          physics: const AlwaysScrollableScrollPhysics(),
          slivers: [
            // App Bar
            _buildAppBar(theme),
            
            // Main Content
            SliverPadding(
              padding: const EdgeInsets.all(16.0),
              sliver: SliverList(
                delegate: SliverChildListDelegate([
                  // Welcome Section
                  _buildWelcomeSection(theme),
                  
                  const SizedBox(height: 24),
                  
                  // Status Cards
                  _buildStatusCards(theme),
                  
                  const SizedBox(height: 24),
                  
                  // Quick Actions
                  _buildQuickActions(theme),
                  
                  const SizedBox(height: 24),
                  
                  // Credentials Section
                  _buildCredentialsSection(theme),
                  
                  const SizedBox(height: 24),
                  
                  // Activity Section
                  _buildActivitySection(theme),
                  
                  const SizedBox(height: 24),
                  
                  // Statistics
                  _buildStatistics(theme),
                  
                  const SizedBox(height: 100), // Bottom padding for FAB
                ]),
              ),
            ),
          ],
        ),
      ),
      floatingActionButton: AnimatedBuilder(
        animation: _fabAnimation,
        builder: (context, child) {
          return Transform.scale(
            scale: _fabAnimation.value,
            child: FloatingActionButton.extended(
              onPressed: _scrollToTop,
              label: const Text('Top'),
              icon: const Icon(Icons.keyboard_arrow_up),
              backgroundColor: theme.colorScheme.primary,
              foregroundColor: theme.colorScheme.onPrimary,
            ),
          );
        },
      ),
    );
  }

  Widget _buildAppBar(ThemeData theme) {
    return Consumer<AuthProvider>(
      builder: (context, authProvider, child) {
        final user = authProvider.currentUser;
        
        return SliverAppBar(
          expandedHeight: 120,
          floating: false,
          pinned: true,
          backgroundColor: theme.colorScheme.primary,
          foregroundColor: theme.colorScheme.onPrimary,
          flexibleSpace: FlexibleSpaceBar(
            background: Container(
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                  colors: [
                    theme.colorScheme.primary,
                    theme.colorScheme.primary.withOpacity(0.8),
                  ],
                ),
              ),
            ),
            title: FadeInDown(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Welcome back',
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: theme.colorScheme.onPrimary.withOpacity(0.8),
                    ),
                  ),
                  Text(
                    user?.firstName ?? 'User',
                    style: theme.textTheme.titleLarge?.copyWith(
                      color: theme.colorScheme.onPrimary,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ],
              ),
            ),
          ),
          actions: [
            IconButton(
              icon: const Icon(Icons.qr_code_scanner),
              onPressed: () {
                Navigator.of(context).pushNamed('/qr-scanner');
              },
            ),
            IconButton(
              icon: const Icon(Icons.notifications_outlined),
              onPressed: () {
                Navigator.of(context).pushNamed('/notifications');
              },
            ),
            IconButton(
              icon: CircleAvatar(
                radius: 16,
                backgroundColor: theme.colorScheme.onPrimary.withOpacity(0.2),
                child: Text(
                  (user?.firstName.isNotEmpty == true ? user!.firstName[0] : 'U').toUpperCase(),
                  style: TextStyle(
                    color: theme.colorScheme.onPrimary,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
              onPressed: () {
                Navigator.of(context).pushNamed('/profile');
              },
            ),
            const SizedBox(width: 8),
          ],
        );
      },
    );
  }

  Widget _buildWelcomeSection(ThemeData theme) {
    return FadeInUp(
      duration: const Duration(milliseconds: 600),
      child: Container(
        padding: const EdgeInsets.all(20),
        decoration: BoxDecoration(
          gradient: LinearGradient(
            colors: [
              theme.colorScheme.primaryContainer,
              theme.colorScheme.primaryContainer.withOpacity(0.7),
            ],
          ),
          borderRadius: BorderRadius.circular(16),
        ),
        child: Row(
          children: [
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Your Digital Identity',
                    style: theme.textTheme.headlineSmall?.copyWith(
                      fontWeight: FontWeight.bold,
                      color: theme.colorScheme.onPrimaryContainer,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Securely manage your government credentials and access services with confidence.',
                    style: theme.textTheme.bodyMedium?.copyWith(
                      color: theme.colorScheme.onPrimaryContainer.withOpacity(0.8),
                    ),
                  ),
                  const SizedBox(height: 16),
                  ElevatedButton.icon(
                    onPressed: () {
                      Navigator.of(context).pushNamed('/add-credential');
                    },
                    icon: const Icon(Icons.add),
                    label: const Text('Add Credential'),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: theme.colorScheme.primary,
                      foregroundColor: theme.colorScheme.onPrimary,
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(width: 16),
            Container(
              width: 80,
              height: 80,
              decoration: BoxDecoration(
                color: theme.colorScheme.primary.withOpacity(0.1),
                borderRadius: BorderRadius.circular(40),
              ),
              child: Lottie.asset(
                'assets/animations/security.json',
                width: 60,
                height: 60,
                errorBuilder: (context, error, stackTrace) {
                  return Icon(
                    Icons.security,
                    size: 40,
                    color: theme.colorScheme.primary,
                  );
                },
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildStatusCards(ThemeData theme) {
    return Consumer<WalletProvider>(
      builder: (context, walletProvider, child) {
        return FadeInUp(
          duration: const Duration(milliseconds: 800),
          child: Row(
            children: [
              Expanded(
                child: _buildStatusCard(
                  theme,
                  'Verified',
                  walletProvider.verifiedCredentialsCount.toString(),
                  Icons.verified_user,
                  Colors.green,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: _buildStatusCard(
                  theme,
                  'Pending',
                  walletProvider.pendingCredentialsCount.toString(),
                  Icons.pending,
                  Colors.orange,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: _buildStatusCard(
                  theme,
                  'Total',
                  walletProvider.totalCredentialsCount.toString(),
                  Icons.wallet,
                  theme.colorScheme.primary,
                ),
              ),
            ],
          ),
        );
      },
    );
  }

  Widget _buildStatusCard(
    ThemeData theme,
    String title,
    String count,
    IconData icon,
    Color color,
  ) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: theme.dividerColor),
      ),
      child: Column(
        children: [
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: color.withOpacity(0.1),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Icon(
              icon,
              color: color,
              size: 24,
            ),
          ),
          const SizedBox(height: 8),
          AnimatedCounter(
            value: int.tryParse(count) ?? 0,
            style: theme.textTheme.headlineSmall?.copyWith(
              fontWeight: FontWeight.bold,
              color: theme.colorScheme.onSurface,
            ),
          ),
          Text(
            title,
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurface.withOpacity(0.7),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildQuickActions(ThemeData theme) {
    return FadeInUp(
      duration: const Duration(milliseconds: 1000),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Quick Actions',
            style: theme.textTheme.titleLarge?.copyWith(
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 16),
          SizedBox(
            height: 120,
            child: ListView(
              scrollDirection: Axis.horizontal,
              children: [
                QuickActionCard(
                  title: 'Scan QR',
                  icon: Icons.qr_code_scanner,
                  onTap: () => Navigator.of(context).pushNamed('/qr-scanner'),
                ),
                const SizedBox(width: 12),
                QuickActionCard(
                  title: 'Share ID',
                  icon: Icons.share,
                  onTap: () => Navigator.of(context).pushNamed('/share-id'),
                ),
                const SizedBox(width: 12),
                QuickActionCard(
                  title: 'Verify',
                  icon: Icons.verified,
                  onTap: () => Navigator.of(context).pushNamed('/verify'),
                ),
                const SizedBox(width: 12),
                QuickActionCard(
                  title: 'Settings',
                  icon: Icons.settings,
                  onTap: () => Navigator.of(context).pushNamed('/settings'),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildCredentialsSection(ThemeData theme) {
    return Consumer<WalletProvider>(
      builder: (context, walletProvider, child) {
        final credentials = walletProvider.credentials;
        
        return FadeInUp(
          duration: const Duration(milliseconds: 1200),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text(
                    'My Credentials',
                    style: theme.textTheme.titleLarge?.copyWith(
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  TextButton(
                    onPressed: () {
                      Navigator.of(context).pushNamed('/credentials');
                    },
                    child: const Text('View All'),
                  ),
                ],
              ),
              const SizedBox(height: 16),
              if (credentials.isEmpty)
                _buildEmptyCredentials(theme)
              else
                SizedBox(
                  height: 200,
                  child: ListView.builder(
                    scrollDirection: Axis.horizontal,
                    itemCount: credentials.take(5).length,
                    itemBuilder: (context, index) {
                      final credential = credentials[index];
                      return Container(
                        width: 300,
                        margin: EdgeInsets.only(
                          right: index < credentials.length - 1 ? 12 : 0,
                        ),
                        child: CredentialCard(
                          credential: credential,
                          onTap: () {
                            Navigator.of(context).pushNamed(
                              '/credential-details',
                              arguments: credential,
                            );
                          },
                        ),
                      );
                    },
                  ),
                ),
            ],
          ),
        );
      },
    );
  }

  Widget _buildEmptyCredentials(ThemeData theme) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(32),
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: theme.dividerColor),
      ),
      child: Column(
        children: [
          Icon(
            Icons.wallet_outlined,
            size: 64,
            color: theme.colorScheme.onSurface.withOpacity(0.4),
          ),
          const SizedBox(height: 16),
          Text(
            'No Credentials Yet',
            style: theme.textTheme.titleMedium?.copyWith(
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            'Add your first credential to get started with your digital identity.',
            style: theme.textTheme.bodyMedium?.copyWith(
              color: theme.colorScheme.onSurface.withOpacity(0.7),
            ),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 16),
          ElevatedButton(
            onPressed: () {
              Navigator.of(context).pushNamed('/add-credential');
            },
            child: const Text('Add Credential'),
          ),
        ],
      ),
    );
  }

  Widget _buildActivitySection(ThemeData theme) {
    return Consumer<WalletProvider>(
      builder: (context, walletProvider, child) {
        final activities = walletProvider.recentActivities;
        
        return FadeInUp(
          duration: const Duration(milliseconds: 1400),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text(
                    'Recent Activity',
                    style: theme.textTheme.titleLarge?.copyWith(
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  TextButton(
                    onPressed: () {
                      Navigator.of(context).pushNamed('/activity');
                    },
                    child: const Text('View All'),
                  ),
                ],
              ),
              const SizedBox(height: 16),
              if (activities.isEmpty)
                Container(
                  width: double.infinity,
                  padding: const EdgeInsets.all(24),
                  decoration: BoxDecoration(
                    color: theme.colorScheme.surface,
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: theme.dividerColor),
                  ),
                  child: Column(
                    children: [
                      Icon(
                        Icons.history,
                        size: 48,
                        color: theme.colorScheme.onSurface.withOpacity(0.4),
                      ),
                      const SizedBox(height: 8),
                      Text(
                        'No recent activity',
                        style: theme.textTheme.bodyLarge,
                      ),
                    ],
                  ),
                )
              else
                ListView.builder(
                  shrinkWrap: true,
                  physics: const NeverScrollableScrollPhysics(),
                  itemCount: activities.take(3).length,
                  itemBuilder: (context, index) {
                    final activity = activities[index];
                    return _buildActivityItem(theme, activity);
                  },
                ),
            ],
          ),
        );
      },
    );
  }

  Widget _buildActivityItem(ThemeData theme, Map<String, dynamic> activity) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: theme.dividerColor.withOpacity(0.5)),
      ),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: _getActivityColor(activity['type']).withOpacity(0.1),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Icon(
              _getActivityIcon(activity['type']),
              color: _getActivityColor(activity['type']),
              size: 20,
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  activity['title'] ?? 'Activity',
                  style: theme.textTheme.bodyMedium?.copyWith(
                    fontWeight: FontWeight.w500,
                  ),
                ),
                Text(
                  activity['description'] ?? '',
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurface.withOpacity(0.7),
                  ),
                ),
              ],
            ),
          ),
          Text(
            activity['time'] ?? '',
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurface.withOpacity(0.5),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildStatistics(ThemeData theme) {
    return Consumer<WalletProvider>(
      builder: (context, walletProvider, child) {
        return FadeInUp(
          duration: const Duration(milliseconds: 1600),
          child: Container(
            padding: const EdgeInsets.all(20),
            decoration: BoxDecoration(
              color: theme.colorScheme.surface,
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: theme.dividerColor),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Usage Statistics',
                  style: theme.textTheme.titleLarge?.copyWith(
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 20),
                SizedBox(
                  height: 200,
                  child: LineChart(
                    LineChartData(
                      gridData: FlGridData(show: false),
                      titlesData: FlTitlesData(show: false),
                      borderData: FlBorderData(show: false),
                      lineBarsData: [
                        LineChartBarData(
                          spots: walletProvider.usageStats,
                          isCurved: true,
                          color: theme.colorScheme.primary,
                          barWidth: 3,
                          belowBarData: BarAreaData(
                            show: true,
                            color: theme.colorScheme.primary.withOpacity(0.1),
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  IconData _getActivityIcon(String type) {
    switch (type) {
      case 'verification':
        return Icons.verified;
      case 'credential_added':
        return Icons.add_card;
      case 'login':
        return Icons.login;
      case 'share':
        return Icons.share;
      default:
        return Icons.history;
    }
  }

  Color _getActivityColor(String type) {
    switch (type) {
      case 'verification':
        return Colors.green;
      case 'credential_added':
        return Colors.blue;
      case 'login':
        return Colors.purple;
      case 'share':
        return Colors.orange;
      default:
        return Colors.grey;
    }
  }
}