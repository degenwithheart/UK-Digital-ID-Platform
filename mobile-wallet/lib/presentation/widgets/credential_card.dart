/// Credential Card Widget
/// 
/// Beautiful card component for displaying digital credentials
/// with animations, security indicators, and interactive features

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:animate_do/animate_do.dart';
import '../../core/services/storage_service.dart';

class CredentialCard extends StatefulWidget {
  final DigitalCredential credential;
  final VoidCallback? onTap;
  final VoidCallback? onLongPress;
  final bool isSelected;
  final bool showStatus;
  final bool isCompact;
  final EdgeInsetsGeometry? margin;

  const CredentialCard({
    Key? key,
    required this.credential,
    this.onTap,
    this.onLongPress,
    this.isSelected = false,
    this.showStatus = true,
    this.isCompact = false,
    this.margin,
  }) : super(key: key);

  @override
  State<CredentialCard> createState() => _CredentialCardState();
}

class _CredentialCardState extends State<CredentialCard>
    with SingleTickerProviderStateMixin {
  late AnimationController _animationController;
  late Animation<double> _scaleAnimation;
  late Animation<double> _elevationAnimation;
  
  bool _isPressed = false;

  @override
  void initState() {
    super.initState();
    _setupAnimations();
  }

  @override
  void dispose() {
    _animationController.dispose();
    super.dispose();
  }

  void _setupAnimations() {
    _animationController = AnimationController(
      duration: const Duration(milliseconds: 200),
      vsync: this,
    );

    _scaleAnimation = Tween<double>(
      begin: 1.0,
      end: 0.95,
    ).animate(CurvedAnimation(
      parent: _animationController,
      curve: Curves.easeInOut,
    ));

    _elevationAnimation = Tween<double>(
      begin: 4.0,
      end: 8.0,
    ).animate(CurvedAnimation(
      parent: _animationController,
      curve: Curves.easeInOut,
    ));
  }

  void _handleTapDown(TapDownDetails details) {
    setState(() => _isPressed = true);
    _animationController.forward();
    HapticFeedback.lightImpact();
  }

  void _handleTapUp(TapUpDetails details) {
    _resetPressState();
  }

  void _handleTapCancel() {
    _resetPressState();
  }

  void _resetPressState() {
    if (_isPressed) {
      setState(() => _isPressed = false);
      _animationController.reverse();
    }
  }

  Color _getCardColor(ThemeData theme) {
    switch (widget.credential.type.toLowerCase()) {
      case 'passport':
        return const Color(0xFF1B237E); // UK Passport Blue
      case 'driving_license':
        return const Color(0xFF006A4E); // DVLA Green
      case 'national_id':
        return const Color(0xFF8B1538); // UK Maroon
      case 'birth_certificate':
        return const Color(0xFF003A6B); // Official Blue
      case 'proof_of_address':
        return const Color(0xFF4A4A4A); // Neutral Gray
      default:
        return theme.colorScheme.primary;
    }
  }

  IconData _getCredentialIcon() {
    switch (widget.credential.type.toLowerCase()) {
      case 'passport':
        return Icons.flight_takeoff;
      case 'driving_license':
        return Icons.directions_car;
      case 'national_id':
        return Icons.badge;
      case 'birth_certificate':
        return Icons.child_care;
      case 'proof_of_address':
        return Icons.home;
      default:
        return Icons.credit_card;
    }
  }

  Widget _buildStatusIndicator(ThemeData theme) {
    if (!widget.showStatus) return const SizedBox.shrink();

    Color statusColor;
    IconData statusIcon;
    String statusText;

    if (widget.credential.isExpired) {
      statusColor = theme.colorScheme.error;
      statusIcon = Icons.error_outline;
      statusText = 'Expired';
    } else {
      switch (widget.credential.status.toLowerCase()) {
        case 'verified':
          statusColor = Colors.green;
          statusIcon = Icons.verified;
          statusText = 'Verified';
          break;
        case 'pending':
          statusColor = Colors.orange;
          statusIcon = Icons.pending;
          statusText = 'Pending';
          break;
        case 'rejected':
          statusColor = theme.colorScheme.error;
          statusIcon = Icons.cancel;
          statusText = 'Rejected';
          break;
        default:
          statusColor = Colors.grey;
          statusIcon = Icons.help_outline;
          statusText = 'Unknown';
      }
    }

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: statusColor.withOpacity(0.1),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: statusColor.withOpacity(0.3)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(statusIcon, size: 14, color: statusColor),
          const SizedBox(width: 4),
          Text(
            statusText,
            style: theme.textTheme.bodySmall?.copyWith(
              color: statusColor,
              fontWeight: FontWeight.w600,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildExpiryInfo(ThemeData theme) {
    if (widget.credential.expiresAt == null) {
      return const SizedBox.shrink();
    }

    final now = DateTime.now();
    final expiry = widget.credential.expiresAt!;
    final daysUntilExpiry = expiry.difference(now).inDays;
    
    Color textColor;
    String text;
    
    if (daysUntilExpiry < 0) {
      textColor = theme.colorScheme.error;
      text = 'Expired ${(-daysUntilExpiry)} days ago';
    } else if (daysUntilExpiry < 30) {
      textColor = Colors.orange;
      text = 'Expires in $daysUntilExpiry days';
    } else {
      textColor = theme.colorScheme.onSurface.withOpacity(0.6);
      text = 'Expires ${expiry.day}/${expiry.month}/${expiry.year}';
    }

    return Row(
      children: [
        Icon(
          Icons.schedule,
          size: 14,
          color: textColor,
        ),
        const SizedBox(width: 4),
        Expanded(
          child: Text(
            text,
            style: theme.textTheme.bodySmall?.copyWith(
              color: textColor,
              fontWeight: FontWeight.w500,
            ),
          ),
        ),
      ],
    );
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cardColor = _getCardColor(theme);
    
    return Container(
      margin: widget.margin,
      child: AnimatedBuilder(
        animation: _animationController,
        builder: (context, child) {
          return Transform.scale(
            scale: _scaleAnimation.value,
            child: GestureDetector(
              onTapDown: _handleTapDown,
              onTapUp: _handleTapUp,
              onTapCancel: _handleTapCancel,
              onTap: widget.onTap,
              onLongPress: () {
                HapticFeedback.mediumImpact();
                widget.onLongPress?.call();
              },
              child: Material(
                elevation: widget.isSelected ? 8.0 : _elevationAnimation.value,
                borderRadius: BorderRadius.circular(16),
                child: Container(
                  decoration: BoxDecoration(
                    gradient: LinearGradient(
                      begin: Alignment.topLeft,
                      end: Alignment.bottomRight,
                      colors: [
                        cardColor,
                        cardColor.withOpacity(0.8),
                      ],
                    ),
                    borderRadius: BorderRadius.circular(16),
                    border: widget.isSelected
                        ? Border.all(color: theme.colorScheme.primary, width: 2)
                        : null,
                  ),
                  child: widget.isCompact ? _buildCompactContent(theme) : _buildFullContent(theme),
                ),
              ),
            ),
          );
        },
      ),
    );
  }

  Widget _buildFullContent(ThemeData theme) {
    return Padding(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header Row
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: Colors.white.withOpacity(0.2),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Icon(
                  _getCredentialIcon(),
                  color: Colors.white,
                  size: 24,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      _formatCredentialType(widget.credential.type),
                      style: theme.textTheme.titleMedium?.copyWith(
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    Text(
                      widget.credential.issuer,
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: Colors.white.withOpacity(0.8),
                      ),
                    ),
                  ],
                ),
              ),
              _buildStatusIndicator(theme),
            ],
          ),
          
          const SizedBox(height: 20),
          
          // Credential Details
          Text(
            'ID: ${widget.credential.id.substring(0, 8).toUpperCase()}',
            style: theme.textTheme.bodyMedium?.copyWith(
              color: Colors.white.withOpacity(0.9),
              fontFamily: 'monospace',
              letterSpacing: 1.2,
            ),
          ),
          
          const SizedBox(height: 8),
          
          Text(
            widget.credential.subject,
            style: theme.textTheme.bodyLarge?.copyWith(
              color: Colors.white,
              fontWeight: FontWeight.w600,
            ),
          ),
          
          const Spacer(),
          
          // Footer
          Row(
            children: [
              Expanded(child: _buildExpiryInfo(theme)),
              if (widget.credential.verificationCount > 0) ...[
                const SizedBox(width: 8),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                  decoration: BoxDecoration(
                    color: Colors.white.withOpacity(0.2),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(
                        Icons.verified_user,
                        size: 14,
                        color: Colors.white.withOpacity(0.8),
                      ),
                      const SizedBox(width: 4),
                      Text(
                        '${widget.credential.verificationCount}',
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: Colors.white.withOpacity(0.8),
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildCompactContent(ThemeData theme) {
    return Padding(
      padding: const EdgeInsets.all(16),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: Colors.white.withOpacity(0.2),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Icon(
              _getCredentialIcon(),
              color: Colors.white,
              size: 20,
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  _formatCredentialType(widget.credential.type),
                  style: theme.textTheme.bodyLarge?.copyWith(
                    color: Colors.white,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                Text(
                  widget.credential.subject,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: Colors.white.withOpacity(0.8),
                  ),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
          _buildStatusIndicator(theme),
        ],
      ),
    );
  }

  String _formatCredentialType(String type) {
    return type
        .split('_')
        .map((word) => word[0].toUpperCase() + word.substring(1).toLowerCase())
        .join(' ');
  }
}

/// Quick Action Card Widget
class QuickActionCard extends StatefulWidget {
  final String title;
  final IconData icon;
  final VoidCallback onTap;
  final Color? color;
  final Color? backgroundColor;
  final String? badge;

  const QuickActionCard({
    Key? key,
    required this.title,
    required this.icon,
    required this.onTap,
    this.color,
    this.backgroundColor,
    this.badge,
  }) : super(key: key);

  @override
  State<QuickActionCard> createState() => _QuickActionCardState();
}

class _QuickActionCardState extends State<QuickActionCard>
    with SingleTickerProviderStateMixin {
  late AnimationController _animationController;
  late Animation<double> _scaleAnimation;
  
  bool _isPressed = false;

  @override
  void initState() {
    super.initState();
    _animationController = AnimationController(
      duration: const Duration(milliseconds: 150),
      vsync: this,
    );
    
    _scaleAnimation = Tween<double>(
      begin: 1.0,
      end: 0.9,
    ).animate(CurvedAnimation(
      parent: _animationController,
      curve: Curves.easeInOut,
    ));
  }

  @override
  void dispose() {
    _animationController.dispose();
    super.dispose();
  }

  void _handleTapDown(TapDownDetails details) {
    setState(() => _isPressed = true);
    _animationController.forward();
    HapticFeedback.lightImpact();
  }

  void _handleTapUp(TapUpDetails details) {
    _resetPressState();
  }

  void _handleTapCancel() {
    _resetPressState();
  }

  void _resetPressState() {
    if (_isPressed) {
      setState(() => _isPressed = false);
      _animationController.reverse();
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    
    return AnimatedBuilder(
      animation: _scaleAnimation,
      builder: (context, child) {
        return Transform.scale(
          scale: _scaleAnimation.value,
          child: GestureDetector(
            onTapDown: _handleTapDown,
            onTapUp: _handleTapUp,
            onTapCancel: _handleTapCancel,
            onTap: () {
              HapticFeedback.selectionClick();
              widget.onTap();
            },
            child: Container(
              width: 100,
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: widget.backgroundColor ?? theme.colorScheme.surface,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(
                  color: theme.dividerColor.withOpacity(0.5),
                ),
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withOpacity(0.05),
                    blurRadius: 4,
                    offset: const Offset(0, 2),
                  ),
                ],
              ),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Stack(
                    clipBehavior: Clip.none,
                    children: [
                      Container(
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          color: (widget.color ?? theme.colorScheme.primary).withOpacity(0.1),
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: Icon(
                          widget.icon,
                          color: widget.color ?? theme.colorScheme.primary,
                          size: 24,
                        ),
                      ),
                      if (widget.badge != null)
                        Positioned(
                          right: -4,
                          top: -4,
                          child: Container(
                            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                            decoration: BoxDecoration(
                              color: theme.colorScheme.error,
                              borderRadius: BorderRadius.circular(8),
                            ),
                            child: Text(
                              widget.badge!,
                              style: theme.textTheme.bodySmall?.copyWith(
                                color: Colors.white,
                                fontSize: 10,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                          ),
                        ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  Text(
                    widget.title,
                    style: theme.textTheme.bodySmall?.copyWith(
                      fontWeight: FontWeight.w500,
                    ),
                    textAlign: TextAlign.center,
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                  ),
                ],
              ),
            ),
          ),
        );
      },
    );
  }
}