/// Custom Button Widget
/// 
/// Reusable button component with multiple variants, loading states,
/// and accessibility features

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

enum ButtonVariant {
  filled,
  outlined,
  text,
  elevated,
}

enum ButtonSize {
  small,
  medium,
  large,
}

class CustomButton extends StatefulWidget {
  final String text;
  final VoidCallback? onPressed;
  final ButtonVariant variant;
  final ButtonSize size;
  final bool isLoading;
  final bool isDisabled;
  final Widget? prefixIcon;
  final Widget? suffixIcon;
  final Color? backgroundColor;
  final Color? foregroundColor;
  final Color? borderColor;
  final double? borderRadius;
  final EdgeInsetsGeometry? padding;
  final double? elevation;
  final bool fullWidth;
  final TextStyle? textStyle;

  const CustomButton({
    Key? key,
    required this.text,
    this.onPressed,
    this.variant = ButtonVariant.filled,
    this.size = ButtonSize.medium,
    this.isLoading = false,
    this.isDisabled = false,
    this.prefixIcon,
    this.suffixIcon,
    this.backgroundColor,
    this.foregroundColor,
    this.borderColor,
    this.borderRadius,
    this.padding,
    this.elevation,
    this.fullWidth = true,
    this.textStyle,
  }) : super(key: key);

  @override
  State<CustomButton> createState() => _CustomButtonState();
}

class _CustomButtonState extends State<CustomButton>
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
      end: 0.95,
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

  EdgeInsetsGeometry _getPadding() {
    if (widget.padding != null) return widget.padding!;
    
    switch (widget.size) {
      case ButtonSize.small:
        return const EdgeInsets.symmetric(horizontal: 16, vertical: 8);
      case ButtonSize.medium:
        return const EdgeInsets.symmetric(horizontal: 24, vertical: 12);
      case ButtonSize.large:
        return const EdgeInsets.symmetric(horizontal: 32, vertical: 16);
    }
  }

  double _getBorderRadius() {
    if (widget.borderRadius != null) return widget.borderRadius!;
    
    switch (widget.size) {
      case ButtonSize.small:
        return 8.0;
      case ButtonSize.medium:
        return 12.0;
      case ButtonSize.large:
        return 16.0;
    }
  }

  TextStyle _getTextStyle(ThemeData theme) {
    TextStyle baseStyle;
    
    switch (widget.size) {
      case ButtonSize.small:
        baseStyle = theme.textTheme.bodyMedium ?? const TextStyle();
        break;
      case ButtonSize.medium:
        baseStyle = theme.textTheme.bodyLarge ?? const TextStyle();
        break;
      case ButtonSize.large:
        baseStyle = theme.textTheme.titleMedium ?? const TextStyle();
        break;
    }
    
    return baseStyle.copyWith(
      fontWeight: FontWeight.w600,
      letterSpacing: 0.5,
    ).merge(widget.textStyle);
  }

  void _handleTapDown(TapDownDetails details) {
    if (!widget.isDisabled && !widget.isLoading) {
      setState(() => _isPressed = true);
      _animationController.forward();
      HapticFeedback.lightImpact();
    }
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

  void _handleTap() {
    if (!widget.isDisabled && !widget.isLoading && widget.onPressed != null) {
      HapticFeedback.selectionClick();
      widget.onPressed!();
    }
  }

  Widget _buildButtonContent(ThemeData theme) {
    final children = <Widget>[];
    
    // Add prefix icon or loading indicator
    if (widget.isLoading) {
      children.add(SizedBox(
        width: 16,
        height: 16,
        child: CircularProgressIndicator(
          strokeWidth: 2,
          valueColor: AlwaysStoppedAnimation<Color>(
            widget.foregroundColor ?? theme.colorScheme.onPrimary,
          ),
        ),
      ));
      children.add(const SizedBox(width: 8));
    } else if (widget.prefixIcon != null) {
      children.add(widget.prefixIcon!);
      children.add(const SizedBox(width: 8));
    }
    
    // Add text
    children.add(
      Text(
        widget.text,
        style: _getTextStyle(theme).copyWith(
          color: widget.foregroundColor,
        ),
        textAlign: TextAlign.center,
      ),
    );
    
    // Add suffix icon
    if (widget.suffixIcon != null && !widget.isLoading) {
      children.add(const SizedBox(width: 8));
      children.add(widget.suffixIcon!);
    }
    
    return Row(
      mainAxisSize: MainAxisSize.min,
      mainAxisAlignment: MainAxisAlignment.center,
      children: children,
    );
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isEnabled = !widget.isDisabled && !widget.isLoading;
    
    Widget button;
    
    switch (widget.variant) {
      case ButtonVariant.filled:
        button = _buildFilledButton(theme, isEnabled);
        break;
      case ButtonVariant.outlined:
        button = _buildOutlinedButton(theme, isEnabled);
        break;
      case ButtonVariant.text:
        button = _buildTextButton(theme, isEnabled);
        break;
      case ButtonVariant.elevated:
        button = _buildElevatedButton(theme, isEnabled);
        break;
    }
    
    return AnimatedBuilder(
      animation: _scaleAnimation,
      builder: (context, child) {
        return Transform.scale(
          scale: _scaleAnimation.value,
          child: button,
        );
      },
    );
  }

  Widget _buildFilledButton(ThemeData theme, bool isEnabled) {
    return SizedBox(
      width: widget.fullWidth ? double.infinity : null,
      child: GestureDetector(
        onTapDown: _handleTapDown,
        onTapUp: _handleTapUp,
        onTapCancel: _handleTapCancel,
        onTap: _handleTap,
        child: Container(
          padding: _getPadding(),
          decoration: BoxDecoration(
            color: isEnabled
                ? (widget.backgroundColor ?? theme.colorScheme.primary)
                : theme.disabledColor,
            borderRadius: BorderRadius.circular(_getBorderRadius()),
            border: widget.borderColor != null
                ? Border.all(color: widget.borderColor!)
                : null,
          ),
          child: _buildButtonContent(theme.copyWith(
            colorScheme: theme.colorScheme.copyWith(
              onPrimary: widget.foregroundColor ?? theme.colorScheme.onPrimary,
            ),
          )),
        ),
      ),
    );
  }

  Widget _buildOutlinedButton(ThemeData theme, bool isEnabled) {
    return SizedBox(
      width: widget.fullWidth ? double.infinity : null,
      child: GestureDetector(
        onTapDown: _handleTapDown,
        onTapUp: _handleTapUp,
        onTapCancel: _handleTapCancel,
        onTap: _handleTap,
        child: Container(
          padding: _getPadding(),
          decoration: BoxDecoration(
            color: _isPressed && isEnabled
                ? (widget.backgroundColor ?? theme.colorScheme.primary).withOpacity(0.1)
                : Colors.transparent,
            borderRadius: BorderRadius.circular(_getBorderRadius()),
            border: Border.all(
              color: isEnabled
                  ? (widget.borderColor ?? theme.colorScheme.primary)
                  : theme.disabledColor,
              width: 1.5,
            ),
          ),
          child: _buildButtonContent(theme.copyWith(
            colorScheme: theme.colorScheme.copyWith(
              onPrimary: widget.foregroundColor ?? theme.colorScheme.primary,
            ),
          )),
        ),
      ),
    );
  }

  Widget _buildTextButton(ThemeData theme, bool isEnabled) {
    return SizedBox(
      width: widget.fullWidth ? double.infinity : null,
      child: GestureDetector(
        onTapDown: _handleTapDown,
        onTapUp: _handleTapUp,
        onTapCancel: _handleTapCancel,
        onTap: _handleTap,
        child: Container(
          padding: _getPadding(),
          decoration: BoxDecoration(
            color: _isPressed && isEnabled
                ? theme.colorScheme.primary.withOpacity(0.1)
                : Colors.transparent,
            borderRadius: BorderRadius.circular(_getBorderRadius()),
          ),
          child: _buildButtonContent(theme.copyWith(
            colorScheme: theme.colorScheme.copyWith(
              onPrimary: widget.foregroundColor ?? theme.colorScheme.primary,
            ),
          )),
        ),
      ),
    );
  }

  Widget _buildElevatedButton(ThemeData theme, bool isEnabled) {
    return SizedBox(
      width: widget.fullWidth ? double.infinity : null,
      child: Material(
        elevation: widget.elevation ?? (isEnabled ? 4.0 : 0.0),
        borderRadius: BorderRadius.circular(_getBorderRadius()),
        color: isEnabled
            ? (widget.backgroundColor ?? theme.colorScheme.primary)
            : theme.disabledColor,
        child: InkWell(
          onTapDown: _handleTapDown,
          onTapUp: _handleTapUp,
          onTapCancel: _handleTapCancel,
          onTap: _handleTap,
          borderRadius: BorderRadius.circular(_getBorderRadius()),
          child: Container(
            padding: _getPadding(),
            child: _buildButtonContent(theme.copyWith(
              colorScheme: theme.colorScheme.copyWith(
                onPrimary: widget.foregroundColor ?? theme.colorScheme.onPrimary,
              ),
            )),
          ),
        ),
      ),
    );
  }
}