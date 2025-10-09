/// Custom Text Field Widget
/// 
/// Reusable text input component with validation, animations,
/// and accessibility features

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

enum TextFieldVariant {
  outlined,
  filled,
  underlined,
}

class CustomTextField extends StatefulWidget {
  final String? label;
  final String? hintText;
  final String? helperText;
  final String? errorText;
  final TextEditingController? controller;
  final TextInputType keyboardType;
  final TextInputAction textInputAction;
  final bool obscureText;
  final bool readOnly;
  final bool enabled;
  final int? maxLines;
  final int? minLines;
  final int? maxLength;
  final TextCapitalization textCapitalization;
  final List<TextInputFormatter>? inputFormatters;
  final String? Function(String?)? validator;
  final ValueChanged<String>? onChanged;
  final ValueChanged<String>? onFieldSubmitted;
  final VoidCallback? onTap;
  final FocusNode? focusNode;
  final IconData? prefixIcon;
  final Widget? suffixIcon;
  final Color? fillColor;
  final Color? borderColor;
  final Color? focusedBorderColor;
  final Color? errorBorderColor;
  final double borderRadius;
  final TextFieldVariant variant;
  final EdgeInsetsGeometry? contentPadding;
  final TextStyle? textStyle;
  final TextStyle? labelStyle;
  final TextStyle? hintStyle;
  final bool autofocus;
  final bool enableSuggestions;
  final bool autocorrect;

  const CustomTextField({
    Key? key,
    this.label,
    this.hintText,
    this.helperText,
    this.errorText,
    this.controller,
    this.keyboardType = TextInputType.text,
    this.textInputAction = TextInputAction.done,
    this.obscureText = false,
    this.readOnly = false,
    this.enabled = true,
    this.maxLines = 1,
    this.minLines,
    this.maxLength,
    this.textCapitalization = TextCapitalization.none,
    this.inputFormatters,
    this.validator,
    this.onChanged,
    this.onFieldSubmitted,
    this.onTap,
    this.focusNode,
    this.prefixIcon,
    this.suffixIcon,
    this.fillColor,
    this.borderColor,
    this.focusedBorderColor,
    this.errorBorderColor,
    this.borderRadius = 12.0,
    this.variant = TextFieldVariant.outlined,
    this.contentPadding,
    this.textStyle,
    this.labelStyle,
    this.hintStyle,
    this.autofocus = false,
    this.enableSuggestions = true,
    this.autocorrect = true,
  }) : super(key: key);

  @override
  State<CustomTextField> createState() => _CustomTextFieldState();
}

class _CustomTextFieldState extends State<CustomTextField>
    with TickerProviderStateMixin {
  late FocusNode _focusNode;
  late AnimationController _animationController;
  late Animation<double> _labelAnimation;
  late Animation<Color?> _borderAnimation;
  
  bool _isFocused = false;
  bool _hasError = false;
  String? _currentError;

  @override
  void initState() {
    super.initState();
    _focusNode = widget.focusNode ?? FocusNode();
    _setupAnimations();
    _setupFocusListener();
  }

  @override
  void didUpdateWidget(CustomTextField oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.errorText != oldWidget.errorText) {
      _updateErrorState();
    }
  }

  @override
  void dispose() {
    if (widget.focusNode == null) {
      _focusNode.dispose();
    }
    _animationController.dispose();
    super.dispose();
  }

  void _setupAnimations() {
    _animationController = AnimationController(
      duration: const Duration(milliseconds: 200),
      vsync: this,
    );

    _labelAnimation = Tween<double>(
      begin: 1.0,
      end: 0.8,
    ).animate(CurvedAnimation(
      parent: _animationController,
      curve: Curves.easeInOut,
    ));

    final theme = Theme.of(context);
    _borderAnimation = ColorTween(
      begin: widget.borderColor ?? theme.colorScheme.outline,
      end: widget.focusedBorderColor ?? theme.colorScheme.primary,
    ).animate(CurvedAnimation(
      parent: _animationController,
      curve: Curves.easeInOut,
    ));
  }

  void _setupFocusListener() {
    _focusNode.addListener(() {
      if (_focusNode.hasFocus != _isFocused) {
        setState(() => _isFocused = _focusNode.hasFocus);
        
        if (_isFocused) {
          _animationController.forward();
          HapticFeedback.selectionClick();
        } else {
          _animationController.reverse();
        }
      }
    });
  }

  void _updateErrorState() {
    final hasError = widget.errorText != null && widget.errorText!.isNotEmpty;
    if (hasError != _hasError) {
      setState(() {
        _hasError = hasError;
        _currentError = widget.errorText;
      });
    }
  }

  String? _getErrorText() {
    if (widget.errorText != null) return widget.errorText;
    return _currentError;
  }

  InputBorder _buildBorder(Color color, {double width = 1.0}) {
    switch (widget.variant) {
      case TextFieldVariant.outlined:
        return OutlineInputBorder(
          borderRadius: BorderRadius.circular(widget.borderRadius),
          borderSide: BorderSide(color: color, width: width),
        );
      case TextFieldVariant.filled:
        return OutlineInputBorder(
          borderRadius: BorderRadius.circular(widget.borderRadius),
          borderSide: BorderSide.none,
        );
      case TextFieldVariant.underlined:
        return UnderlineInputBorder(
          borderSide: BorderSide(color: color, width: width),
        );
    }
  }

  EdgeInsetsGeometry _getContentPadding() {
    if (widget.contentPadding != null) return widget.contentPadding!;
    
    switch (widget.variant) {
      case TextFieldVariant.outlined:
        return const EdgeInsets.symmetric(horizontal: 16, vertical: 12);
      case TextFieldVariant.filled:
        return const EdgeInsets.symmetric(horizontal: 16, vertical: 16);
      case TextFieldVariant.underlined:
        return const EdgeInsets.symmetric(horizontal: 0, vertical: 8);
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final errorText = _getErrorText();
    final hasError = errorText != null && errorText.isNotEmpty;
    
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // Label (if outside field)
        if (widget.label != null && widget.variant == TextFieldVariant.underlined)
          Padding(
            padding: const EdgeInsets.only(bottom: 8),
            child: AnimatedBuilder(
              animation: _labelAnimation,
              builder: (context, child) {
                return Text(
                  widget.label!,
                  style: (widget.labelStyle ?? theme.textTheme.bodyMedium)?.copyWith(
                    color: hasError
                        ? theme.colorScheme.error
                        : _isFocused
                            ? theme.colorScheme.primary
                            : theme.colorScheme.onSurface.withOpacity(0.7),
                    fontWeight: _isFocused ? FontWeight.w500 : FontWeight.normal,
                  ),
                );
              },
            ),
          ),
        
        // Text Field
        AnimatedBuilder(
          animation: _animationController,
          builder: (context, child) {
            return TextFormField(
              controller: widget.controller,
              focusNode: _focusNode,
              keyboardType: widget.keyboardType,
              textInputAction: widget.textInputAction,
              obscureText: widget.obscureText,
              readOnly: widget.readOnly,
              enabled: widget.enabled,
              maxLines: widget.maxLines,
              minLines: widget.minLines,
              maxLength: widget.maxLength,
              textCapitalization: widget.textCapitalization,
              inputFormatters: widget.inputFormatters,
              validator: widget.validator,
              onChanged: widget.onChanged,
              onFieldSubmitted: widget.onFieldSubmitted,
              onTap: widget.onTap,
              autofocus: widget.autofocus,
              enableSuggestions: widget.enableSuggestions,
              autocorrect: widget.autocorrect,
              style: widget.textStyle ?? theme.textTheme.bodyLarge,
              decoration: InputDecoration(
                labelText: widget.variant != TextFieldVariant.underlined ? widget.label : null,
                hintText: widget.hintText,
                helperText: widget.helperText,
                errorText: errorText,
                filled: widget.variant == TextFieldVariant.filled,
                fillColor: widget.fillColor ?? 
                    (widget.variant == TextFieldVariant.filled 
                        ? theme.colorScheme.surfaceVariant.withOpacity(0.5)
                        : null),
                contentPadding: _getContentPadding(),
                prefixIcon: widget.prefixIcon != null
                    ? Icon(
                        widget.prefixIcon,
                        color: hasError
                            ? theme.colorScheme.error
                            : _isFocused
                                ? theme.colorScheme.primary
                                : theme.colorScheme.onSurface.withOpacity(0.7),
                      )
                    : null,
                suffixIcon: widget.suffixIcon,
                border: _buildBorder(
                  widget.borderColor ?? theme.colorScheme.outline,
                ),
                enabledBorder: _buildBorder(
                  widget.borderColor ?? theme.colorScheme.outline,
                ),
                focusedBorder: _buildBorder(
                  hasError
                      ? widget.errorBorderColor ?? theme.colorScheme.error
                      : _borderAnimation.value ?? theme.colorScheme.primary,
                  width: 2.0,
                ),
                errorBorder: _buildBorder(
                  widget.errorBorderColor ?? theme.colorScheme.error,
                ),
                focusedErrorBorder: _buildBorder(
                  widget.errorBorderColor ?? theme.colorScheme.error,
                  width: 2.0,
                ),
                labelStyle: widget.labelStyle ?? theme.textTheme.bodyMedium?.copyWith(
                  color: hasError
                      ? theme.colorScheme.error
                      : _isFocused
                          ? theme.colorScheme.primary
                          : theme.colorScheme.onSurface.withOpacity(0.7),
                ),
                hintStyle: widget.hintStyle ?? theme.textTheme.bodyMedium?.copyWith(
                  color: theme.colorScheme.onSurface.withOpacity(0.5),
                ),
                errorStyle: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.error,
                ),
                helperStyle: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurface.withOpacity(0.6),
                ),
              ),
            );
          },
        ),
      ],
    );
  }
}

/// Specialized text fields
class EmailTextField extends CustomTextField {
  const EmailTextField({
    Key? key,
    TextEditingController? controller,
    String? label,
    String? hintText,
    String? Function(String?)? validator,
    ValueChanged<String>? onChanged,
    ValueChanged<String>? onFieldSubmitted,
    FocusNode? focusNode,
  }) : super(
    key: key,
    controller: controller,
    label: label ?? 'Email Address',
    hintText: hintText ?? 'Enter your email address',
    keyboardType: TextInputType.emailAddress,
    textInputAction: TextInputAction.next,
    prefixIcon: Icons.email_outlined,
    validator: validator,
    onChanged: onChanged,
    onFieldSubmitted: onFieldSubmitted,
    focusNode: focusNode,
    autocorrect: false,
    enableSuggestions: false,
  );
}

class PasswordTextField extends StatefulWidget {
  final TextEditingController? controller;
  final String? label;
  final String? hintText;
  final String? Function(String?)? validator;
  final ValueChanged<String>? onChanged;
  final ValueChanged<String>? onFieldSubmitted;
  final FocusNode? focusNode;
  final bool showStrengthIndicator;

  const PasswordTextField({
    Key? key,
    this.controller,
    this.label,
    this.hintText,
    this.validator,
    this.onChanged,
    this.onFieldSubmitted,
    this.focusNode,
    this.showStrengthIndicator = false,
  }) : super(key: key);

  @override
  State<PasswordTextField> createState() => _PasswordTextFieldState();
}

class _PasswordTextFieldState extends State<PasswordTextField> {
  bool _obscurePassword = true;
  
  @override
  Widget build(BuildContext context) {
    return CustomTextField(
      controller: widget.controller,
      label: widget.label ?? 'Password',
      hintText: widget.hintText ?? 'Enter your password',
      keyboardType: TextInputType.visiblePassword,
      textInputAction: TextInputAction.done,
      obscureText: _obscurePassword,
      prefixIcon: Icons.lock_outline,
      suffixIcon: IconButton(
        icon: Icon(
          _obscurePassword ? Icons.visibility_off_outlined : Icons.visibility_outlined,
        ),
        onPressed: () {
          setState(() => _obscurePassword = !_obscurePassword);
        },
      ),
      validator: widget.validator,
      onChanged: widget.onChanged,
      onFieldSubmitted: widget.onFieldSubmitted,
      focusNode: widget.focusNode,
      autocorrect: false,
      enableSuggestions: false,
    );
  }
}

class SearchTextField extends CustomTextField {
  const SearchTextField({
    Key? key,
    TextEditingController? controller,
    String? hintText,
    ValueChanged<String>? onChanged,
    VoidCallback? onClear,
    FocusNode? focusNode,
  }) : super(
    key: key,
    controller: controller,
    hintText: hintText ?? 'Search...',
    prefixIcon: Icons.search,
    suffixIcon: controller?.text.isNotEmpty == true
        ? IconButton(
            icon: const Icon(Icons.clear),
            onPressed: onClear,
          )
        : null,
    onChanged: onChanged,
    focusNode: focusNode,
    variant: TextFieldVariant.filled,
  );
}