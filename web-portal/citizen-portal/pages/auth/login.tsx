import React, { useState, useEffect } from 'react';
import { NextPage } from 'next';
import Head from 'next/head';
import Link from 'next/link';
import { useRouter } from 'next/router';
import {
  Container,
  Paper,
  TextField,
  Button,
  Typography,
  Box,
  Alert,
  InputAdornment,
  IconButton,
  FormControlLabel,
  Checkbox,
  Divider,
  CircularProgress,
  Grid,
} from '@mui/material';
import {
  Visibility,
  VisibilityOff,
  Email,
  Lock,
  Fingerprint,
  Google,
  Facebook,
  Apple,
  Security,
} from '@mui/icons-material';
import { useFormik } from 'formik';
import * as Yup from 'yup';
import { motion, AnimatePresence } from 'framer-motion';
import { useAppDispatch, useAppSelector } from '@/store/hooks';
import { loginUser, clearError } from '@/store/slices/authSlice';
import { addNotification } from '@/store/slices/notificationSlice';
import { LoginCredentials } from '@/types';
import { FEATURES, REGEX_PATTERNS } from '@/config/constants';

// Validation schema
const validationSchema = Yup.object({
  email: Yup.string()
    .matches(REGEX_PATTERNS.EMAIL, 'Invalid email address')
    .required('Email is required'),
  password: Yup.string()
    .min(8, 'Password must be at least 8 characters')
    .required('Password is required'),
  twoFactorCode: Yup.string().when('showTwoFactor', {
    is: true,
    then: Yup.string()
      .length(6, 'Two-factor code must be 6 digits')
      .matches(/^\d+$/, 'Two-factor code must be numeric')
      .required('Two-factor code is required'),
  }),
});

const Login: NextPage = () => {
  const router = useRouter();
  const dispatch = useAppDispatch();
  const { isLoading, error, isAuthenticated, loginAttempts, accountLocked } = useAppSelector((state) => state.auth);
  
  const [showPassword, setShowPassword] = useState(false);
  const [showTwoFactor, setShowTwoFactor] = useState(false);
  const [biometricAvailable, setBiometricAvailable] = useState(false);
  
  const formik = useFormik<LoginCredentials & { showTwoFactor?: boolean }>({
    initialValues: {
      email: '',
      password: '',
      rememberMe: false,
      twoFactorCode: '',
      showTwoFactor: false,
    },
    validationSchema,
    onSubmit: async (values) => {
      try {
        const result = await dispatch(loginUser(values));
        
        if (loginUser.fulfilled.match(result)) {
          dispatch(addNotification({
            type: 'success',
            title: 'Login Successful',
            message: 'Welcome back to your Digital ID Portal',
          }));
          
          // Redirect to dashboard or intended page
          const returnUrl = router.query.returnUrl as string || '/dashboard';
          router.push(returnUrl);
        } else if (loginUser.rejected.match(result)) {
          // Handle specific error cases
          if (result.payload === 'Two-factor authentication required') {
            setShowTwoFactor(true);
            formik.setFieldValue('showTwoFactor', true);
          } else {
            dispatch(addNotification({
              type: 'error',
              title: 'Login Failed',
              message: result.payload as string,
            }));
          }
        }
      } catch (error: any) {
        dispatch(addNotification({
          type: 'error',
          title: 'Login Error',
          message: error.message || 'An unexpected error occurred',
        }));
      }
    },
  });

  // Check for biometric availability
  useEffect(() => {
    const checkBiometricSupport = async () => {
      if (typeof window !== 'undefined' && 'navigator' in window && 'credentials' in navigator) {
        try {
          const available = await (navigator as any).credentials?.get?.({
            publicKey: { challenge: new Uint8Array(32) }
          });
          setBiometricAvailable(true);
        } catch {
          setBiometricAvailable(false);
        }
      }
    };

    if (FEATURES.BIOMETRIC_AUTH) {
      checkBiometricSupport();
    }
  }, []);

  // Redirect if already authenticated
  useEffect(() => {
    if (isAuthenticated) {
      const returnUrl = router.query.returnUrl as string || '/dashboard';
      router.push(returnUrl);
    }
  }, [isAuthenticated, router]);

  // Clear error on component mount
  useEffect(() => {
    dispatch(clearError());
  }, [dispatch]);

  const handleBiometricLogin = async () => {
    try {
      // Implement biometric authentication
      dispatch(addNotification({
        type: 'info',
        title: 'Biometric Authentication',
        message: 'Please authenticate using your biometric device',
      }));
    } catch (error) {
      dispatch(addNotification({
        type: 'error',
        title: 'Biometric Authentication Failed',
        message: 'Please try again or use password login',
      }));
    }
  };

  const handleSocialLogin = (provider: string) => {
    // Implement social login
    window.location.href = `/api/auth/social/${provider}`;
  };

  if (accountLocked) {
    return (
      <Container maxWidth="sm" sx={{ mt: 8 }}>
        <Head>
          <title>Account Locked - UK Digital Identity Portal</title>
          <meta name="description" content="Your account has been temporarily locked" />
        </Head>
        
        <Paper elevation={3} sx={{ p: 4, textAlign: 'center' }}>
          <Security color="error" sx={{ fontSize: 64, mb: 2 }} />
          <Typography variant="h4" gutterBottom color="error">
            Account Locked
          </Typography>
          <Typography variant="body1" sx={{ mb: 3 }}>
            Your account has been temporarily locked due to multiple failed login attempts.
            Please try again later or contact support.
          </Typography>
          <Button
            variant="outlined"
            component={Link}
            href="/auth/forgot-password"
            sx={{ mr: 2 }}
          >
            Reset Password
          </Button>
          <Button
            variant="contained"
            href="mailto:support@digital-identity.gov.uk"
          >
            Contact Support
          </Button>
        </Paper>
      </Container>
    );
  }

  return (
    <Container maxWidth="sm" sx={{ mt: 4 }}>
      <Head>
        <title>Login - UK Digital Identity Portal</title>
        <meta name="description" content="Sign in to your UK Digital Identity account" />
      </Head>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <Paper elevation={3} sx={{ p: 4 }}>
          <Box textAlign="center" mb={3}>
            <Typography variant="h4" component="h1" gutterBottom>
              Sign In
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Access your Digital Identity Portal
            </Typography>
          </Box>

          {error && (
            <Alert severity="error" sx={{ mb: 3 }} onClose={() => dispatch(clearError())}>
              {error}
            </Alert>
          )}

          {loginAttempts > 0 && loginAttempts < 5 && (
            <Alert severity="warning" sx={{ mb: 3 }}>
              Failed login attempt {loginAttempts} of 5. Account will be locked after 5 failed attempts.
            </Alert>
          )}

          <form onSubmit={formik.handleSubmit}>
            <TextField
              fullWidth
              id="email"
              name="email"
              label="Email Address"
              type="email"
              value={formik.values.email}
              onChange={formik.handleChange}
              onBlur={formik.handleBlur}
              error={formik.touched.email && Boolean(formik.errors.email)}
              helperText={formik.touched.email && formik.errors.email}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <Email />
                  </InputAdornment>
                ),
              }}
              sx={{ mb: 2 }}
              autoComplete="email"
            />

            <TextField
              fullWidth
              id="password"
              name="password"
              label="Password"
              type={showPassword ? 'text' : 'password'}
              value={formik.values.password}
              onChange={formik.handleChange}
              onBlur={formik.handleBlur}
              error={formik.touched.password && Boolean(formik.errors.password)}
              helperText={formik.touched.password && formik.errors.password}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <Lock />
                  </InputAdornment>
                ),
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton
                      onClick={() => setShowPassword(!showPassword)}
                      edge="end"
                      aria-label="toggle password visibility"
                    >
                      {showPassword ? <VisibilityOff /> : <Visibility />}
                    </IconButton>
                  </InputAdornment>
                ),
              }}
              sx={{ mb: 2 }}
              autoComplete="current-password"
            />

            <AnimatePresence>
              {showTwoFactor && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  transition={{ duration: 0.3 }}
                >
                  <TextField
                    fullWidth
                    id="twoFactorCode"
                    name="twoFactorCode"
                    label="Two-Factor Authentication Code"
                    value={formik.values.twoFactorCode}
                    onChange={formik.handleChange}
                    onBlur={formik.handleBlur}
                    error={formik.touched.twoFactorCode && Boolean(formik.errors.twoFactorCode)}
                    helperText={formik.touched.twoFactorCode && formik.errors.twoFactorCode}
                    sx={{ mb: 2 }}
                    placeholder="Enter 6-digit code"
                    inputProps={{ maxLength: 6 }}
                  />
                </motion.div>
              )}
            </AnimatePresence>

            <FormControlLabel
              control={
                <Checkbox
                  name="rememberMe"
                  checked={formik.values.rememberMe}
                  onChange={formik.handleChange}
                />
              }
              label="Remember me"
              sx={{ mb: 2 }}
            />

            <Button
              type="submit"
              fullWidth
              variant="contained"
              size="large"
              disabled={isLoading}
              sx={{ mb: 2, py: 1.5 }}
            >
              {isLoading ? <CircularProgress size={24} /> : 'Sign In'}
            </Button>
          </form>

          {/* Biometric Authentication */}
          {FEATURES.BIOMETRIC_AUTH && biometricAvailable && (
            <>
              <Divider sx={{ my: 2 }}>
                <Typography variant="body2" color="text.secondary">
                  OR
                </Typography>
              </Divider>

              <Button
                fullWidth
                variant="outlined"
                startIcon={<Fingerprint />}
                onClick={handleBiometricLogin}
                sx={{ mb: 2 }}
              >
                Use Biometric Authentication
              </Button>
            </>
          )}

          {/* Social Login */}
          {FEATURES.SOCIAL_LOGIN && (
            <>
              <Divider sx={{ my: 2 }}>
                <Typography variant="body2" color="text.secondary">
                  OR CONTINUE WITH
                </Typography>
              </Divider>

              <Grid container spacing={2} sx={{ mb: 2 }}>
                <Grid item xs={4}>
                  <Button
                    fullWidth
                    variant="outlined"
                    startIcon={<Google />}
                    onClick={() => handleSocialLogin('google')}
                  >
                    Google
                  </Button>
                </Grid>
                <Grid item xs={4}>
                  <Button
                    fullWidth
                    variant="outlined"
                    startIcon={<Facebook />}
                    onClick={() => handleSocialLogin('facebook')}
                  >
                    Facebook
                  </Button>
                </Grid>
                <Grid item xs={4}>
                  <Button
                    fullWidth
                    variant="outlined"
                    startIcon={<Apple />}
                    onClick={() => handleSocialLogin('apple')}
                  >
                    Apple
                  </Button>
                </Grid>
              </Grid>
            </>
          )}

          <Box textAlign="center" mt={3}>
            <Typography variant="body2">
              <Link href="/auth/forgot-password">
                Forgot your password?
              </Link>
            </Typography>
            <Typography variant="body2" mt={1}>
              Don't have an account?{' '}
              <Link href="/auth/register">
                Create one here
              </Link>
            </Typography>
          </Box>
        </Paper>
      </motion.div>
    </Container>
  );
};

export default Login;