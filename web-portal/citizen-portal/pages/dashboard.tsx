import React from 'react';
import { NextPage } from 'next';
import Head from 'next/head';
import Link from 'next/link';
import { useRouter } from 'next/router';
import {
  Container,
  Paper,
  Typography,
  Box,
  Button,
  Grid,
  Card,
  CardContent,
  CardActions,
  Chip,
  Avatar,
  LinearProgress,
  Alert,
  Fab,
} from '@mui/material';
import {
  Dashboard as DashboardIcon,
  Security,
  AccountBox,
  Verified,
  Warning,
  Add,
  Sync,
  Notifications,
  TrendingUp,
  Shield,
  Speed,
} from '@mui/icons-material';
import { motion } from 'framer-motion';
import { useAppSelector } from '@/store/hooks';
import { VERIFICATION_LEVELS } from '@/config/constants';

const Dashboard: NextPage = () => {
  const router = useRouter();
  const { user, isAuthenticated } = useAppSelector((state) => state.auth);
  const { credentials, services, totalCredentials, verifiedCredentials } = useAppSelector((state) => state.wallet);

  // Redirect if not authenticated
  React.useEffect(() => {
    if (!isAuthenticated) {
      router.push('/auth/login?returnUrl=/dashboard');
    }
  }, [isAuthenticated, router]);

  if (!isAuthenticated || !user) {
    return null; // Will redirect
  }

  const verificationProgress = totalCredentials > 0 ? (verifiedCredentials / totalCredentials) * 100 : 0;
  const securityScore = calculateSecurityScore();
  
  function calculateSecurityScore(): number {
    let score = 0;
    
    // Base score for having an account
    score += 20;
    
    // Two-factor authentication
    if (user?.twoFactorEnabled) score += 25;
    
    // Biometric authentication
    if (user?.biometricEnabled) score += 20;
    
    // Verified credentials
    if (verifiedCredentials > 0) score += 20;
    if (verifiedCredentials >= 3) score += 10;
    
    // Verification level
    switch (user?.verificationLevel) {
      case VERIFICATION_LEVELS.BASIC: score += 5; break;
      case VERIFICATION_LEVELS.ENHANCED: score += 10; break;
      case VERIFICATION_LEVELS.ENHANCED_PLUS: score += 15; break;
    }
    
    return Math.min(score, 100);
  }

  const getVerificationLevelColor = (level: string) => {
    switch (level) {
      case VERIFICATION_LEVELS.ENHANCED_PLUS: return 'success';
      case VERIFICATION_LEVELS.ENHANCED: return 'primary';
      case VERIFICATION_LEVELS.BASIC: return 'warning';
      default: return 'default';
    }
  };

  const getSecurityScoreColor = (score: number) => {
    if (score >= 80) return 'success';
    if (score >= 60) return 'warning';
    return 'error';
  };

  const quickActions = [
    {
      title: 'Add Credential',
      description: 'Upload a new document or certificate',
      icon: <Add />,
      href: '/credentials/add',
      color: 'primary',
    },
    {
      title: 'Browse Services',
      description: 'Find and access government services',
      icon: <Dashboard />,
      href: '/services',
      color: 'secondary',
    },
    {
      title: 'Security Settings',
      description: 'Manage your account security',
      icon: <Security />,
      href: '/settings/security',
      color: 'error',
    },
    {
      title: 'Profile Settings',
      description: 'Update your personal information',
      icon: <AccountBox />,
      href: '/settings/profile',
      color: 'info',
    },
  ];

  const recentActivities = [
    {
      type: 'credential_verified',
      title: 'Passport verified',
      description: 'Your passport has been successfully verified',
      timestamp: '2 hours ago',
      icon: <Verified color="success" />,
    },
    {
      type: 'service_access',
      title: 'HMRC Self Assessment accessed',
      description: 'You accessed HMRC Self Assessment service',
      timestamp: '1 day ago',
      icon: <DashboardIcon color="primary" />,
    },
    {
      type: 'security_update',
      title: 'Two-factor authentication enabled',
      description: 'You enabled 2FA for enhanced security',
      timestamp: '3 days ago',
      icon: <Shield color="success" />,
    },
  ];

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      <Head>
        <title>Dashboard - UK Digital Identity Portal</title>
        <meta name="description" content="Your Digital Identity dashboard" />
      </Head>

      {/* Welcome Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <Box mb={4}>
          <Typography variant="h3" component="h1" gutterBottom>
            Welcome back, {user.firstName}!
          </Typography>
          <Typography variant="h6" color="text.secondary">
            {new Date().toLocaleDateString('en-GB', { 
              weekday: 'long', 
              year: 'numeric', 
              month: 'long', 
              day: 'numeric' 
            })}
          </Typography>
        </Box>
      </motion.div>

      {/* Status Overview */}
      <Grid container spacing={3} mb={4}>
        {/* Verification Status */}
        <Grid item xs={12} md={6} lg={3}>
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5, delay: 0.1 }}
          >
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center" mb={2}>
                  <Avatar sx={{ bgcolor: 'primary.main', mr: 2 }}>
                    <Verified />
                  </Avatar>
                  <Box>
                    <Typography variant="h6">Verification Level</Typography>
                    <Chip 
                      label={user.verificationLevel?.replace('_', ' ').toUpperCase() || 'None'} 
                      color={getVerificationLevelColor(user.verificationLevel || '')}
                      size="small"
                    />
                  </Box>
                </Box>
                <LinearProgress 
                  variant="determinate" 
                  value={verificationProgress} 
                  sx={{ mb: 1 }}
                />
                <Typography variant="body2" color="text.secondary">
                  {verifiedCredentials} of {totalCredentials} credentials verified
                </Typography>
              </CardContent>
            </Card>
          </motion.div>
        </Grid>

        {/* Security Score */}
        <Grid item xs={12} md={6} lg={3}>
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5, delay: 0.2 }}
          >
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center" mb={2}>
                  <Avatar sx={{ bgcolor: getSecurityScoreColor(securityScore) + '.main', mr: 2 }}>
                    <Shield />
                  </Avatar>
                  <Box>
                    <Typography variant="h6">Security Score</Typography>
                    <Typography variant="h4" color={getSecurityScoreColor(securityScore) + '.main'}>
                      {securityScore}%
                    </Typography>
                  </Box>
                </Box>
                <LinearProgress 
                  variant="determinate" 
                  value={securityScore}
                  color={getSecurityScoreColor(securityScore)}
                  sx={{ mb: 1 }}
                />
                <Typography variant="body2" color="text.secondary">
                  {securityScore >= 80 ? 'Excellent' : securityScore >= 60 ? 'Good' : 'Needs improvement'}
                </Typography>
              </CardContent>
            </Card>
          </motion.div>
        </Grid>

        {/* Total Credentials */}
        <Grid item xs={12} md={6} lg={3}>
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5, delay: 0.3 }}
          >
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center">
                  <Avatar sx={{ bgcolor: 'info.main', mr: 2 }}>
                    <AccountBox />
                  </Avatar>
                  <Box>
                    <Typography variant="h6">Total Credentials</Typography>
                    <Typography variant="h4">{totalCredentials}</Typography>
                    <Typography variant="body2" color="text.secondary">
                      Documents in your wallet
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </motion.div>
        </Grid>

        {/* Active Services */}
        <Grid item xs={12} md={6} lg={3}>
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5, delay: 0.4 }}
          >
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center">
                  <Avatar sx={{ bgcolor: 'secondary.main', mr: 2 }}>
                    <Speed />
                  </Avatar>
                  <Box>
                    <Typography variant="h6">Active Services</Typography>
                    <Typography variant="h4">{user.enrolledServices?.length || 0}</Typography>
                    <Typography variant="body2" color="text.secondary">
                      Government services
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </motion.div>
        </Grid>
      </Grid>

      {/* Security Alerts */}
      {!user.twoFactorEnabled && (
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.5, delay: 0.5 }}
        >
          <Alert severity="warning" sx={{ mb: 3 }}>
            <Typography variant="subtitle1" gutterBottom>
              Enhance your security
            </Typography>
            <Typography variant="body2">
              Enable two-factor authentication to improve your account security score and protect your digital identity.
            </Typography>
            <Button
              component={Link}
              href="/settings/security"
              size="small"
              sx={{ mt: 1 }}
            >
              Enable 2FA
            </Button>
          </Alert>
        </motion.div>
      )}

      <Grid container spacing={3}>
        {/* Quick Actions */}
        <Grid item xs={12} lg={8}>
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.6 }}
          >
            <Paper sx={{ p: 3, mb: 3 }}>
              <Typography variant="h5" gutterBottom>
                Quick Actions
              </Typography>
              <Grid container spacing={2}>
                {quickActions.map((action, index) => (
                  <Grid item xs={12} sm={6} md={3} key={index}>
                    <Card 
                      sx={{ 
                        height: '100%', 
                        cursor: 'pointer',
                        transition: 'transform 0.2s',
                        '&:hover': { transform: 'translateY(-4px)' }
                      }}
                      onClick={() => router.push(action.href)}
                    >
                      <CardContent sx={{ textAlign: 'center' }}>
                        <Avatar sx={{ bgcolor: `${action.color}.main`, mx: 'auto', mb: 2 }}>
                          {action.icon}
                        </Avatar>
                        <Typography variant="h6" gutterBottom>
                          {action.title}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          {action.description}
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </motion.div>
        </Grid>

        {/* Recent Activity */}
        <Grid item xs={12} lg={4}>
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.7 }}
          >
            <Paper sx={{ p: 3, height: 'fit-content' }}>
              <Typography variant="h5" gutterBottom>
                Recent Activity
              </Typography>
              
              {recentActivities.map((activity, index) => (
                <Box key={index} display="flex" alignItems="start" mb={2}>
                  <Avatar sx={{ mr: 2, width: 32, height: 32 }}>
                    {activity.icon}
                  </Avatar>
                  <Box flex={1}>
                    <Typography variant="subtitle2">
                      {activity.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" gutterBottom>
                      {activity.description}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {activity.timestamp}
                    </Typography>
                  </Box>
                </Box>
              ))}
              
              <Button
                component={Link}
                href="/activity"
                fullWidth
                variant="outlined"
                sx={{ mt: 2 }}
              >
                View All Activity
              </Button>
            </Paper>
          </motion.div>
        </Grid>
      </Grid>

      {/* Floating Action Button */}
      <Fab
        color="primary"
        aria-label="sync"
        sx={{
          position: 'fixed',
          bottom: 16,
          right: 16,
        }}
        onClick={() => {
          // Implement sync functionality
        }}
      >
        <Sync />
      </Fab>
    </Container>
  );
};

export default Dashboard;