import React, { useEffect } from 'react';
import { NextPage } from 'next';
import Head from 'next/head';
import { useRouter } from 'next/router';
import {
  Container,
  Typography,
  Button,
  Box,
  Grid,
  Card,
  CardContent,
  Paper,
  Chip,
} from '@mui/material';
import {
  Security,
  Verified,
  Speed,
  AccountBalance,
  ArrowForward,
  Login,
  PersonAdd,
} from '@mui/icons-material';
import { motion } from 'framer-motion';
import { useAppSelector } from '@/store/hooks';

const HomePage: NextPage = () => {
  const router = useRouter();
  const { isAuthenticated } = useAppSelector((state) => state.auth);

  useEffect(() => {
    // Redirect authenticated users to dashboard
    if (isAuthenticated) {
      router.push('/dashboard');
    }
  }, [isAuthenticated, router]);

  const features = [
    {
      icon: <Security />,
      title: 'Secure & Trusted',
      description: 'Bank-level security with end-to-end encryption and multi-factor authentication.',
      color: 'primary',
    },
    {
      icon: <Verified />,
      title: 'Government Verified',
      description: 'Official UK government identity verification with enhanced security levels.',
      color: 'success',
    },
    {
      icon: <Speed />,
      title: 'Fast & Convenient',
      description: 'Access all government services instantly with a single secure login.',
      color: 'info',
    },
    {
      icon: <AccountBalance />,
      title: 'All Services',
      description: 'Connect to HMRC, NHS, DVLA, and all other government departments.',
      color: 'secondary',
    },
  ];

  if (isAuthenticated) {
    return null; // Will redirect to dashboard
  }

  return (
    <>
      <Head>
        <title>UK Digital Identity Portal - Secure Government Services Access</title>
        <meta 
          name="description" 
          content="Access all UK government services securely with your digital identity. One account for HMRC, NHS, DVLA and more." 
        />
      </Head>

      <Box sx={{ minHeight: '100vh', backgroundColor: 'background.default' }}>
        {/* Hero Section */}
        <Container maxWidth="lg" sx={{ pt: 8, pb: 6 }}>
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
          >
            <Box textAlign="center" mb={6}>
              <Typography
                variant="h2"
                component="h1"
                gutterBottom
                sx={{ fontWeight: 'bold' }}
              >
                UK Digital Identity Portal
              </Typography>
              
              <Typography variant="h5" color="text.secondary" paragraph>
                Your secure gateway to all UK government services
              </Typography>

              <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
                <Button
                  variant="contained"
                  size="large"
                  startIcon={<Login />}
                  onClick={() => router.push('/auth/login')}
                  sx={{ px: 4, py: 1.5 }}
                >
                  Sign In
                </Button>
                
                <Button
                  variant="outlined"
                  size="large"
                  startIcon={<PersonAdd />}
                  onClick={() => router.push('/auth/register')}
                  sx={{ px: 4, py: 1.5 }}
                >
                  Create Account
                </Button>
              </Box>
            </Box>
          </motion.div>
        </Container>

        {/* Features Section */}
        <Container maxWidth="lg" sx={{ py: 8 }}>
          <Grid container spacing={4}>
            {features.map((feature, index) => (
              <Grid item xs={12} md={6} lg={3} key={index}>
                <Card sx={{ height: '100%', textAlign: 'center' }}>
                  <CardContent sx={{ p: 3 }}>
                    <Box sx={{ mb: 2 }}>
                      {feature.icon}
                    </Box>
                    <Typography variant="h6" gutterBottom>
                      {feature.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {feature.description}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Container>
      </Box>
    </>
  );
};

export default HomePage;