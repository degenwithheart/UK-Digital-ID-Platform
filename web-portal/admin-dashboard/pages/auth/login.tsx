import React, { useState, useEffect } from 'react';
import {
  Box,
  Container,
  Paper,
  TextField,
  Button,
  Typography,
  Alert,
  Card,
  CardContent,
  CircularProgress,
  InputAdornment,
  IconButton,
} from '@mui/material';
import {
  AdminPanelSettings as AdminIcon,
  Visibility,
  VisibilityOff,
  Security as SecurityIcon,
} from '@mui/icons-material';

const AdminLogin: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      // Simulate admin login
      if (email === 'admin@system.gov.uk' && password === 'AdminPass123!') {
        // Create mock admin token and user
        const adminUser = {
          id: 'admin-1',
          email: 'admin@system.gov.uk',
          name: 'System Administrator',
          role: 'admin',
          permissions: ['*'],
          isVerified: true
        };
        
        const mockToken = btoa(JSON.stringify({
          sub: 'admin-1',
          email: 'admin@system.gov.uk',
          name: 'System Administrator',
          role: 'admin',
          permissions: ['*'],
          isVerified: true,
          exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60), // 24 hours
          iat: Math.floor(Date.now() / 1000)
        }));

        localStorage.setItem('admin_token', mockToken);
        localStorage.setItem('admin_user', JSON.stringify(adminUser));
        
        // Redirect to admin dashboard
        window.location.href = '/admin';
      } else {
        throw new Error('Invalid credentials or insufficient privileges');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  // Check if already logged in
  useEffect(() => {
    const token = localStorage.getItem('admin_token');
    const userStr = localStorage.getItem('admin_user');
    
    if (token && userStr) {
      try {
        const user = JSON.parse(userStr);
        if (user.role === 'admin') {
          window.location.href = '/admin';
        }
      } catch {
        // Invalid stored data, continue with login
      }
    }
  }, []);

  return (
    <Box
      sx={{
        minHeight: '100vh',
        background: 'linear-gradient(135deg, #1976d2 0%, #42a5f5 100%)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        p: 2
      }}
    >
      <Container maxWidth="sm">
        <Paper elevation={8} sx={{ borderRadius: 2, overflow: 'hidden' }}>
          {/* Header */}
          <Box
            sx={{
              background: 'linear-gradient(135deg, #1565c0 0%, #1976d2 100%)',
              color: 'white',
              p: 4,
              textAlign: 'center'
            }}
          >
            <AdminIcon sx={{ fontSize: 60, mb: 2 }} />
            <Typography variant="h4" gutterBottom fontWeight="bold">
              Admin Dashboard
            </Typography>
            <Typography variant="h6" sx={{ opacity: 0.9 }}>
              UK Digital Identity Platform
            </Typography>
            <Typography variant="body2" sx={{ opacity: 0.8, mt: 1 }}>
              Secure Administrative Access
            </Typography>
          </Box>

          {/* Login Form */}
          <Box sx={{ p: 4 }}>
            <Card variant="outlined" sx={{ mb: 3 }}>
              <CardContent sx={{ textAlign: 'center', py: 2 }}>
                <SecurityIcon color="primary" sx={{ mb: 1 }} />
                <Typography variant="body2" color="text.secondary">
                  This system is for authorized government personnel only. 
                  All access attempts are logged and monitored.
                </Typography>
              </CardContent>
            </Card>

            {error && (
              <Alert severity="error" sx={{ mb: 3 }}>
                {error}
              </Alert>
            )}

            <Box component="form" onSubmit={handleLogin}>
              <TextField
                fullWidth
                label="Admin Email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                margin="normal"
                required
                autoComplete="email"
                placeholder="admin@system.gov.uk"
                disabled={loading}
              />

              <TextField
                fullWidth
                label="Password"
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                margin="normal"
                required
                autoComplete="current-password"
                disabled={loading}
                InputProps={{
                  endAdornment: (
                    <InputAdornment position="end">
                      <IconButton
                        onClick={() => setShowPassword(!showPassword)}
                        edge="end"
                      >
                        {showPassword ? <VisibilityOff /> : <Visibility />}
                      </IconButton>
                    </InputAdornment>
                  ),
                }}
              />

              <Button
                type="submit"
                fullWidth
                variant="contained"
                size="large"
                disabled={loading || !email || !password}
                sx={{ 
                  mt: 3, 
                  mb: 2,
                  py: 1.5,
                  background: 'linear-gradient(135deg, #1565c0 0%, #1976d2 100%)',
                  '&:hover': {
                    background: 'linear-gradient(135deg, #0d47a1 0%, #1565c0 100%)',
                  }
                }}
              >
                {loading ? (
                  <CircularProgress size={24} color="inherit" />
                ) : (
                  'Access Admin Dashboard'
                )}
              </Button>
            </Box>

            {/* Demo Credentials Info */}
            <Card variant="outlined" sx={{ mt: 3, bgcolor: 'grey.50' }}>
              <CardContent sx={{ py: 2 }}>
                <Typography variant="subtitle2" color="primary" gutterBottom>
                  Demo Credentials:
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Email: admin@system.gov.uk<br />
                  Password: AdminPass123!
                </Typography>
              </CardContent>
            </Card>

            <Typography 
              variant="caption" 
              color="text.secondary" 
              sx={{ display: 'block', textAlign: 'center', mt: 3 }}
            >
              Protected by multi-factor authentication and continuous monitoring
            </Typography>
          </Box>
        </Paper>
      </Container>
    </Box>
  );
};

export default AdminLogin;