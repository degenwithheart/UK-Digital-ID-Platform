import { useState, useEffect, useCallback } from 'react';
import { jwtDecode } from 'jwt-decode';

interface User {
  id: string;
  email: string;
  name: string;
  role: 'admin' | 'government_official' | 'citizen';
  permissions: string[];
  isVerified: boolean;
}

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  isAdmin: boolean;
  isLoading: boolean;
  token: string | null;
}

interface JWTPayload {
  sub: string;
  email: string;
  name: string;
  role: string;
  permissions: string[];
  isVerified: boolean;
  exp: number;
  iat: number;
}

export const useAuth = () => {
  const [authState, setAuthState] = useState<AuthState>({
    user: null,
    isAuthenticated: false,
    isAdmin: false,
    isLoading: true,
    token: null
  });

  const checkTokenExpiration = useCallback((token: string): boolean => {
    try {
      const decoded = jwtDecode<JWTPayload>(token);
      const currentTime = Date.now() / 1000;
      return decoded.exp > currentTime;
    } catch {
      return false;
    }
  }, []);

  const setUser = useCallback((token: string) => {
    try {
      const decoded = jwtDecode<JWTPayload>(token);
      const user: User = {
        id: decoded.sub,
        email: decoded.email,
        name: decoded.name,
        role: decoded.role as User['role'],
        permissions: decoded.permissions || [],
        isVerified: decoded.isVerified
      };

      setAuthState({
        user,
        isAuthenticated: true,
        isAdmin: user.role === 'admin',
        isLoading: false,
        token
      });

      // Store in localStorage
      localStorage.setItem('admin_token', token);
      localStorage.setItem('admin_user', JSON.stringify(user));
    } catch (error) {
      console.error('Error decoding token:', error);
      logout();
    }
  }, []);

  const login = useCallback(async (email: string, password: string): Promise<boolean> => {
    try {
      setAuthState(prev => ({ ...prev, isLoading: true }));

      const response = await fetch('/api/auth/admin/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email, password, adminAccess: true })
      });

      if (!response.ok) {
        throw new Error('Login failed');
      }

      const data = await response.json();
      
      if (data.token && data.user?.role === 'admin') {
        setUser(data.token);
        return true;
      } else {
        throw new Error('Insufficient privileges for admin access');
      }
    } catch (error) {
      console.error('Login error:', error);
      setAuthState(prev => ({ ...prev, isLoading: false }));
      return false;
    }
  }, [setUser]);

  const logout = useCallback(() => {
    localStorage.removeItem('admin_token');
    localStorage.removeItem('admin_user');
    
    setAuthState({
      user: null,
      isAuthenticated: false,
      isAdmin: false,
      isLoading: false,
      token: null
    });

    // Redirect to login
    window.location.href = '/auth/login';
  }, []);

  const refreshToken = useCallback(async (): Promise<boolean> => {
    const token = localStorage.getItem('admin_token');
    if (!token) return false;

    try {
      const response = await fetch('/api/auth/refresh', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) throw new Error('Token refresh failed');

      const data = await response.json();
      setUser(data.token);
      return true;
    } catch (error) {
      console.error('Token refresh error:', error);
      logout();
      return false;
    }
  }, [setUser, logout]);

  const hasPermission = useCallback((permission: string): boolean => {
    return authState.user?.permissions.includes(permission) || authState.isAdmin || false;
  }, [authState.user?.permissions, authState.isAdmin]);

  const hasAnyPermission = useCallback((permissions: string[]): boolean => {
    return permissions.some(permission => hasPermission(permission));
  }, [hasPermission]);

  // Initialize auth state on mount
  useEffect(() => {
    const initAuth = async () => {
      const token = localStorage.getItem('admin_token');
      const userStr = localStorage.getItem('admin_user');

      if (token && userStr) {
        if (checkTokenExpiration(token)) {
          try {
            const user = JSON.parse(userStr);
            if (user.role === 'admin') {
              setAuthState({
                user,
                isAuthenticated: true,
                isAdmin: true,
                isLoading: false,
                token
              });
            } else {
              logout();
            }
          } catch {
            logout();
          }
        } else {
          // Try to refresh token
          const refreshed = await refreshToken();
          if (!refreshed) {
            setAuthState(prev => ({ ...prev, isLoading: false }));
          }
        }
      } else {
        setAuthState(prev => ({ ...prev, isLoading: false }));
      }
    };

    initAuth();
  }, [checkTokenExpiration, refreshToken, logout]);

  // Auto-refresh token before expiration
  useEffect(() => {
    if (!authState.token) return;

    const interval = setInterval(async () => {
      if (authState.token && checkTokenExpiration(authState.token)) {
        // Refresh token when it's 5 minutes from expiration
        const decoded = jwtDecode<JWTPayload>(authState.token);
        const currentTime = Date.now() / 1000;
        const timeToExpiry = decoded.exp - currentTime;
        
        if (timeToExpiry < 300) { // 5 minutes
          await refreshToken();
        }
      }
    }, 60000); // Check every minute

    return () => clearInterval(interval);
  }, [authState.token, checkTokenExpiration, refreshToken]);

  return {
    ...authState,
    login,
    logout,
    refreshToken,
    hasPermission,
    hasAnyPermission,
    checkTokenExpiration
  };
};