import React, { ReactNode, useEffect } from 'react';
import { useRouter } from 'next/router';
import { useAppSelector } from '@/store/hooks';
import LoadingScreen from './LoadingScreen';

interface AuthGuardProps {
  children: ReactNode;
}

const AuthGuard: React.FC<AuthGuardProps> = ({ children }) => {
  const router = useRouter();
  const { isAuthenticated, isLoading } = useAppSelector((state) => state.auth);

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      // Store the attempted URL for redirect after login
      const returnUrl = router.asPath;
      router.push(`/auth/login?returnUrl=${encodeURIComponent(returnUrl)}`);
    }
  }, [isAuthenticated, isLoading, router]);

  // Show loading while checking authentication
  if (isLoading) {
    return <LoadingScreen message="Checking authentication..." backdrop />;
  }

  // Show loading while redirecting to login
  if (!isAuthenticated) {
    return <LoadingScreen message="Redirecting to login..." backdrop />;
  }

  // User is authenticated, show the protected content
  return <>{children}</>;
};

export default AuthGuard;