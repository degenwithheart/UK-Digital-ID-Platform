import React from 'react';
import type { AppProps } from 'next/app';
import { ThemeProvider, CssBaseline } from '@mui/material';
import { LocalizationProvider } from '@mui/x-date-pickers';
import { AdapterDayjs } from '@mui/x-date-pickers/AdapterDayjs';
import { SnackbarProvider } from 'notistack';
import { Provider } from 'react-redux';
import { PersistGate } from 'redux-persist/integration/react';
import { wrapper } from '@/store';
import { createTheme } from '@/utils/theme';
import { useAppSelector } from '@/store/hooks';
import Layout from '@/components/Layout';
import LoadingScreen from '@/components/LoadingScreen';
import ErrorBoundary from '@/components/ErrorBoundary';
import AuthGuard from '@/components/AuthGuard';
import { FEATURES } from '@/config/constants';
import '@/styles/globals.css';

// Theme Provider Component
const ThemeProviderWrapper: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const themeSettings = useAppSelector((state) => state.theme);
  const theme = createTheme(themeSettings);

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      {children}
    </ThemeProvider>
  );
};

// Main App Component
function MyApp({ Component, pageProps }: AppProps) {
  const { store, props } = wrapper.useWrappedStore({ ...pageProps });
  
  // Check if page needs authentication
  const isAuthPage = Component.displayName?.includes('Auth') || 
                     pageProps.requireAuth === false;

  return (
    <Provider store={store}>
      <PersistGate loading={<LoadingScreen />} persistor={store.__persistor}>
        <ThemeProviderWrapper>
          <LocalizationProvider dateAdapter={AdapterDayjs}>
            <SnackbarProvider
              maxSnack={3}
              anchorOrigin={{
                vertical: 'top',
                horizontal: 'right',
              }}
              dense
              preventDuplicate
            >
              <ErrorBoundary>
                {isAuthPage ? (
                  <Component {...pageProps} />
                ) : (
                  <AuthGuard>
                    <Layout>
                      <Component {...pageProps} />
                    </Layout>
                  </AuthGuard>
                )}
              </ErrorBoundary>
            </SnackbarProvider>
          </LocalizationProvider>
        </ThemeProviderWrapper>
      </PersistGate>
    </Provider>
  );
}

export default wrapper.withRedux(MyApp);