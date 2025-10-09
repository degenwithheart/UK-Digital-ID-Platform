import { configureStore, ThunkAction, Action } from '@reduxjs/toolkit';
import { createWrapper, HYDRATE } from 'next-redux-wrapper';
import { persistStore, persistReducer, FLUSH, REHYDRATE, PAUSE, PERSIST, PURGE, REGISTER } from 'redux-persist';
import storage from 'redux-persist/lib/storage';
import { combineReducers } from '@reduxjs/toolkit';

// Import reducers
import authReducer from './slices/authSlice';
import walletReducer from './slices/walletSlice';
import uiReducer from './slices/uiSlice';
import notificationReducer from './slices/notificationSlice';
import themeReducer from './slices/themeSlice';

// Root reducer
const rootReducer = combineReducers({
  auth: authReducer,
  wallet: walletReducer,
  ui: uiReducer,
  notifications: notificationReducer,
  theme: themeReducer,
});

// Persist configuration
const persistConfig = {
  key: 'root',
  version: 1,
  storage,
  whitelist: ['auth', 'theme', 'wallet'], // Only persist these reducers
  blacklist: ['ui', 'notifications'], // Don't persist these
};

const persistedReducer = persistReducer(persistConfig, rootReducer);

// Master reducer with HYDRATE action for SSR
const masterReducer = (state: any, action: any) => {
  if (action.type === HYDRATE) {
    const nextState = {
      ...state, // use previous state
      ...action.payload, // apply delta from hydration
    };
    
    // Preserve client-side state for specific slices
    if (state.auth) nextState.auth = state.auth;
    if (state.theme) nextState.theme = state.theme;
    
    return nextState;
  } else {
    return persistedReducer(state, action);
  }
};

// Store creator
export const makeStore = () => {
  const store = configureStore({
    reducer: masterReducer,
    devTools: process.env.NODE_ENV !== 'production',
    middleware: (getDefaultMiddleware) =>
      getDefaultMiddleware({
        serializableCheck: {
          ignoredActions: [FLUSH, REHYDRATE, PAUSE, PERSIST, PURGE, REGISTER, HYDRATE],
        },
        immutableCheck: {
          warnAfter: 128,
        },
        serializableStateInvariantMiddleware: {
          warnAfter: 128,
        },
      }),
  });

  // Enable hot module replacement
  if (process.env.NODE_ENV === 'development' && module.hot) {
    module.hot.accept('./slices', () => {
      const newRootReducer = require('./slices').default;
      store.replaceReducer(newRootReducer);
    });
  }

  return store;
};

// Store type
export type AppStore = ReturnType<typeof makeStore>;
export type RootState = ReturnType<AppStore['getState']>;
export type AppThunk<ReturnType = void> = ThunkAction<ReturnType, RootState, unknown, Action<string>>;
export type AppDispatch = AppStore['dispatch'];

// Create wrapper
export const wrapper = createWrapper<AppStore>(makeStore, {
  debug: process.env.NODE_ENV === 'development',
});

// Persistor factory
export const createPersistor = (store: AppStore) => persistStore(store);

// Typed hooks
export { useAppDispatch, useAppSelector } from './hooks';