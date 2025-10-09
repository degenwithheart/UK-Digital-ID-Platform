import { createSlice, PayloadAction, createAsyncThunk } from '@reduxjs/toolkit';

// Types
export interface Credential {
  id: string;
  type: 'passport' | 'driving_license' | 'national_id' | 'birth_certificate' | 'utility_bill' | 'bank_statement' | 'other';
  issuer: string;
  issuedDate: string;
  expiryDate?: string;
  status: 'pending' | 'verified' | 'expired' | 'revoked';
  verificationLevel: 'basic' | 'enhanced' | 'enhanced_plus';
  data: Record<string, any>;
  metadata: {
    uploadedAt: string;
    verifiedAt?: string;
    verifiedBy?: string;
    fileSize?: number;
    fileName?: string;
  };
}

export interface Service {
  id: string;
  name: string;
  description: string;
  provider: string;
  category: 'government' | 'healthcare' | 'financial' | 'education' | 'transport' | 'other';
  requiredVerificationLevel: 'none' | 'basic' | 'enhanced' | 'enhanced_plus';
  isActive: boolean;
  accessUrl?: string;
  iconUrl?: string;
  lastUsed?: string;
}

export interface WalletState {
  credentials: Credential[];
  services: Service[];
  isLoading: boolean;
  error: string | null;
  selectedCredential: string | null;
  syncStatus: 'idle' | 'syncing' | 'success' | 'error';
  lastSync?: string;
  backupEnabled: boolean;
  encryptionEnabled: boolean;
  totalCredentials: number;
  verifiedCredentials: number;
}

// Initial state
const initialState: WalletState = {
  credentials: [],
  services: [],
  isLoading: false,
  error: null,
  selectedCredential: null,
  syncStatus: 'idle',
  lastSync: undefined,
  backupEnabled: true,
  encryptionEnabled: true,
  totalCredentials: 0,
  verifiedCredentials: 0,
};

// Async thunks
export const fetchCredentials = createAsyncThunk(
  'wallet/fetchCredentials',
  async (_, { rejectWithValue }) => {
    try {
      const response = await fetch('/api/wallet/credentials', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
        },
      });

      if (!response.ok) {
        const error = await response.json();
        return rejectWithValue(error.message || 'Failed to fetch credentials');
      }

      return await response.json();
    } catch (error: any) {
      return rejectWithValue(error.message || 'Network error');
    }
  }
);

export const addCredential = createAsyncThunk(
  'wallet/addCredential',
  async (credentialData: Partial<Credential>, { rejectWithValue }) => {
    try {
      const response = await fetch('/api/wallet/credentials', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
        },
        body: JSON.stringify(credentialData),
      });

      if (!response.ok) {
        const error = await response.json();
        return rejectWithValue(error.message || 'Failed to add credential');
      }

      return await response.json();
    } catch (error: any) {
      return rejectWithValue(error.message || 'Network error');
    }
  }
);

export const updateCredential = createAsyncThunk(
  'wallet/updateCredential',
  async (
    { id, updates }: { id: string; updates: Partial<Credential> },
    { rejectWithValue }
  ) => {
    try {
      const response = await fetch(`/api/wallet/credentials/${id}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
        },
        body: JSON.stringify(updates),
      });

      if (!response.ok) {
        const error = await response.json();
        return rejectWithValue(error.message || 'Failed to update credential');
      }

      return await response.json();
    } catch (error: any) {
      return rejectWithValue(error.message || 'Network error');
    }
  }
);

export const deleteCredential = createAsyncThunk(
  'wallet/deleteCredential',
  async (id: string, { rejectWithValue }) => {
    try {
      const response = await fetch(`/api/wallet/credentials/${id}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
        },
      });

      if (!response.ok) {
        const error = await response.json();
        return rejectWithValue(error.message || 'Failed to delete credential');
      }

      return { id };
    } catch (error: any) {
      return rejectWithValue(error.message || 'Network error');
    }
  }
);

export const fetchServices = createAsyncThunk(
  'wallet/fetchServices',
  async (_, { rejectWithValue }) => {
    try {
      const response = await fetch('/api/wallet/services', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
        },
      });

      if (!response.ok) {
        const error = await response.json();
        return rejectWithValue(error.message || 'Failed to fetch services');
      }

      return await response.json();
    } catch (error: any) {
      return rejectWithValue(error.message || 'Network error');
    }
  }
);

export const syncWallet = createAsyncThunk(
  'wallet/syncWallet',
  async (_, { rejectWithValue }) => {
    try {
      const response = await fetch('/api/wallet/sync', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
        },
      });

      if (!response.ok) {
        const error = await response.json();
        return rejectWithValue(error.message || 'Sync failed');
      }

      return await response.json();
    } catch (error: any) {
      return rejectWithValue(error.message || 'Network error');
    }
  }
);

// Wallet slice
const walletSlice = createSlice({
  name: 'wallet',
  initialState,
  reducers: {
    clearError: (state) => {
      state.error = null;
    },
    setSelectedCredential: (state, action: PayloadAction<string | null>) => {
      state.selectedCredential = action.payload;
    },
    toggleBackup: (state) => {
      state.backupEnabled = !state.backupEnabled;
    },
    toggleEncryption: (state) => {
      state.encryptionEnabled = !state.encryptionEnabled;
    },
    setSyncStatus: (state, action: PayloadAction<WalletState['syncStatus']>) => {
      state.syncStatus = action.payload;
    },
    updateCredentialLocally: (state, action: PayloadAction<{ id: string; updates: Partial<Credential> }>) => {
      const { id, updates } = action.payload;
      const credential = state.credentials.find(c => c.id === id);
      if (credential) {
        Object.assign(credential, updates);
      }
    },
  },
  extraReducers: (builder) => {
    builder
      // Fetch credentials
      .addCase(fetchCredentials.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(fetchCredentials.fulfilled, (state, action) => {
        state.isLoading = false;
        state.credentials = action.payload.credentials;
        state.totalCredentials = action.payload.credentials.length;
        state.verifiedCredentials = action.payload.credentials.filter(
          (c: Credential) => c.status === 'verified'
        ).length;
        state.lastSync = new Date().toISOString();
      })
      .addCase(fetchCredentials.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload as string;
      })
      // Add credential
      .addCase(addCredential.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(addCredential.fulfilled, (state, action) => {
        state.isLoading = false;
        state.credentials.push(action.payload);
        state.totalCredentials = state.credentials.length;
      })
      .addCase(addCredential.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload as string;
      })
      // Update credential
      .addCase(updateCredential.fulfilled, (state, action) => {
        const index = state.credentials.findIndex(c => c.id === action.payload.id);
        if (index !== -1) {
          state.credentials[index] = action.payload;
          state.verifiedCredentials = state.credentials.filter(
            c => c.status === 'verified'
          ).length;
        }
      })
      // Delete credential
      .addCase(deleteCredential.fulfilled, (state, action) => {
        state.credentials = state.credentials.filter(c => c.id !== action.payload.id);
        state.totalCredentials = state.credentials.length;
        state.verifiedCredentials = state.credentials.filter(
          c => c.status === 'verified'
        ).length;
        if (state.selectedCredential === action.payload.id) {
          state.selectedCredential = null;
        }
      })
      // Fetch services
      .addCase(fetchServices.fulfilled, (state, action) => {
        state.services = action.payload.services;
      })
      // Sync wallet
      .addCase(syncWallet.pending, (state) => {
        state.syncStatus = 'syncing';
      })
      .addCase(syncWallet.fulfilled, (state, action) => {
        state.syncStatus = 'success';
        state.lastSync = new Date().toISOString();
        // Update credentials from sync
        if (action.payload.credentials) {
          state.credentials = action.payload.credentials;
          state.totalCredentials = action.payload.credentials.length;
          state.verifiedCredentials = action.payload.credentials.filter(
            (c: Credential) => c.status === 'verified'
          ).length;
        }
      })
      .addCase(syncWallet.rejected, (state, action) => {
        state.syncStatus = 'error';
        state.error = action.payload as string;
      });
  },
});

export const {
  clearError,
  setSelectedCredential,
  toggleBackup,
  toggleEncryption,
  setSyncStatus,
  updateCredentialLocally,
} = walletSlice.actions;

export default walletSlice.reducer;