import { createSlice, PayloadAction } from '@reduxjs/toolkit';

// Types
export type ThemeMode = 'light' | 'dark' | 'system';
export type ColorScheme = 'default' | 'government' | 'accessible' | 'high-contrast';

export interface ThemeState {
  mode: ThemeMode;
  colorScheme: ColorScheme;
  primaryColor: string;
  secondaryColor: string;
  fontSize: 'small' | 'medium' | 'large';
  fontFamily: 'default' | 'dyslexic-friendly' | 'high-contrast';
  reducedMotion: boolean;
  highContrast: boolean;
  systemDarkMode: boolean;
  customization: {
    borderRadius: number;
    spacing: number;
    density: 'comfortable' | 'compact' | 'spacious';
  };
  accessibility: {
    screenReaderMode: boolean;
    keyboardNavigation: boolean;
    focusVisible: boolean;
    announcements: boolean;
  };
}

// Initial state
const initialState: ThemeState = {
  mode: 'system',
  colorScheme: 'government',
  primaryColor: '#1976d2',
  secondaryColor: '#dc004e',
  fontSize: 'medium',
  fontFamily: 'default',
  reducedMotion: false,
  highContrast: false,
  systemDarkMode: false,
  customization: {
    borderRadius: 4,
    spacing: 8,
    density: 'comfortable',
  },
  accessibility: {
    screenReaderMode: false,
    keyboardNavigation: true,
    focusVisible: true,
    announcements: true,
  },
};

// Theme slice
const themeSlice = createSlice({
  name: 'theme',
  initialState,
  reducers: {
    setThemeMode: (state, action: PayloadAction<ThemeMode>) => {
      state.mode = action.payload;
    },
    
    setColorScheme: (state, action: PayloadAction<ColorScheme>) => {
      state.colorScheme = action.payload;
      
      // Update colors based on scheme
      switch (action.payload) {
        case 'government':
          state.primaryColor = '#1976d2';
          state.secondaryColor = '#dc004e';
          break;
        case 'accessible':
          state.primaryColor = '#0066cc';
          state.secondaryColor = '#cc0000';
          break;
        case 'high-contrast':
          state.primaryColor = '#000000';
          state.secondaryColor = '#ffffff';
          state.highContrast = true;
          break;
        default:
          state.primaryColor = '#1976d2';
          state.secondaryColor = '#dc004e';
          break;
      }
    },
    
    setPrimaryColor: (state, action: PayloadAction<string>) => {
      state.primaryColor = action.payload;
      // Reset to custom if user manually changes colors
      if (state.colorScheme !== 'default') {
        state.colorScheme = 'default';
      }
    },
    
    setSecondaryColor: (state, action: PayloadAction<string>) => {
      state.secondaryColor = action.payload;
      // Reset to custom if user manually changes colors
      if (state.colorScheme !== 'default') {
        state.colorScheme = 'default';
      }
    },
    
    setFontSize: (state, action: PayloadAction<ThemeState['fontSize']>) => {
      state.fontSize = action.payload;
    },
    
    setFontFamily: (state, action: PayloadAction<ThemeState['fontFamily']>) => {
      state.fontFamily = action.payload;
    },
    
    toggleReducedMotion: (state) => {
      state.reducedMotion = !state.reducedMotion;
    },
    
    setReducedMotion: (state, action: PayloadAction<boolean>) => {
      state.reducedMotion = action.payload;
    },
    
    toggleHighContrast: (state) => {
      state.highContrast = !state.highContrast;
      if (state.highContrast) {
        state.colorScheme = 'high-contrast';
      }
    },
    
    setHighContrast: (state, action: PayloadAction<boolean>) => {
      state.highContrast = action.payload;
      if (action.payload) {
        state.colorScheme = 'high-contrast';
      }
    },
    
    setSystemDarkMode: (state, action: PayloadAction<boolean>) => {
      state.systemDarkMode = action.payload;
    },
    
    updateCustomization: (state, action: PayloadAction<Partial<ThemeState['customization']>>) => {
      state.customization = { ...state.customization, ...action.payload };
    },
    
    setBorderRadius: (state, action: PayloadAction<number>) => {
      state.customization.borderRadius = action.payload;
    },
    
    setSpacing: (state, action: PayloadAction<number>) => {
      state.customization.spacing = action.payload;
    },
    
    setDensity: (state, action: PayloadAction<ThemeState['customization']['density']>) => {
      state.customization.density = action.payload;
    },
    
    updateAccessibilitySettings: (state, action: PayloadAction<Partial<ThemeState['accessibility']>>) => {
      state.accessibility = { ...state.accessibility, ...action.payload };
    },
    
    toggleScreenReaderMode: (state) => {
      state.accessibility.screenReaderMode = !state.accessibility.screenReaderMode;
    },
    
    toggleKeyboardNavigation: (state) => {
      state.accessibility.keyboardNavigation = !state.accessibility.keyboardNavigation;
    },
    
    toggleFocusVisible: (state) => {
      state.accessibility.focusVisible = !state.accessibility.focusVisible;
    },
    
    toggleAnnouncements: (state) => {
      state.accessibility.announcements = !state.accessibility.announcements;
    },
    
    // Preset themes
    applyLightTheme: (state) => {
      state.mode = 'light';
      state.colorScheme = 'government';
      state.primaryColor = '#1976d2';
      state.secondaryColor = '#dc004e';
      state.highContrast = false;
    },
    
    applyDarkTheme: (state) => {
      state.mode = 'dark';
      state.colorScheme = 'government';
      state.primaryColor = '#90caf9';
      state.secondaryColor = '#f48fb1';
      state.highContrast = false;
    },
    
    applyHighContrastTheme: (state) => {
      state.mode = 'light';
      state.colorScheme = 'high-contrast';
      state.primaryColor = '#000000';
      state.secondaryColor = '#ffffff';
      state.highContrast = true;
      state.fontFamily = 'high-contrast';
      state.fontSize = 'large';
    },
    
    applyAccessibleTheme: (state) => {
      state.colorScheme = 'accessible';
      state.primaryColor = '#0066cc';
      state.secondaryColor = '#cc0000';
      state.fontSize = 'large';
      state.fontFamily = 'dyslexic-friendly';
      state.customization.density = 'spacious';
      state.accessibility.screenReaderMode = true;
      state.accessibility.focusVisible = true;
      state.accessibility.announcements = true;
    },
    
    resetTheme: () => {
      return initialState;
    },
  },
});

export const {
  setThemeMode,
  setColorScheme,
  setPrimaryColor,
  setSecondaryColor,
  setFontSize,
  setFontFamily,
  toggleReducedMotion,
  setReducedMotion,
  toggleHighContrast,
  setHighContrast,
  setSystemDarkMode,
  updateCustomization,
  setBorderRadius,
  setSpacing,
  setDensity,
  updateAccessibilitySettings,
  toggleScreenReaderMode,
  toggleKeyboardNavigation,
  toggleFocusVisible,
  toggleAnnouncements,
  applyLightTheme,
  applyDarkTheme,
  applyHighContrastTheme,
  applyAccessibleTheme,
  resetTheme,
} = themeSlice.actions;

export default themeSlice.reducer;