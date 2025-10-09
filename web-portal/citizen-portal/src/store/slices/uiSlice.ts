import { createSlice, PayloadAction } from '@reduxjs/toolkit';

// Types
export interface UIState {
  sidebarOpen: boolean;
  loading: {
    global: boolean;
    components: Record<string, boolean>;
  };
  modal: {
    isOpen: boolean;
    type: string | null;
    data: any;
  };
  drawer: {
    isOpen: boolean;
    content: string | null;
  };
  breadcrumbs: Array<{
    label: string;
    href?: string;
  }>;
  searchQuery: string;
  filters: Record<string, any>;
  pagination: {
    page: number;
    pageSize: number;
    total: number;
  };
  viewMode: 'grid' | 'list';
  sortBy: string;
  sortOrder: 'asc' | 'desc';
}

// Initial state
const initialState: UIState = {
  sidebarOpen: true,
  loading: {
    global: false,
    components: {},
  },
  modal: {
    isOpen: false,
    type: null,
    data: null,
  },
  drawer: {
    isOpen: false,
    content: null,
  },
  breadcrumbs: [],
  searchQuery: '',
  filters: {},
  pagination: {
    page: 1,
    pageSize: 10,
    total: 0,
  },
  viewMode: 'grid',
  sortBy: 'createdAt',
  sortOrder: 'desc',
};

// UI slice
const uiSlice = createSlice({
  name: 'ui',
  initialState,
  reducers: {
    toggleSidebar: (state) => {
      state.sidebarOpen = !state.sidebarOpen;
    },
    setSidebarOpen: (state, action: PayloadAction<boolean>) => {
      state.sidebarOpen = action.payload;
    },
    setGlobalLoading: (state, action: PayloadAction<boolean>) => {
      state.loading.global = action.payload;
    },
    setComponentLoading: (state, action: PayloadAction<{ component: string; loading: boolean }>) => {
      const { component, loading } = action.payload;
      state.loading.components[component] = loading;
    },
    openModal: (state, action: PayloadAction<{ type: string; data?: any }>) => {
      const { type, data } = action.payload;
      state.modal.isOpen = true;
      state.modal.type = type;
      state.modal.data = data || null;
    },
    closeModal: (state) => {
      state.modal.isOpen = false;
      state.modal.type = null;
      state.modal.data = null;
    },
    openDrawer: (state, action: PayloadAction<string>) => {
      state.drawer.isOpen = true;
      state.drawer.content = action.payload;
    },
    closeDrawer: (state) => {
      state.drawer.isOpen = false;
      state.drawer.content = null;
    },
    setBreadcrumbs: (state, action: PayloadAction<UIState['breadcrumbs']>) => {
      state.breadcrumbs = action.payload;
    },
    addBreadcrumb: (state, action: PayloadAction<{ label: string; href?: string }>) => {
      state.breadcrumbs.push(action.payload);
    },
    removeBreadcrumb: (state, action: PayloadAction<number>) => {
      state.breadcrumbs.splice(action.payload, 1);
    },
    setSearchQuery: (state, action: PayloadAction<string>) => {
      state.searchQuery = action.payload;
    },
    setFilters: (state, action: PayloadAction<Record<string, any>>) => {
      state.filters = action.payload;
    },
    updateFilter: (state, action: PayloadAction<{ key: string; value: any }>) => {
      const { key, value } = action.payload;
      state.filters[key] = value;
    },
    clearFilters: (state) => {
      state.filters = {};
    },
    setPagination: (state, action: PayloadAction<Partial<UIState['pagination']>>) => {
      state.pagination = { ...state.pagination, ...action.payload };
    },
    setViewMode: (state, action: PayloadAction<'grid' | 'list'>) => {
      state.viewMode = action.payload;
    },
    setSortBy: (state, action: PayloadAction<string>) => {
      state.sortBy = action.payload;
    },
    setSortOrder: (state, action: PayloadAction<'asc' | 'desc'>) => {
      state.sortOrder = action.payload;
    },
    toggleSortOrder: (state) => {
      state.sortOrder = state.sortOrder === 'asc' ? 'desc' : 'asc';
    },
    resetUI: (state) => {
      return {
        ...initialState,
        sidebarOpen: state.sidebarOpen, // Preserve sidebar state
      };
    },
  },
});

export const {
  toggleSidebar,
  setSidebarOpen,
  setGlobalLoading,
  setComponentLoading,
  openModal,
  closeModal,
  openDrawer,
  closeDrawer,
  setBreadcrumbs,
  addBreadcrumb,
  removeBreadcrumb,
  setSearchQuery,
  setFilters,
  updateFilter,
  clearFilters,
  setPagination,
  setViewMode,
  setSortBy,
  setSortOrder,
  toggleSortOrder,
  resetUI,
} = uiSlice.actions;

export default uiSlice.reducer;