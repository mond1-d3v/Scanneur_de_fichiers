'use client';

import React, { createContext, useContext, useState, useEffect } from 'react';
import authService from '@/services/authService';
import { User } from '@/types/User';

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isAdmin: boolean;
  isLoading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  updateUser: (userData: Partial<User>) => User | null;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  isAuthenticated: false,
  isAdmin: false,
  isLoading: true,
  login: async () => {},
  logout: () => {},
  updateUser: () => null,
});

export const useAuth = () => useContext(AuthContext);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isAdmin, setIsAdmin] = useState(false);

  useEffect(() => {
    const currentUser = authService.getCurrentUser();
    setUser(currentUser);
    const checkAdmin = async () => {
      if (currentUser) {
        if (currentUser.isAdmin) {
          setIsAdmin(true);
        } else {
          const adminStatus = await authService.checkAdminStatus();
          setIsAdmin(adminStatus);
        }
      }
    };
    
    checkAdmin();
    setIsLoading(false);
  }, []);

  const login = async (username: string, password: string) => {
    try {
      const loggedInUser = await authService.login(username, password);
      setUser(loggedInUser);
      setIsAdmin(loggedInUser.isAdmin || false);
    } catch (error) {
      throw error;
    }
  };

  const logout = () => {
    authService.logout();
    setUser(null);
    setIsAdmin(false);
  };

  const updateUser = (userData: Partial<User>) => {
    const updatedUser = authService.updateUser(userData);
    setUser(updatedUser);
    if (userData.isAdmin !== undefined) {
      setIsAdmin(userData.isAdmin);
    }
    return updatedUser;
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isAdmin,
        isLoading,
        login,
        logout,
        updateUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};
