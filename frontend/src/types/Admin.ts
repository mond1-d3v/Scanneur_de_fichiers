export interface ScanStats {
  totalScans: number;
  maliciousScans: number;
  cleanScans: number;
  totalUsers: number;
  scansByDay: {
    date: string;
    count: number;
  }[];
}

export interface ScanError {
  id: string;
  errorType: string;
  errorMessage: string;
  timestamp: string;
  fileName: string;
  fileSize?: string;
  userId?: string;
  ipAddress: string;
  userAgent: string;
  stackTrace?: string;
}

export interface AdminUser {
  id: string;
  username: string;
  email: string;
  name: string;
  created: string;
  isVerified: boolean;
  isAdmin: boolean;
  isOnline: boolean;
  lastLogin?: string;
  avatarUrl?: string;
  emailVerified: boolean;
  scanCount?: number;
  malwareCount?: number;
  lastScan?: string;
}
