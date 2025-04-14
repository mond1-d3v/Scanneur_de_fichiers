import { ScanStats, ScanError, AdminUser } from '@/types/Admin';

const POCKETBASE_URL = 'http://IP_DE_POCKETBASE:8080';
const API_URL = 'http://localhost:5000/api';

class AdminService {
  async verifyAdminStatus(token: string): Promise<boolean> {
    try {
      const response = await fetch(`${POCKETBASE_URL}/api/collections/users/auth-refresh`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
        }
      });

      if (!response.ok) {
        throw new Error('Échec de la vérification du token');
      }
      const data = await response.json();
      return data.record && data.record.verified === true;
    } catch (error) {
      console.error('Erreur lors de la vérification du statut admin:', error);
      return false;
    }
  }

  async getScanStatistics(): Promise<ScanStats> {
    try {
      const response = await fetch(`${API_URL}/admin/statistics`, {
        headers: {
          'Authorization': `Bearer ${this.getToken()}`,
        }
      });

      if (!response.ok) {
        throw new Error('Échec de la récupération des statistiques');
      }

      return await response.json();
    } catch (error) {
      console.error('Erreur lors de la récupération des statistiques:', error);
      return {
        totalScans: 0,
        maliciousScans: 0,
        cleanScans: 0,
        totalUsers: 0,
        scansByDay: []
      };
    }
  }

  async getScanErrors(): Promise<ScanError[]> {
    try {
      const response = await fetch(`${API_URL}/admin/errors`, {
        headers: {
          'Authorization': `Bearer ${this.getToken()}`,
        }
      });

      if (!response.ok) {
        throw new Error('Échec de la récupération des erreurs');
      }

      return await response.json();
    } catch (error) {
      console.error('Erreur lors de la récupération des erreurs:', error);
      return [];
    }
  }

  async getUsers(): Promise<AdminUser[]> {
    try {
      const response = await fetch(`${POCKETBASE_URL}/api/collections/users/records?perPage=100`, {
        headers: {
          'Authorization': `Bearer ${this.getToken()}`,
        }
      });

      if (!response.ok) {
        throw new Error('Échec de la récupération des utilisateurs');
      }

      const data = await response.json();
      return data.items.map((item: any) => ({
        id: item.id,
        username: item.username,
        email: item.email,
        name: item.name || item.username,
        created: item.created,
        isVerified: item.verified || false,
        isAdmin: item.verified || false,
        isOnline: false, 
        lastLogin: item.lastLogin,
        avatarUrl: item.avatar ? `${POCKETBASE_URL}/api/files/users/${item.id}/${item.avatar}` : undefined,
        emailVerified: item.emailVerified || false,
        scanCount: 0, 
        malwareCount: 0, 
      }));
    } catch (error) {
      console.error('Erreur lors de la récupération des utilisateurs:', error);
      return [];
    }
  }

  async logoutUser(userId: string): Promise<void> {
    try {
      const response = await fetch(`${API_URL}/admin/logout-user/${userId}`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.getToken()}`,
          'Content-Type': 'application/json',
        }
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.message || 'Échec de la déconnexion de l\'utilisateur');
      }
    } catch (error) {
      console.error('Erreur lors de la déconnexion de l\'utilisateur:', error);
      throw error;
    }
  }

  async deleteUser(userId: string): Promise<void> {
    try {
      const response = await fetch(`${POCKETBASE_URL}/api/collections/users/records/${userId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${this.getToken()}`,
        }
      });

      if (!response.ok) {
        throw new Error('Échec de la suppression de l\'utilisateur');
      }
    } catch (error) {
      console.error('Erreur lors de la suppression de l\'utilisateur:', error);
      throw error;
    }
  }

  private getToken(): string {
    const userStr = localStorage.getItem('auth_user');
    if (!userStr) return '';
    
    try {
      const user = JSON.parse(userStr);
      return user.token || '';
    } catch {
      return '';
    }
  }
}

export default new AdminService();
