import { User } from '@/types/User';

const API_URL = 'http://localhost:5000/api';
const POCKETBASE_URL = 'http://IP_DE_POCKETBASE:8080';

class AuthService {
  private tokenKey = 'auth_token';
  private userKey = 'auth_user';

  async register(userData: { username: string; email: string; password: string; passwordConfirm: string; name: string; avatar?: File }): Promise<User> {
    try {
      const formData = new FormData();
      formData.append('username', userData.username);
      formData.append('email', userData.email);
      formData.append('password', userData.password);
      formData.append('passwordConfirm', userData.password);
      formData.append('name', userData.name);
      
      if (userData.avatar) {
        formData.append('avatar', userData.avatar);
      }
      
      const response = await fetch(`${POCKETBASE_URL}/api/collections/users/records`, {
        method: 'POST',
        body: formData,
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        if (errorData.data) {
          const errorMessages = [];
          for (const field in errorData.data) {
            errorMessages.push(`${field}: ${errorData.data[field].message}`);
          }
          throw new Error(errorMessages.join(' | ') || 'Erreur de validation lors de l\'inscription');
        }
        
        throw new Error(errorData.message || 'Erreur lors de l\'inscription');
      }
      console.log("Inscription réussie, tentative de connexion automatique");
      return this.login(userData.username, userData.password);
    } catch (error) {
      console.error('Erreur d\'inscription:', error);
      throw error;
    }
  }

  async login(usernameOrEmail: string, password: string): Promise<User> {
    try {
      const response = await fetch(`${POCKETBASE_URL}/api/collections/users/auth-with-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          identity: usernameOrEmail,
          password,
        }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.message || 'Identifiants invalides');
      }

      const data = await response.json();
      
      const user: User = {
        id: data.record.id,
        username: data.record.username,
        email: data.record.email,
        name: data.record.name,
        avatarUrl: data.record.avatar ? `${POCKETBASE_URL}/api/files/users/${data.record.id}/${data.record.avatar}` : null,
        token: data.token,
        isAdmin: data.record.verified || false,
      };
      localStorage.setItem(this.tokenKey, data.token);
      localStorage.setItem(this.userKey, JSON.stringify(user));

      return user;
    } catch (error) {
      console.error('Erreur de connexion:', error);
      throw error;
    }
  }

  updateUser(userData: Partial<User>): User | null {
    const currentUser = this.getCurrentUser();
    if (!currentUser) return null;

    const updatedUser = { ...currentUser, ...userData };
    localStorage.setItem(this.userKey, JSON.stringify(updatedUser));
    
    return updatedUser;
  }

  logout(): void {
    localStorage.removeItem(this.tokenKey);
    localStorage.removeItem(this.userKey);
    window.location.href = '/';
  }

  getCurrentUser(): User | null {
    const userStr = localStorage.getItem(this.userKey);
    if (!userStr) return null;
    
    try {
      return JSON.parse(userStr);
    } catch {
      return null;
    }
  }

  isAuthenticated(): boolean {
    return !!this.getToken() && !!this.getCurrentUser();
  }

  getToken(): string | null {
    return localStorage.getItem(this.tokenKey);
  }

  async updateProfile(userData: { name?: string; email?: string; avatar?: File; currentPassword?: string; password?: string; passwordConfirm?: string }): Promise<User> {
    try {
      const user = this.getCurrentUser();
      if (!user) throw new Error('Non connecté');

      const formData = new FormData();
      
      if (userData.name) formData.append('name', userData.name);
      if (userData.email) formData.append('email', userData.email);
      if (userData.avatar) formData.append('avatar', userData.avatar);
      if (userData.password) {
        formData.append('password', userData.password);
        formData.append('passwordConfirm', userData.passwordConfirm || '');
        formData.append('oldPassword', userData.currentPassword || '');
      }
      
      const response = await fetch(`${POCKETBASE_URL}/api/collections/users/records/${user.id}`, {
        method: 'PATCH',
        headers: {
          'Authorization': `Bearer ${this.getToken()}`,
        },
        body: formData,
      });
      
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.message || 'Erreur lors de la mise à jour du profil');
      }
      
      const data = await response.json();
      const updatedUser: User = {
        ...user,
        name: data.name || user.name,
        email: data.email || user.email,
        avatarUrl: data.avatar ? `${POCKETBASE_URL}/api/files/users/${data.id}/${data.avatar}` : user.avatarUrl,
      };
      
      localStorage.setItem(this.userKey, JSON.stringify(updatedUser));
      
      return updatedUser;
    } catch (error) {
      console.error('Erreur lors de la mise à jour du profil:', error);
      throw error;
    }
  }

  async checkAdminStatus(): Promise<boolean> {
    const user = this.getCurrentUser();
    if (!user) return false;
    
    try {
      const response = await fetch(`${POCKETBASE_URL}/api/collections/users/auth-refresh`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${user.token}`,
        }
      });

      if (!response.ok) return false;

      const data = await response.json();
      
      const isAdmin = data.record && data.record.verified === true;
      
      if (isAdmin !== user.isAdmin) {
        this.updateUser({ isAdmin });
      }
      
      return isAdmin;
    } catch (error) {
      console.error('Erreur lors de la vérification du statut admin:', error);
      return false;
    }
  }
}

export default new AuthService();
