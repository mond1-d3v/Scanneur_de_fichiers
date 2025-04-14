'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import authService from '@/services/authService';
import adminService from '@/services/adminService';
import { User } from '@/types/User';
import { ScanStats, ScanError, AdminUser } from '@/types/Admin';
import StatisticsPanel from './components/StatisticsPanel';
import ErrorsPanel from './components/ErrorsPanel';
import UsersPanel from './components/UsersPanel';
export default function AdminPage() {
  const router = useRouter();
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [isAdmin, setIsAdmin] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('stats');
  const [scanStats, setScanStats] = useState<ScanStats>({
    totalScans: 0,
    maliciousScans: 0,
    cleanScans: 0,
    totalUsers: 0,
    scansByDay: [],
  });
  const [scanErrors, setScanErrors] = useState<ScanError[]>([]);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [userSearchQuery, setUserSearchQuery] = useState('');
  const [errorMessage, setErrorMessage] = useState('');

  useEffect(() => {
    const checkAdminAccess = async () => {
      try {
        const user = authService.getCurrentUser();
        
        if (!user) {
          router.push('/connexion');
          return;
        }
        setCurrentUser(user);
        const isAdminUser = await adminService.verifyAdminStatus(user.token);
        setIsAdmin(isAdminUser);
        
        if (!isAdminUser) {
          router.push('/');
          return;
        }
        await loadData();
        setIsLoading(false);
      } catch (error) {
        console.error('Erreur lors de la vérification des droits admin:', error);
        router.push('/');
      }
    };
    checkAdminAccess();
  }, [router]);
  
  const loadData = async () => {
    try {
      setIsLoading(true);
      const stats = await adminService.getScanStatistics();
      setScanStats(stats);
      const errors = await adminService.getScanErrors();
      setScanErrors(errors);
      const usersList = await adminService.getUsers();
      setUsers(usersList);
      
      setIsLoading(false);
    } catch (error: any) {
      setErrorMessage(error.message || 'Erreur lors du chargement des données');
      setIsLoading(false);
    }
  };
  const handleLogoutUser = async (userId: string) => {
    try {
      await adminService.logoutUser(userId);
      const updatedUsers = await adminService.getUsers();
      setUsers(updatedUsers);
    } catch (error: any) {
      setErrorMessage(error.message || 'Erreur lors de la déconnexion de l\'utilisateur');
    }
  };
  
  const handleDeleteUser = async (userId: string) => {
    if (window.confirm('Êtes-vous sûr de vouloir supprimer cet utilisateur ? Cette action est irréversible.')) {
      try {
        await adminService.deleteUser(userId);s
        const updatedUsers = await adminService.getUsers();
        setUsers(updatedUsers);
      } catch (error: any) {
        setErrorMessage(error.message || 'Erreur lors de la suppression de l\'utilisateur');
      }
    }
  };
  
  const handleSearchUsers = (query: string) => {
    setUserSearchQuery(query);
  };
  
  const filteredUsers = users.filter(user => 
    user.username.toLowerCase().includes(userSearchQuery.toLowerCase()) ||
    user.email.toLowerCase().includes(userSearchQuery.toLowerCase()) ||
    user.name.toLowerCase().includes(userSearchQuery.toLowerCase())
  );
  
  if (isLoading) {
    return (
      <div className="min-h-screen flex justify-center items-center bg-gray-900">
        <div className="animate-spin rounded-full h-16 w-16 border-t-2 border-b-2 border-blue-500"></div>
      </div>
    );
  }
  
  if (!isAdmin) {
    return (
      <div className="min-h-screen flex justify-center items-center bg-gray-900">
        <div className="bg-red-600 text-white p-8 rounded-lg shadow-lg">
          <h1 className="text-2xl font-bold mb-4">Accès refusé</h1>
          <p>Vous n&pos;avez pas les droits d&pos;administration requis.</p>
          <button 
            onClick={() => router.push('/')}
            className="mt-6 px-4 py-2 bg-white text-red-600 rounded hover:bg-gray-100 transition-colors"
          >
            Retour à l&pos;accueil
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      <div className="max-w-7xl mx-auto px-4 py-8">
        <div className="flex flex-wrap items-center justify-between mb-8">
          <h1 className="text-3xl font-bold">Panneau d&pos;Administration</h1>
          <div className="text-sm text-gray-400">
            Connecté en tant que: <span className="font-medium text-blue-400">{currentUser?.name} (Admin)</span>
          </div>
        </div>
        
        {errorMessage && (
          <div className="bg-red-600 text-white p-4 rounded-lg mb-6">
            {errorMessage}
            <button 
              className="ml-4 underline"
              onClick={() => setErrorMessage('')}
            >
              Fermer
            </button>
          </div>
        )}

        {/* Navigation des onglets */}
        <div className="border-b border-gray-700 mb-6">
          <nav className="flex space-x-4">
            <button
              className={`px-4 py-2 font-medium ${activeTab === 'stats' ? 'text-blue-500 border-b-2 border-blue-500' : 'text-gray-400 hover:text-white'}`}
              onClick={() => setActiveTab('stats')}
            >
              Statistiques
            </button>
            <button
              className={`px-4 py-2 font-medium ${activeTab === 'errors' ? 'text-blue-500 border-b-2 border-blue-500' : 'text-gray-400 hover:text-white'}`}
              onClick={() => setActiveTab('errors')}
            >
              Erreurs d&pos;analyse
            </button>
            <button
              className={`px-4 py-2 font-medium ${activeTab === 'users' ? 'text-blue-500 border-b-2 border-blue-500' : 'text-gray-400 hover:text-white'}`}
              onClick={() => setActiveTab('users')}
            >
              Gestion des utilisateurs
            </button>
          </nav>
        </div>
        <div className="bg-gray-800 rounded-lg shadow-lg p-6">
          {activeTab === 'stats' && (
            <StatisticsPanel stats={scanStats} />
          )}
          
          {activeTab === 'errors' && (
            <ErrorsPanel errors={scanErrors} />
          )}
          
          {activeTab === 'users' && (
            <UsersPanel 
              users={filteredUsers} 
              onSearchUsers={handleSearchUsers} 
              onLogoutUser={handleLogoutUser} 
              onDeleteUser={handleDeleteUser}
              searchQuery={userSearchQuery}
            />
          )}
        </div>
      </div>
    </div>
  );
}
