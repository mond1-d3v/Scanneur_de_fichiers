import React, { useState } from 'react';
import Image from 'next/image';
import { AdminUser } from '@/types/Admin';

interface UsersPanelProps {
  users: AdminUser[];
  searchQuery: string;
  onSearchUsers: (query: string) => void;
  onLogoutUser: (userId: string) => Promise<void>;
  onDeleteUser: (userId: string) => Promise<void>;
}

const UsersPanel: React.FC<UsersPanelProps> = ({ 
  users, 
  searchQuery, 
  onSearchUsers, 
  onLogoutUser, 
  onDeleteUser 
}) => {
  const [activeUserId, setActiveUserId] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  
  const handleLogoutUser = async (userId: string) => {
    setActionLoading(`logout-${userId}`);
    await onLogoutUser(userId);
    setActionLoading(null);
  };
  
  const handleDeleteUser = async (userId: string) => {
    setActionLoading(`delete-${userId}`);
    await onDeleteUser(userId);
    setActionLoading(null);
  };
  
  const toggleUserDetails = (userId: string) => {
    setActiveUserId(activeUserId === userId ? null : userId);
  };

  return (
    <div>
      <h2 className="text-xl font-bold mb-6">Gestion des utilisateurs</h2>
      
      <div className="mb-6">
        <input
          type="text"
          placeholder="Rechercher par nom, email ou nom d'utilisateur..."
          value={searchQuery}
          onChange={(e) => onSearchUsers(e.target.value)}
          className="w-full p-3 bg-gray-700 border border-gray-600 rounded-lg text-white focus:border-blue-500 focus:outline-none"
        />
      </div>
      
      <div className="mb-4 flex justify-between items-center">
        <div className="text-gray-400">
          {users.length} utilisateur{users.length !== 1 ? 's' : ''} trouvé{users.length !== 1 ? 's' : ''}
        </div>
        <div className="flex space-x-4">
          <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-purple-100 text-purple-800">
            Admin
          </span>
          <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">
            Vérifié
          </span>
          <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-yellow-100 text-yellow-800">
            Non vérifié
          </span>
        </div>
      </div>
      
      {users.length === 0 ? (
        <div className="bg-gray-700 p-6 rounded-lg text-center text-gray-400">
          {searchQuery 
            ? 'Aucun utilisateur trouvé pour cette recherche.' 
            : 'Aucun utilisateur enregistré.'}
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-600">
            <thead className="bg-gray-700">
              <tr>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Utilisateur
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Email
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Status
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Inscription
                </th>
                <th scope="col" className="relative px-6 py-3">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody className="bg-gray-800 divide-y divide-gray-700">
              {users.map((user) => (
                <React.Fragment key={user.id}>
                  <tr className="hover:bg-gray-700 cursor-pointer" onClick={() => toggleUserDetails(user.id)}>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <div className="flex-shrink-0 h-10 w-10 relative">
                          {user.avatarUrl ? (
                            <Image
                              src={user.avatarUrl}
                              alt={`Avatar de ${user.name}`}
                              className="h-10 w-10 rounded-full object-cover"
                              width={40}
                              height={40}
                            />
                          ) : (
                            <div className="h-10 w-10 rounded-full bg-gray-600 flex items-center justify-center">
                              <span className="text-lg font-medium text-white">
                                {user.name.charAt(0).toUpperCase()}
                              </span>
                            </div>
                          )}
                          {user.isOnline && (
                            <span className="absolute bottom-0 right-0 block h-2.5 w-2.5 rounded-full bg-green-400 ring-2 ring-gray-800"></span>
                          )}
                        </div>
                        <div className="ml-4">
                          <div className="text-sm font-medium text-white">
                            {user.name}
                          </div>
                          <div className="text-sm text-gray-400">
                            @{user.username}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm text-gray-300">{user.email}</div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                        user.isVerified 
                          ? 'bg-green-100 text-green-800' 
                          : 'bg-yellow-100 text-yellow-800'
                      }`}>
                        {user.isVerified ? 'Vérifié' : 'Non vérifié'}
                      </span>
                      {user.isAdmin && (
                        <span className="ml-2 px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-purple-100 text-purple-800">
                          Admin
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                      {new Date(user.created).toLocaleDateString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                      <div className="flex justify-end space-x-2">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleLogoutUser(user.id);
                          }}
                          disabled={actionLoading === `logout-${user.id}`}
                          className="text-blue-400 hover:text-blue-300 transition-colors"
                        >
                          {actionLoading === `logout-${user.id}` ? 'Déconnexion...' : 'Déconnecter'}
                        </button>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleDeleteUser(user.id);
                          }}
                          disabled={actionLoading === `delete-${user.id}`}
                          className="text-red-400 hover:text-red-300 transition-colors"
                        >
                          {actionLoading === `delete-${user.id}` ? 'Suppression...' : 'Supprimer'}
                        </button>
                      </div>
                    </td>
                  </tr>
                  
                  {activeUserId === user.id && (
                    <tr className="bg-gray-900">
                      <td colSpan={5} className="px-6 py-4">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                          <div>
                            <h4 className="text-sm font-semibold text-gray-400 mb-2">Informations détaillées</h4>
                            <div className="bg-gray-800 p-4 rounded">
                              <div className="mb-2">
                                <span className="text-gray-400 text-xs">ID: </span>
                                <span className="text-sm font-mono">{user.id}</span>
                              </div>
                              <div className="mb-2">
                                <span className="text-gray-400 text-xs">Dernière connexion: </span>
                                <span className="text-sm">{user.lastLogin ? new Date(user.lastLogin).toLocaleString() : 'Jamais'}</span>
                              </div>
                              <div className="mb-2">
                                <span className="text-gray-400 text-xs">Inscrit le: </span>
                                <span className="text-sm">{new Date(user.created).toLocaleString()}</span>
                              </div>
                              <div className="mb-2">
                                <span className="text-gray-400 text-xs">Email vérifié: </span>
                                <span className="text-sm">{user.emailVerified ? 'Oui' : 'Non'}</span>
                              </div>
                            </div>
                          </div>
                          
                          <div>
                            <h4 className="text-sm font-semibold text-gray-400 mb-2">Statistiques d&apos;utilisation</h4>
                            <div className="bg-gray-800 p-4 rounded">
                              <div className="mb-2">
                                <span className="text-gray-400 text-xs">Analyses effectuées: </span>
                                <span className="text-sm">{user.scanCount || 0}</span>
                              </div>
                              <div className="mb-2">
                                <span className="text-gray-400 text-xs">Malwares détectés: </span>
                                <span className="text-sm">{user.malwareCount || 0}</span>
                              </div>
                              <div className="mb-2">
                                <span className="text-gray-400 text-xs">Dernière analyse: </span>
                                <span className="text-sm">{user.lastScan ? new Date(user.lastScan).toLocaleString() : 'Jamais'}</span>
                              </div>
                            </div>
                          </div>
                        </div>
                        
                        <div className="mt-4 flex justify-end space-x-3">
                          {!user.isVerified && (
                            <button className="px-3 py-1 bg-green-600 text-white text-sm rounded hover:bg-green-700 transition-colors">
                              Vérifier l&apos;utilisateur
                            </button>
                          )}
                          {!user.isAdmin && (
                            <button className="px-3 py-1 bg-purple-600 text-white text-sm rounded hover:bg-purple-700 transition-colors">
                              Promouvoir comme admin
                            </button>
                          )}
                          {user.isAdmin && (
                            <button className="px-3 py-1 bg-gray-600 text-white text-sm rounded hover:bg-gray-700 transition-colors">
                              Révoquer droits admin
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default UsersPanel;
