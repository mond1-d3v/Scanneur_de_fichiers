'use client';

import { useState, useEffect } from 'react';
import axios from 'axios';
import { format } from 'date-fns';
import { fr } from 'date-fns/locale';
import { useAuth } from '@/context/AuthContext';

interface ScanHistoryItem {
  id: string;
  file_name: string;
  file_size: number;
  file_type: string;
  scan_date: string;
  is_malicious: boolean;
  score: number;
  username?: string;
}

export default function HistoriquePage() {
  const [scanHistory, setScanHistory] = useState<ScanHistoryItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { isAuthenticated, user } = useAuth();

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        setIsLoading(true);
        const headers: Record<string, string> = {};
        if (isAuthenticated && user?.token) {
          headers['Authorization'] = `Bearer ${user.token}`;
        }
        
        const response = await axios.get(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000/api'}/history`, { headers });
        setScanHistory(response.data);
      } catch (err) {
        console.error('Erreur lors de la récupération de l\'historique:', err);
        setError('Impossible de charger l\'historique des analyses');
      } finally {
        setIsLoading(false);
      }
    };

    fetchHistory();
  }, [isAuthenticated, user]);

  const formatDate = (dateStr: string) => {
    try {
      const date = new Date(dateStr);
      return format(date, 'dd MMMM yyyy à HH:mm', { locale: fr });
    } catch (e) {
      return dateStr;
    }
  };

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(2)} KB`;
    return `${(bytes / 1048576).toFixed(2)} MB`;
  };

  return (
    <div className="max-w-6xl mx-auto">
      <h1 className="text-2xl font-bold my-6 text-center">
        {isAuthenticated ? 'Mon Historique de Scans' : 'Historique des Scans'}
      </h1>

      {isLoading ? (
        <div className="flex justify-center items-center h-64">
          <div className="animate-spin rounded-full h-16 w-16 border-t-2 border-b-2 border-blue-500"></div>
        </div>
      ) : scanHistory.length === 0 ? (
        <div className="bg-gray-800 rounded-lg p-6 text-center">
          <h2 className="text-xl text-gray-300">Aucun historique disponible</h2>
          <p className="text-gray-400 mt-2">
            {isAuthenticated 
              ? 'Vous n\'avez pas encore analysé de fichiers.' 
              : 'Aucun fichier n\'a encore été analysé.'}
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto bg-gray-800 rounded-lg shadow">
          <table className="min-w-full divide-y divide-gray-700">
            <thead className="bg-gray-700">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                  Fichier
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                  Type
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                  Taille
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                  Date d&apos;analyse
                </th>
                {!isAuthenticated && (
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                    Utilisateur
                  </th>
                )}
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                  Score
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                  Statut
                </th>
              </tr>
            </thead>
            <tbody className="bg-gray-800 divide-y divide-gray-700">
              {scanHistory.map((item) => (
                <tr key={item.id} className="hover:bg-gray-700">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm font-medium text-white">{item.file_name}</div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm text-gray-400">{item.file_type}</div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm text-gray-400">{formatFileSize(item.file_size)}</div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm text-gray-400">{formatDate(item.scan_date)}</div>
                  </td>
                  {!isAuthenticated && (
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm text-gray-400">{item.username || 'Anonyme'}</div>
                    </td>
                  )}
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className={`text-sm ${
                      item.score >= 7 ? 'text-red-400' : 
                      item.score >= 4 ? 'text-yellow-400' : 
                      'text-green-400'
                    } font-bold`}>
                      {typeof item.score === 'number' ? item.score : 0}/10
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                      item.is_malicious ? 'bg-red-900 text-red-200' : 'bg-green-900 text-green-200'
                    }`}>
                      {item.is_malicious ? 'Malveillant' : 'Sécurisé'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
