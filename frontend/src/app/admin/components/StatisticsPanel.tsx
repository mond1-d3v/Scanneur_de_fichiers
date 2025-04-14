import React from 'react';
import { ScanStats } from '@/types/Admin';

interface StatisticsPanelProps {
  stats: ScanStats;
}

const StatisticsPanel: React.FC<StatisticsPanelProps> = ({ stats }) => {
  const maliciousPercentage = stats.totalScans > 0 
    ? Math.round((stats.maliciousScans / stats.totalScans) * 100) 
    : 0;

  return (
    <div>
      <h2 className="text-xl font-bold mb-6">Statistiques des analyses</h2>
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="bg-gray-700 rounded-lg p-6 shadow">
          <div className="text-4xl font-bold text-blue-400">{stats.totalScans}</div>
          <div className="text-gray-400 mt-2">Analyses totales</div>
        </div>
        
        <div className="bg-gray-700 rounded-lg p-6 shadow">
          <div className="text-4xl font-bold text-green-400">{stats.cleanScans}</div>
          <div className="text-gray-400 mt-2">Fichiers sains</div>
        </div>
        
        <div className="bg-gray-700 rounded-lg p-6 shadow">
          <div className="text-4xl font-bold text-red-400">{stats.maliciousScans}</div>
          <div className="text-gray-400 mt-2">Fichiers malveillants</div>
        </div>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
        <div className="bg-gray-700 rounded-lg p-6 shadow">
          <h3 className="text-lg font-semibold mb-4">Taux de détection</h3>
          <div className="h-8 bg-gray-600 rounded-full overflow-hidden">
            <div 
              className="h-full bg-red-600 rounded-full"
              style={{ width: `${maliciousPercentage}%` }}
            ></div>
          </div>
          <div className="mt-2 text-center">
            {maliciousPercentage}% des fichiers analysés étaient malveillants
          </div>
        </div>
        
        <div className="bg-gray-700 rounded-lg p-6 shadow">
          <h3 className="text-lg font-semibold mb-4">Utilisateurs actifs</h3>
          <div className="text-4xl font-bold text-purple-400 text-center">{stats.totalUsers}</div>
          <div className="text-gray-400 mt-2 text-center">Utilisateurs enregistrés</div>
        </div>
      </div>
      
      {stats.scansByDay.length > 0 && (
        <div className="bg-gray-700 rounded-lg p-6 shadow">
          <h3 className="text-lg font-semibold mb-4">Analyses par jour (7 derniers jours)</h3>
          <div className="h-64 flex items-end space-x-2">
            {stats.scansByDay.map((day, index) => (
              <div key={index} className="flex-1 flex flex-col items-center">
                <div className="w-full bg-blue-600 rounded-t-md" style={{ height: `${(day.count / Math.max(...stats.scansByDay.map(d => d.count))) * 100}%` }}></div>
                <div className="text-xs mt-2 text-gray-400">{day.date}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default StatisticsPanel;
