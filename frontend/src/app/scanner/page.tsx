'use client';

import { useState } from 'react';
import FileInput from '@/components/FileInput';
import { useAuth } from '@/context/AuthContext';
interface ScanResult {
  is_malicious: boolean;
  score: number;
  message: string;
  threats: Array<{
    type: string;
    name: string;
    description: string;
    severity: string;
  }>;
  scan_time?: number;
  file_name?: string;
  file_path?: string;
  scan_details?: Record<string, unknown>;
}

export default function ScannerPage() {
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const { isAuthenticated, user } = useAuth();

  const handleFileSelect = (file: File) => {
    setSelectedFile(file);
    setScanResult(null);
    setError(null);
  };

  const handleAnalyze = async () => {
    if (!selectedFile) return;
    
    setIsLoading(true);
    setError(null);
    setScanResult(null);

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      const headers: Record<string, string> = {};
      if (isAuthenticated && user?.token) {
        headers['Authorization'] = `Bearer ${user.token}`;
      }
      const response = await fetch('http://localhost:5000/api/scan', {
        method: 'POST',
        body: formData,
        headers,
      });

      if (!response.ok) {
        throw new Error(`Erreur: ${response.status} ${response.statusText}`);
      }

      const result = await response.json();
      setScanResult(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Une erreur est survenue');
      console.error('Erreur lors du scan:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleDeleteFile = async () => {
    return new Promise<void>((resolve) => {
      setSelectedFile(null);
      setScanResult(null);
      resolve();
    });
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'high':
        return 'text-red-600';
      case 'medium':
        return 'text-orange-500';
      case 'low':
        return 'text-yellow-500';
      default:
        return 'text-gray-600';
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 7) return 'text-red-600';
    if (score >= 4) return 'text-orange-500';
    return 'text-green-600';
  };

  return (
    <div className="max-w-4xl mx-auto">
      <h1 className="text-3xl font-bold mb-6 text-center">Scanner de Malware</h1>
      
      <div className="flex flex-col items-center justify-center bg-gray-800 p-8 rounded-lg shadow-md mb-8">
        <h2 className="text-xl font-semibold mb-6 text-white">Téléchargez un fichier à analyser</h2>
        <FileInput 
          onFileSelect={handleFileSelect}
          onAnalyze={handleAnalyze}
          className="mb-4"
        />
        
        <p className="text-sm text-gray-400 mt-4 text-center">
          Formats supportés: fichiers exécutables, scripts, documents et archives.<br/>
          Taille maximale: 50 MB.
        </p>
      </div>

      {isLoading && (
        <div className="text-center py-8">
          <div className="inline-block animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-600 mb-4"></div>
          <p className="text-white">Analyse en cours, veuillez patienter...</p>
        </div>
      )}

      {error && (
        <div className="bg-red-800 border border-red-400 text-white px-4 py-3 rounded mb-6">
          <strong className="font-bold">Erreur!</strong>
          <p>{error}</p>
        </div>
      )}

      {scanResult && (
        <div className={`bg-gray-800 p-6 rounded-lg shadow-md mb-6 border-l-4 ${
          scanResult.is_malicious ? 'border-red-500' : 'border-green-500'
        }`}>
          <h2 className="text-xl font-semibold mb-4 text-white">Résultat de l&apos;analyse</h2>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <div>
              <p className="font-medium text-gray-300">Fichier:</p>
              <p className="text-white">{scanResult.file_name || 'Inconnu'}</p>
            </div>
            <div>
              <p className="font-medium text-gray-300">Temps d&apos;analyse:</p>
              <p className="text-white">{scanResult.scan_time ? `${scanResult.scan_time.toFixed(2)} secondes` : 'Non disponible'}</p>
            </div>
            <div>
              <p className="font-medium text-gray-300">Statut:</p>
              <p className={scanResult.is_malicious ? 'text-red-400 font-bold' : 'text-green-400 font-bold'}>
                {scanResult.is_malicious ? 'Menace détectée' : 'Aucune menace détectée'}
              </p>
            </div>
            <div>
              <p className="font-medium text-gray-300">Score de risque:</p>
              <p className={`font-bold ${getScoreColor(scanResult.score)}`}>
                {scanResult.score}/10
              </p>
            </div>
          </div>
          
          <div className="mb-4">
            <p className="font-medium text-gray-300">Message:</p>
            <p className="text-white">{scanResult.message}</p>
          </div>
          
          {scanResult.threats && scanResult.threats.length > 0 && (
            <div>
              <h3 className="text-lg font-semibold mb-2 text-white">Menaces détectées:</h3>
              <div className="space-y-3">
                {scanResult.threats.map((threat, index) => (
                  <div key={index} className="border-l-2 border-red-400 pl-4 py-1">
                    <p className="font-medium text-white">{threat.name}</p>
                    <p className="text-sm text-gray-300">{threat.description}</p>
                    <p className={`text-sm ${getSeverityColor(threat.severity)} font-medium`}>
                      Sévérité: {threat.severity}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
