import React, { useState } from 'react';
import { ScanError } from '@/types/Admin';

interface ErrorsPanelProps {
  errors: ScanError[];
}

const ErrorsPanel: React.FC<ErrorsPanelProps> = ({ errors }) => {
  const [expandedErrors, setExpandedErrors] = useState<Set<string>>(new Set());
  
  const toggleErrorExpansion = (errorId: string) => {
    const newExpanded = new Set(expandedErrors);
    if (newExpanded.has(errorId)) {
      newExpanded.delete(errorId);
    } else {
      newExpanded.add(errorId);
    }
    setExpandedErrors(newExpanded);
  };

  return (
    <div>
      <h2 className="text-xl font-bold mb-6">Erreurs d&apos;analyse</h2>
      
      {errors.length === 0 ? (
        <div className="bg-gray-700 p-6 rounded-lg text-center text-gray-400">
          Aucune erreur d&apos;analyse à afficher.
        </div>
      ) : (
        <div className="space-y-4">
          {errors.map((error) => (
            <div 
              key={error.id} 
              className="bg-gray-700 rounded-lg overflow-hidden"
            >
              <div 
                className="p-4 flex justify-between items-center cursor-pointer hover:bg-gray-600"
                onClick={() => toggleErrorExpansion(error.id)}
              >
                <div>
                  <div className="font-semibold">{error.errorType}</div>
                  <div className="text-sm text-gray-400">
                    {new Date(error.timestamp).toLocaleString()} - {error.fileName}
                  </div>
                </div>
                <div>
                  <svg 
                    xmlns="http://www.w3.org/2000/svg" 
                    className={`h-5 w-5 transition-transform duration-200 ${expandedErrors.has(error.id) ? 'transform rotate-180' : ''}`} 
                    viewBox="0 0 20 20" 
                    fill="currentColor"
                  >
                    <path fillRule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clipRule="evenodd" />
                  </svg>
                </div>
              </div>
              
              {expandedErrors.has(error.id) && (
                <div className="p-4 border-t border-gray-600 bg-gray-800">
                  <div className="mb-4">
                    <div className="text-sm font-semibold text-gray-400 mb-1">Message d&apos;erreur :</div>
                    <div className="bg-gray-900 p-3 rounded overflow-auto text-sm font-mono">
                      {error.errorMessage}
                    </div>
                  </div>
                  
                  {error.stackTrace && (
                    <div>
                      <div className="text-sm font-semibold text-gray-400 mb-1">Stack trace :</div>
                      <pre className="bg-gray-900 p-3 rounded overflow-auto text-xs font-mono whitespace-pre-wrap">
                        {error.stackTrace}
                      </pre>
                    </div>
                  )}
                  
                  <div className="mt-4 grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="text-gray-400">ID d&apos;utilisateur :</span> {error.userId || 'Anonyme'}
                    </div>
                    <div>
                      <span className="text-gray-400">Adresse IP :</span> {error.ipAddress}
                    </div>
                    <div>
                      <span className="text-gray-400">User Agent :</span> {error.userAgent}
                    </div>
                    <div>
                      <span className="text-gray-400">Taille du fichier :</span> {error.fileSize}
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default ErrorsPanel;
