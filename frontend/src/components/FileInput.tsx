'use client';

import { useState, useRef } from 'react';
import DeleteButton from '@/components/DeleteButton';

interface FileInputProps {
  onFileSelect: (file: File) => void;
  onAnalyze: () => void;
  className?: string;
}

const FileInput = ({ onFileSelect, onAnalyze, className = "" }: FileInputProps) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      const file = files[0];
      setSelectedFile(file);
      onFileSelect(file);
    }
  };

  const clearFile = () => {
    setSelectedFile(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  return (
    <div className={`flex flex-col items-center ${className}`}>
      <div className="relative w-24 h-24 rounded-full border-2 border-[rgb(1,235,252)] flex justify-center items-center overflow-hidden 
                    shadow-[0px_0px_100px_rgb(1,235,252),inset_0px_0px_10px_rgb(1,235,252),0px_0px_5px_rgb(255,255,255)]
                    animate-flicker">
        <input
          ref={fileInputRef}
          type="file"
          onChange={handleFileChange}
          className="absolute opacity-0 w-full h-full cursor-pointer z-10"
        />
        <svg 
          xmlns="http://www.w3.org/2000/svg" 
          width="2em" 
          height="2em" 
          strokeLinejoin="round" 
          strokeLinecap="round" 
          viewBox="0 0 24 24" 
          strokeWidth={2} 
          fill="none" 
          stroke="currentColor" 
          className="text-[rgb(1,235,252)] text-2xl cursor-pointer animate-iconflicker"
        >
          <polyline points="16 16 12 12 8 16" />
          <line y2={21} x2={12} y1={12} x1={12} />
          <path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3" />
          <polyline points="16 16 12 12 8 16" />
        </svg>
      </div>
      {selectedFile && (
        <div className="mt-4 text-[rgb(1,235,252)] font-bold text-center">
          {selectedFile.name}
        </div>
      )}
      <div className="flex space-x-4 mt-4">
        <button
          onClick={onAnalyze}
          disabled={!selectedFile}
          className={`px-4 py-2 rounded-md transition-colors ${
            selectedFile 
              ? 'bg-[rgb(1,235,252)] text-black hover:bg-[rgb(0,210,230)]' 
              : 'bg-gray-600 text-gray-400 cursor-not-allowed'
          }`}
        >
          Lancer l&apos;analyse
        </button>

        {selectedFile && (
          <DeleteButton 
            onDelete={async () => {
              clearFile();
              return Promise.resolve();
            }}
          />
        )}
      </div>
    </div>
  );
};

export default FileInput;
