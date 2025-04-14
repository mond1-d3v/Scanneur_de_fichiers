'use client';

import { useState } from 'react';

interface DeleteButtonProps {
  onDelete: () => Promise<void>;
  className?: string;
}

const DeleteButton = ({ onDelete, className = '' }: DeleteButtonProps) => {
  const [isDeleting, setIsDeleting] = useState(false);

  const handleDelete = async () => {
    setIsDeleting(true);
    try {
      await onDelete();
    } catch (error) {
      console.error('Erreur lors de la suppression:', error);
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <div className={`${className}`}>
      <button 
        onClick={handleDelete}
        disabled={isDeleting}
        className="w-[50px] h-[50px] rounded-full bg-[rgb(20,20,20)] border-none font-semibold flex items-center justify-center shadow-[0px_0px_20px_rgba(0,0,0,0.164)] cursor-pointer transition-all duration-300 overflow-hidden relative hover:w-[140px] hover:rounded-[50px] hover:bg-[rgb(255,69,69)] hover:items-center group"
      >
        <svg 
          viewBox="0 0 448 512" 
          className="w-3 transition-all duration-300 group-hover:w-[50px] group-hover:translate-y-[60%]"
          fill="white"
        >
          <path d="M135.2 17.7L128 32H32C14.3 32 0 46.3 0 64S14.3 96 32 96H416c17.7 0 32-14.3 32-32s-14.3-32-32-32H320l-7.2-14.3C307.4 6.8 296.3 0 284.2 0H163.8c-12.1 0-23.2 6.8-28.6 17.7zM416 128H32L53.2 467c1.6 25.3 22.6 45 47.9 45H346.9c25.3 0 46.3-19.7 47.9-45L416 128z" />
        </svg>
        
        <span className="absolute top-[-20px] text-white transition-all duration-300 text-[2px] group-hover:text-[13px] group-hover:opacity-100 group-hover:translate-y-[30px]">
          Delete
        </span>
      </button>
    </div>
  );
};

export default DeleteButton;
