'use client';

import Image from 'next/image';
import { useState, useRef, useEffect } from 'react';
import Link from 'next/link';
import authService from '@/services/authService';

interface UserAvatarProps {
  size?: number;
  showMenu?: boolean;
}
const UserAvatar = ({ size = 40, showMenu = true }: UserAvatarProps) => {
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const user = authService.getCurrentUser();
  
  const toggleMenu = () => {
    setMenuOpen(!menuOpen);
  };

  const handleLogout = () => {
    authService.logout();
  };

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setMenuOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  if (!user) return null;

  return (
    <div className="relative" ref={menuRef}>
      <button 
        className="rounded-full overflow-hidden focus:outline-none focus:ring-2 focus:ring-blue-500"
        onClick={toggleMenu}
      >
        {user.avatarUrl ? (
          <Image 
            src={user.avatarUrl} 
            alt={`Avatar de ${user.name}`} 
            width={size} 
            height={size} 
            className="rounded-full object-cover"
          />
        ) : (
          <div 
            className="bg-gray-700 text-white flex items-center justify-center rounded-full font-semibold"
            style={{ width: `${size}px`, height: `${size}px` }}
          >
            {user.name.charAt(0).toUpperCase()}
          </div>
        )}
      </button>

      {showMenu && menuOpen && (
        <div className="absolute right-0 mt-2 w-48 bg-gray-800 rounded-md shadow-lg py-1 z-10">
          <div className="px-4 py-2 text-sm text-white border-b border-gray-700">
            <div className="font-medium">{user.name}</div>
            <div className="text-gray-400 text-xs truncate">{user.email}</div>
          </div>
          <Link href="/mon-compte" className="block px-4 py-2 text-sm text-white hover:bg-gray-700 w-full text-left">
            Mon Compte
          </Link>
          <button
            onClick={handleLogout}
            className="block w-full text-left px-4 py-2 text-sm text-white hover:bg-gray-700"
          >
            Déconnexion
          </button>
        </div>
      )}
    </div>
  );
};

export default UserAvatar;
