'use client';

import Link from 'next/link';
import Image from 'next/image';
import { usePathname } from 'next/navigation';
import { useEffect, useState } from 'react';
import UserAvatar from './UserAvatar';
import { useAuth } from '@/context/AuthContext';
import authService from '@/services/authService';

const Navbar = () => {
  const pathname = usePathname();
  const { isAuthenticated } = useAuth();
  const [isAdmin, setIsAdmin] = useState(false);

  useEffect(() => {
    const checkAdminStatus = async () => {
      if (isAuthenticated) {
        const user = authService.getCurrentUser();
        if (user?.isAdmin) {
          setIsAdmin(true);
        } else {
          const isAdmin = await authService.checkAdminStatus();
          setIsAdmin(isAdmin);
        }
      }
    };
    
    checkAdminStatus();
  }, [isAuthenticated]);

  const isActive = (path: string) => {
    return pathname === path ? 'bg-gray-700 text-white' : 'text-gray-300';
  };

  return (
    <nav className="bg-[rgb(10,10,10)] p-6 shadow-sm">
      <div className="container mx-auto flex items-center px-4">
        <div className="mr-auto">
          <Link href="/" className="flex items-center">
            <Image 
              src="/logo.png" 
              alt="Scanner de Malware" 
              width={82} 
              height={82} 
              className="mr-4"
            />
          </Link>
        </div>
        <div className="flex space-x-6 justify-center mx-auto">
          <Link href="/" className={`px-3 py-2 rounded hover:bg-gray-800 transition-colors duration-200 ${isActive('/')}`}>
            Accueil
          </Link>
          <Link href="/scanner" className={`px-3 py-2 rounded hover:bg-gray-800 transition-colors duration-200 ${isActive('/scanner')}`}>
            Scanner
          </Link>
          <Link href="/historique" className={`px-3 py-2 rounded hover:bg-gray-800 transition-colors duration-200 ${isActive('/historique')}`}>
            {isAuthenticated ? 'Mes Scans' : 'Historique'}
          </Link>
          <Link href="/a-propos" className={`px-3 py-2 rounded hover:bg-gray-800 transition-colors duration-200 ${isActive('/a-propos')}`}>
            À Propos
          </Link>
          {isAdmin && (
            <Link href="/admin" className={`px-3 py-2 rounded hover:bg-gray-800 transition-colors duration-200 ${isActive('/admin')}`}>
              Admin
            </Link>
          )}
        </div>
        <div className="ml-auto">
          {isAuthenticated ? (
            <UserAvatar />
          ) : (
            <Link 
              href="/connexion" 
              className="px-4 py-2 rounded bg-gray-700 hover:bg-gray-800 text-white transition-colors duration-200"
            >
              Connexion
            </Link>
          )}
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
