'use client';

import { useState, useEffect, useRef, ChangeEvent } from 'react';
import { useRouter } from 'next/navigation';
import Image from 'next/image';
import authService from '@/services/authService';
import { User } from '@/types/User';

export default function MonComptePage() {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState({ text: '', type: '' });
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    currentPassword: '',
    password: '',
    passwordConfirm: '',
  });
  const [avatarFile, setAvatarFile] = useState<File | null>(null);
  const [avatarPreview, setAvatarPreview] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [activeTab, setActiveTab] = useState('profile');

  useEffect(() => {
    const currentUser = authService.getCurrentUser();
    if (!currentUser) {
      router.push('/connexion');
      return;
    }

    setUser(currentUser);
    setFormData({
      name: currentUser.name || '',
      email: currentUser.email || '',
      currentPassword: '',
      password: '',
      passwordConfirm: '',
    });
    setAvatarPreview(currentUser.avatarUrl);
  }, [router]);

  const handleChange = (e: ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleAvatarClick = () => {
    fileInputRef.current?.click();
  };

  const handleFileChange = (e: ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      setAvatarFile(file);
      const reader = new FileReader();
      reader.onload = (event) => {
        setAvatarPreview(event.target?.result as string);
      };
      reader.readAsDataURL(file);
    }
  };

  const handleProfileUpdate = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setMessage({ text: '', type: '' });

    try {
      const updateData: any = {
        name: formData.name,
        email: formData.email,
      };

      if (avatarFile) {
        updateData.avatar = avatarFile;
      }

      const updatedUser = await authService.updateProfile(updateData);
      setUser(updatedUser);
      setMessage({ text: 'Profil mis à jour avec succès', type: 'success' });
    } catch (error: any) {
      setMessage({ text: error.message || 'Erreur lors de la mise à jour du profil', type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  const handlePasswordUpdate = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setMessage({ text: '', type: '' });

    if (formData.password !== formData.passwordConfirm) {
      setMessage({ text: 'Les mots de passe ne correspondent pas', type: 'error' });
      setLoading(false);
      return;
    }

    try {
      await authService.updateProfile({
        currentPassword: formData.currentPassword,
        password: formData.password,
        passwordConfirm: formData.passwordConfirm,
      });
      
      setFormData(prev => ({
        ...prev,
        currentPassword: '',
        password: '',
        passwordConfirm: '',
      }));
      
      setMessage({ text: 'Mot de passe mis à jour avec succès', type: 'success' });
    } catch (error: any) {
      setMessage({ text: error.message || 'Erreur lors de la mise à jour du mot de passe', type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    authService.logout();
    router.push('/');
  };

  if (!user) {
    return (
      <div className="min-h-screen flex justify-center items-center">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-white"></div>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto p-6">
      <h1 className="text-3xl font-bold mb-8 text-center text-white">Mon Compte</h1>
      <div className="bg-gray-800 rounded-lg shadow-lg overflow-hidden mb-6">
        <div className="p-6">
          <div className="flex flex-col md:flex-row items-start md:items-center mb-8">
            <div className="mr-6 mb-4 md:mb-0">
              <div className="relative" onClick={handleAvatarClick}>
                {avatarPreview ? (
                  <div className="w-24 h-24 rounded-full overflow-hidden bg-gray-700">
                    <Image 
                      src={avatarPreview} 
                      alt="Avatar" 
                      width={96} 
                      height={96} 
                      className="w-full h-full object-cover cursor-pointer"
                    />
                  </div>
                ) : (
                  <div className="w-24 h-24 flex items-center justify-center bg-gray-700 text-white rounded-full text-2xl font-bold cursor-pointer">
                    {user.name.charAt(0).toUpperCase()}
                  </div>
                )}
                <div className="absolute bottom-0 right-0 bg-blue-600 rounded-full p-2 cursor-pointer">
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" />
                  </svg>
                </div>
                <input 
                  type="file" 
                  ref={fileInputRef} 
                  onChange={handleFileChange} 
                  className="hidden" 
                  accept="image/*" 
                />
              </div>
            </div>
            <div>
              <h2 className="text-xl font-semibold text-white">{user.name}</h2>
              <p className="text-gray-400">{user.email}</p>
              <p className="text-gray-400 text-sm">Nom d&apos;utilisateur: {user.username}</p>
            </div>
          </div>

          {message.text && (
            <div className={`mb-4 p-3 rounded ${message.type === 'success' ? 'bg-green-700 text-white' : 'bg-red-700 text-white'}`}>
              {message.text}
            </div>
          )}

          <div className="border-b border-gray-700 mb-6">
            <div className="flex">
              <button 
                onClick={() => setActiveTab('profile')} 
                className={`px-4 py-2 font-medium ${activeTab === 'profile' ? 'text-blue-500 border-b-2 border-blue-500' : 'text-gray-400'}`}
              >
                Profil
              </button>
              <button 
                onClick={() => setActiveTab('password')} 
                className={`px-4 py-2 font-medium ${activeTab === 'password' ? 'text-blue-500 border-b-2 border-blue-500' : 'text-gray-400'}`}
              >
                Sécurité
              </button>
            </div>
          </div>

          {activeTab === 'profile' && (
            <form onSubmit={handleProfileUpdate}>
              <div className="mb-4">
                <label htmlFor="name" className="block text-gray-300 mb-2">Nom complet</label>
                <input
                  type="text"
                  id="name"
                  name="name"
                  value={formData.name}
                  onChange={handleChange}
                  className="w-full p-2 rounded bg-gray-700 text-white border border-gray-600 focus:border-blue-500 focus:outline-none"
                  required
                />
              </div>
              <div className="mb-6">
                <label htmlFor="email" className="block text-gray-300 mb-2">Email</label>
                <input
                  type="email"
                  id="email"
                  name="email"
                  value={formData.email}
                  onChange={handleChange}
                  className="w-full p-2 rounded bg-gray-700 text-white border border-gray-600 focus:border-blue-500 focus:outline-none"
                  required
                />
              </div>
              <div className="flex justify-end">
                <button
                  type="submit"
                  disabled={loading}
                  className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors"
                >
                  {loading ? 'Mise à jour...' : 'Mettre à jour le profil'}
                </button>
              </div>
            </form>
          )}

          {activeTab === 'password' && (
            <form onSubmit={handlePasswordUpdate}>
              <div className="mb-4">
                <label htmlFor="currentPassword" className="block text-gray-300 mb-2">Mot de passe actuel</label>
                <input
                  type="password"
                  id="currentPassword"
                  name="currentPassword"
                  value={formData.currentPassword}
                  onChange={handleChange}
                  className="w-full p-2 rounded bg-gray-700 text-white border border-gray-600 focus:border-blue-500 focus:outline-none"
                  required
                />
              </div>
              <div className="mb-4">
                <label htmlFor="password" className="block text-gray-300 mb-2">Nouveau mot de passe</label>
                <input
                  type="password"
                  id="password"
                  name="password"
                  value={formData.password}
                  onChange={handleChange}
                  className="w-full p-2 rounded bg-gray-700 text-white border border-gray-600 focus:border-blue-500 focus:outline-none"
                  required
                />
              </div>
              <div className="mb-6">
                <label htmlFor="passwordConfirm" className="block text-gray-300 mb-2">Confirmer le nouveau mot de passe</label>
                <input
                  type="password"
                  id="passwordConfirm"
                  name="passwordConfirm"
                  value={formData.passwordConfirm}
                  onChange={handleChange}
                  className="w-full p-2 rounded bg-gray-700 text-white border border-gray-600 focus:border-blue-500 focus:outline-none"
                  required
                />
              </div>
              <div className="flex justify-end">
                <button
                  type="submit"
                  disabled={loading}
                  className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors"
                >
                  {loading ? 'Mise à jour...' : 'Mettre à jour le mot de passe'}
                </button>
              </div>
            </form>
          )}
        </div>
      </div>

      <div className="text-center">
        <button
          onClick={handleLogout}
          className="px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700 transition-colors"
        >
          Déconnexion
        </button>
      </div>
    </div>
  );
}
