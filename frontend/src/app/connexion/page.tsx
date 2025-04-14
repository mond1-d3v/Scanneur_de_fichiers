'use client';

import { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';
import authService from '@/services/authService';

export default function ConnexionPage() {
  const [isRegistering, setIsRegistering] = useState(false);
  const [loginUsername, setLoginUsername] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [registerUsername, setRegisterUsername] = useState('');
  const [registerEmail, setRegisterEmail] = useState('');
  const [registerPassword, setRegisterPassword] = useState('');
  const [registerPasswordConfirm, setRegisterPasswordConfirm] = useState('');
  const [registerName, setRegisterName] = useState('');
  const [registerAvatar, setRegisterAvatar] = useState<File | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);
  const router = useRouter();
  
  useEffect(() => {
    if (authService.isAuthenticated()) {
      router.push('/');
    }
  }, [router]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');
    
    try {
      await authService.login(loginUsername, loginPassword);
      router.push('/');
    } catch (error: unknown) {
      if (error instanceof Error) {
        setError(error.message || 'Erreur de connexion');
      } else {
        setError('Erreur de connexion');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (registerPassword !== registerPasswordConfirm) {
      setError("Les mots de passe ne correspondent pas");
      return;
    }
    
    setIsLoading(true);
    setError('');
    
    try {
      await authService.register({
        username: registerUsername,
        email: registerEmail,
        password: registerPassword,
        passwordConfirm: registerPasswordConfirm,
        name: registerName,
        avatar: registerAvatar || undefined
      });
      setTimeout(() => {
        router.push('/');
        router.refresh();
      }, 1500);
    } catch (error: any) {
      console.error("Erreur d'inscription:", error);
      if (error.message.includes('username') && error.message.includes('already exists')) {
        setError("Ce nom d'utilisateur est déjà utilisé. Veuillez en choisir un autre.");
      } else if (error.message.includes('email') && error.message.includes('already exists')) {
        setError("Cette adresse email est déjà utilisée. Veuillez vous connecter ou utiliser une autre adresse.");
      } else {
        setError(error.message || "Une erreur s'est produite lors de l'inscription. Veuillez réessayer.");
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleAvatarChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setRegisterAvatar(e.target.files[0]);
    }
  };

  const handleAvatarClick = () => {
    fileInputRef.current?.click();
  };
  const toggleForm = () => {
    setIsRegistering(!isRegistering);
    setError('');
  };

  return (
    <div className="flex items-center justify-center min-h-[80vh]">
      <div className="w-[345px] relative rounded-md overflow-hidden text-white shadow-[1.5px_1.5px_3px_#0e0e0e,_-1.5px_-1.5px_3px_rgba(95,94,94,0.25),_inset_0px_0px_0px_#0e0e0e,_inset_0px_-0px_0px_#5f5e5e] bg-[rgb(31,31,31)]">
        <div 
          className={`w-[200%] relative transition-transform duration-300 ease-out flex ${
            isRegistering ? 'translate-x-[-50%]' : 'translate-x-0'
          }`}
        >
          <form onSubmit={handleLogin} className="flex flex-col justify-center items-center gap-[30px] p-[1.5em_3em] w-1/2">
            <span className="text-center font-bold text-2xl">Se connecter</span>
            
            {error && !isRegistering && (
              <div className="bg-red-700 text-white p-2 rounded-md text-sm w-full">
                {error}
              </div>
            )}
            
            <div className="form_control w-full relative overflow-hidden">
              <input 
                type="text" 
                className="input w-full bg-transparent border-none outline-none text-white p-2 text-xs rounded-md transition-shadow duration-200 shadow-[0px_0px_0px_#0e0e0e,_0px_0px_0px_rgba(95,94,94,0.25),_inset_1.5px_1.5px_3px_#0e0e0e,_inset_-1.5px_-1.5px_3px_#5f5e5e] focus:shadow-[0px_0px_0px_#0e0e0e,_0px_0px_0px_rgba(95,94,94,0.25),_inset_3px_3px_4px_#0e0e0e,_inset_-3px_-3px_4px_#5f5e5e] valid:shadow-[0px_0px_0px_#0e0e0e,_0px_0px_0px_rgba(95,94,94,0.25),_inset_3px_3px_4px_#0e0e0e,_inset_-3px_-3px_4px_#5f5e5e]"
                required
                value={loginUsername}
                onChange={(e) => setLoginUsername(e.target.value)}
              />
              <label className={`label absolute top-1/2 left-[10px] transition-transform duration-200 ease-in-out ${loginUsername ? 'translate-x-[-150%] translate-y-[-50%]' : 'translate-x-0 translate-y-[-50%]'} text-xs select-none pointer-events-none text-[#b0b0b0]`}>
                Email
              </label>
            </div>
            
            <div className="form_control w-full relative overflow-hidden">
              <input 
                type="password" 
                className="input w-full bg-transparent border-none outline-none text-white p-2 text-xs rounded-md transition-shadow duration-200 shadow-[0px_0px_0px_#0e0e0e,_0px_0px_0px_rgba(95,94,94,0.25),_inset_1.5px_1.5px_3px_#0e0e0e,_inset_-1.5px_-1.5px_3px_#5f5e5e] focus:shadow-[0px_0px_0px_#0e0e0e,_0px_0px_0px_rgba(95,94,94,0.25),_inset_3px_3px_4px_#0e0e0e,_inset_-3px_-3px_4px_#5f5e5e] valid:shadow-[0px_0px_0px_#0e0e0e,_0px_0px_0px_rgba(95,94,94,0.25),_inset_3px_3px_4px_#0e0e0e,_inset_-3px_-3px_4px_#5f5e5e]"
                required
                value={loginPassword}
                onChange={(e) => setLoginPassword(e.target.value)}
              />
              <label className={`label absolute top-1/2 left-[10px] transition-transform duration-200 ease-in-out ${loginPassword ? 'translate-x-[-150%] translate-y-[-50%]' : 'translate-x-0 translate-y-[-50%]'} text-xs select-none pointer-events-none text-[#b0b0b0]`}>
                Mot de passe
              </label>
            </div>
            
            <button 
              type="submit" 
              disabled={isLoading}
              className="w-full bg-transparent border-none outline-none text-white p-2 text-xs rounded-md transition-shadow duration-100 shadow-[1.5px_1.5px_3px_#0e0e0e,_-1.5px_-1.5px_3px_rgba(95,94,94,0.25),_inset_0px_0px_0px_#0e0e0e,_inset_0px_-0px_0px_#5f5e5e] active:shadow-[0px_0px_0px_#0e0e0e,_0px_0px_0px_rgba(95,94,94,0.25),_inset_3px_3px_4px_#0e0e0e,_inset_-3px_-3px_4px_#5f5e5e]"
            >
              {isLoading ? "Connexion..." : "Login"}
            </button>
            
            <span className="text-[0.65em]">
              Pas de compte ? 
              <button 
                type="button" 
                onClick={toggleForm} 
                className="font-bold cursor-pointer ml-1 text-[1em] bg-transparent border-none text-white"
              >
                Créer un compte
              </button>
            </span>
          </form>
          <form onSubmit={handleRegister} className="flex flex-col justify-center items-center gap-[20px] p-[1.5em_3em] w-1/2">
            <span className="text-center font-bold text-2xl">Création de compte</span>
            
            {error && isRegistering && (
              <div className="bg-red-700 text-white p-2 rounded-md text-sm w-full">
                {error}
              </div>
            )}
            
            <div className="form_control w-full relative overflow-hidden">
              <input 
                type="text" 
                className="input w-full bg-transparent border-none outline-none text-white p-2 text-xs rounded-md transition-shadow duration-200 shadow-[0px_0px_0px_#0e0e0e,_0px_0px_0px_rgba(95,94,94,0.25),_inset_1.5px_1.5px_3px_#0e0e0e,_inset_-1.5px_-1.5px_3px_#5f5e5e] focus:shadow-[0px_0px_0px_#0e0e0e,_0px_0px_0px_rgba(95,94,94,0.25),_inset_3px_3px_4px_#0e0e0e,_inset_-3px_-3px_4px_#5f5e5e] valid:shadow-[0px_0px_0px_#0e0e0e,_0px_0px_0px_rgba(95,94,94,0.25),_inset_3px_3px_4px_#0e0e0e,_inset_-3px_-3px_4px_#5f5e5e]"
                required
                value={registerUsername}
                onChange={(e) => setRegisterUsername(e.target.value)}
              />
              <label className={`label absolute top-1/2 left-[10px] transition-transform duration-200 ease-in-out ${registerUsername ? 'translate-x-[-150%] translate-y-[-50%]' : 'translate-x-0 translate-y-[-50%]'} text-xs select-none pointer-events-none text-[#b0b0b0]`}>
                Nom d&apos;utilisateur
              </label>
            </div>
            
            <div className="form_control w-full relative overflow-hidden">
              <input 
                type="email" 
                className="input w-full bg-transparent border-none outline-none text-white p-2 text-xs rounded-md transition-shadow duration-200 shadow-[0px_0px_0px_#0e0e0e,_0px_0px_0px_rgba(95,94,94,0.25),_inset_1.5px_1.5px_3px_#0e0e0e,_inset_-1.5px_-1.5px_3px_#5f5e5e] focus:shadow-[0px_0px_0px_#0e0e0e,_0px_0px_0px_rgba(95,94,94,0.25),_inset_3px_3px_4px_#0e0e0e,_inset_-3px_-3px_4px_#5f5e5e] valid:shadow-[0px_0px_0px_#0e0e0e,_0px_0px_0px_rgba(95,94,94,0.25),_inset_3px_3px_4px_#0e0e0e,_inset_-3px_-3px_4px_#5f5e5e]"
                required
                value={registerEmail}
                onChange={(e) => setRegisterEmail(e.target.value)}
              />
              <label className={`label absolute top-1/2 left-[10px] transition-transform duration-200 ease-in-out ${registerEmail ? 'translate-x-[-150%] translate-y-[-50%]' : 'translate-x-0 translate-y-[-50%]'} text-xs select-none pointer-events-none text-[#b0b0b0]`}>
                Email
              </label>
            </div>
            
            <div className="form_control w-full relative overflow-hidden">
              <input 
                type="text" 
                className="input w-full bg-transparent border-none outline-none text-white p-2 text-xs rounded-md transition-shadow duration-200 shadow-[0px_0px_0px_#0e0e0e,_0px_0px_0px_rgba(95,94,94,0.25),_inset_1.5px_1.5px_3px_#0e0e0e,_inset_-1.5px_-1.5px_3px_#5f5e5e] focus:shadow-[0px_0px_0px_#0e0e0e,_0px_0px_0px_rgba(95,94,94,0.25),_inset_3px_3px_4px_#0e0e0e,_inset_-3px_-3px_4px_#5f5e5e] valid:shadow-[0px_0px_0px_#0e0e0e,_0px_0px_0px_rgba(95,94,94,0.25),_inset_3px_3px_4px_#0e0e0e,_inset_-3px_-3px_4px_#5f5e5e]"
                required
                value={registerName}
                onChange={(e) => setRegisterName(e.target.value)}
              />
              <label className={`label absolute top-1/2 left-[10px] transition-transform duration-200 ease-in-out ${registerName ? 'translate-x-[-150%] translate-y-[-50%]' : 'translate-x-0 translate-y-[-50%]'} text-xs select-none pointer-events-none text-[#b0b0b0]`}>
                Nom complet
              </label>
            </div>
            
            <div className="form_control w-full relative overflow-hidden">
              <input 
                type="password" 
                className="input w-full bg-transparent border-none outline-none text-white p-2 text-xs rounded-md transition-shadow duration-200 shadow-[0px_0px_0px_#0e0e0e,_0px_0px_0px_rgba(95,94,94,0.25),_inset_1.5px_1.5px_3px_#0e0e0e,_inset_-1.5px_-1.5px_3px_#5f5e5e] focus:shadow-[0px_0px_0px_#0e0e0e,_0px_0px_0px_rgba(95,94,94,0.25),_inset_3px_3px_4px_#0e0e0e,_inset_-3px_-3px_4px_#5f5e5e] valid:shadow-[0px_0px_0px_#0e0e0e,_0px_0px_0px_rgba(95,94,94,0.25),_inset_3px_3px_4px_#0e0e0e,_inset_-3px_-3px_4px_#5f5e5e]"
                required
                value={registerPassword}
                onChange={(e) => setRegisterPassword(e.target.value)}
              />
              <label className={`label absolute top-1/2 left-[10px] transition-transform duration-200 ease-in-out ${registerPassword ? 'translate-x-[-150%] translate-y-[-50%]' : 'translate-x-0 translate-y-[-50%]'} text-xs select-none pointer-events-none text-[#b0b0b0]`}>
                Mot de passe
              </label>
            </div>
            
            <div className="form_control w-full relative overflow-hidden">
              <input 
                type="password" 
                className="input w-full bg-transparent border-none outline-none text-white p-2 text-xs rounded-md transition-shadow duration-200 shadow-[0px_0px_0px_#0e0e0e,_0px_0px_0px_rgba(95,94,94,0.25),_inset_1.5px_1.5px_3px_#0e0e0e,_inset_-1.5px_-1.5px_3px_#5f5e5e] focus:shadow-[0px_0px_0px_#0e0e0e,_0px_0px_0px_rgba(95,94,94,0.25),_inset_3px_3px_4px_#0e0e0e,_inset_-3px_-3px_4px_#5f5e5e] valid:shadow-[0px_0px_0px_#0e0e0e,_0px_0px_0px_rgba(95,94,94,0.25),_inset_3px_3px_4px_#0e0e0e,_inset_-3px_-3px_4px_#5f5e5e]"
                required
                value={registerPasswordConfirm}
                onChange={(e) => setRegisterPasswordConfirm(e.target.value)}
              />
              <label className={`label absolute top-1/2 left-[10px] transition-transform duration-200 ease-in-out ${registerPasswordConfirm ? 'translate-x-[-150%] translate-y-[-50%]' : 'translate-x-0 translate-y-[-50%]'} text-xs select-none pointer-events-none text-[#b0b0b0]`}>
                Confirmer le mot de passe
              </label>
            </div>
            
            <div className="w-full">
              <div 
                className="flex items-center p-2 mb-2 text-xs border border-dashed border-gray-600 rounded-md cursor-pointer hover:border-gray-400 transition-colors"
                onClick={handleAvatarClick}
              >
                <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-2 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
                </svg>
                <span className="text-gray-400">
                  {registerAvatar ? registerAvatar.name : "Choisir une photo de profil (optionnel)"}
                </span>
                <input 
                  type="file" 
                  ref={fileInputRef}
                  className="hidden" 
                  accept="image/*"
                  onChange={handleAvatarChange}
                />
              </div>
            </div>
            
            <button 
              type="submit" 
              disabled={isLoading}
              className="w-full bg-transparent border-none outline-none text-white p-2 text-xs rounded-md transition-shadow duration-100 shadow-[1.5px_1.5px_3px_#0e0e0e,_-1.5px_-1.5px_3px_rgba(95,94,94,0.25),_inset_0px_0px_0px_#0e0e0e,_inset_0px_-0px_0px_#5f5e5e] active:shadow-[0px_0px_0px_#0e0e0e,_0px_0px_0px_rgba(95,94,94,0.25),_inset_3px_3px_4px_#0e0e0e,_inset_-3px_-3px_4px_#5f5e5e]"
            >
              {isLoading ? "Inscription..." : "Sign Up"}
            </button>
            
            <span className="text-[0.65em]">
              Vous avez un compte? 
              <button 
                type="button" 
                onClick={toggleForm} 
                className="font-bold cursor-pointer ml-1 text-[1em] bg-transparent border-none text-white"
              >
                Se connecter
              </button>
            </span>
          </form>
        </div>
      </div>
      
      <style jsx>{`
        input:focus + .label, input:valid + .label {
          transform: translate(-150%, -50%) !important;
        }
      `}</style>
    </div>
  );
}
