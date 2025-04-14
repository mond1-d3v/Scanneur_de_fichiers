import './globals.css';
import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import Navbar from '@/components/Navbar';
import { AuthProvider } from '@/context/AuthContext';

const inter = Inter({ subsets: ['latin'] });

export const metadata: Metadata = {
  title: 'Scanner de Malware',
  description: 'Application de détection de malware et analyse de fichiers',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="fr" className="h-full">
      <body className={`${inter.className}  flex flex-col min-h-screen`}>
        <AuthProvider>
          <header>
            <Navbar />
          </header>
          <main className="container mx-auto py-8 px-4 flex-grow">
            {children}
          </main>
          <footer className="bg-[rgb(10,10,10)] p-4   w-full mt-auto">
            <div className="container mx-auto text-center text-white">
              &copy; {new Date().getFullYear()} CyberSentinel - Projet | XHARDA Mondi 
            </div>
          </footer>
        </AuthProvider>
      </body>
    </html>
  );
}
