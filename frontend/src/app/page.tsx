import Link from 'next/link';

export default function Home() {
  return (
    <div className="flex flex-col items-center justify-center min-h-[80vh] px-4">
      <h1 className="text-8xl md:text-9xl font-bold mb-6 text-center text-[#00FFFF]">CyberSentinel</h1>
      
      <div className="max-w-xl text-center mb-10">
        <p className="text-md mb-2 text-white">
          Analysez vos fichiers en toute sécurité pour identifier d&apos;éventuelles menaces.
          Notre scanner utilise des techniques avancées pour détecter les logiciels malveillants.
        </p>
      </div>
      
      <Link 
        href="/scanner" 
        className="bg-[#00DFDF] hover:bg-[#009494] text-white px-6 py-3 rounded-lg flex items-center text-lg transition-all duration-300 shadow-md hover:shadow-lg"
      >
        <span>Commencer le scan</span>
        <span className="ml-2">→</span>
      </Link>
    </div>
  );
}
