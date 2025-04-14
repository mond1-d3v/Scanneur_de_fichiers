import Image from 'next/image';

export default function AboutPage() {
  const technologies = [
    { name: 'Next.js', logo: '/nextjs.svg', width: 80, height: 40 },
    { name: 'TypeScript', logo: '/typescript.svg', width: 40, height: 40 },
    { name: 'Tailwind CSS', logo: '/tailwindcss.svg', width: 40, height: 40 },
    { name: 'Python', logo: '/python.svg', width: 40, height: 40 },
    { name: 'PocketBase', logo: '/pocketbase.svg', width: 40, height: 40 },
  ];

  return (
    <div className="max-w-3xl mx-auto">
      <h1 className="text-[#00FFFF] text-3xl font-bold mb-6 text-center">À propos du Scanner de Malware</h1>
      
      <div className="bg-[rgb(31,31,31)] p-6 rounded-lg shadow-md mb-8">
        <h2 className="text-xl font-semibold mb-4 text-[#00FFFF]">Notre mission</h2>
        <p className="mb-4">
          Notre scanner de malware a été développé pour offrir une solution simple mais efficace 
          pour détecter les menaces dans les fichiers. Que ce soit pour des scripts, des exécutables 
          ou d&apos;autres types de fichiers, notre outil utilise des techniques avancées pour identifier 
          les comportements malveillants.
        </p>
        <p>
          Notre objectif est de rendre la sécurité informatique accessible à tous, avec une 
          interface intuitive et des résultats clairs.
        </p>
      </div>
      
      <div className="bg-[rgb(31,31,31)] p-6 rounded-lg shadow-md mb-8">
        <h2 className="text-xl font-semibold mb-4 text-[#00FFFF]">Technologies utilisées</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <h3 className="font-semibold text-lg mb-2">Frontend</h3>
            <ul className="space-y-4">
              {technologies.slice(0, 3).map((tech, index) => (
                <li key={index} className="flex items-center space-x-3 text-gray-300">
                  {tech.logo && (
                    <div className="w-10 h-10 flex items-center justify-center  rounded p-1">
                      <Image 
                        src={tech.logo} 
                        alt={`${tech.name} logo`} 
                        width={tech.width} 
                        height={tech.height}
                      />
                    </div>
                  )}
                  <span>{tech.name}</span>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <h3 className="font-semibold text-lg mb-2">Backend</h3>
            <ul className="space-y-4">
              {technologies.slice(3).map((tech, index) => (
                <li key={index} className="flex items-center space-x-3 text-gray-300">
                  {tech.logo && (
                    <div className="w-10 h-10 flex items-center justify-center  rounded p-1">
                      <Image 
                        src={tech.logo} 
                        alt={`${tech.name} logo`} 
                        width={tech.width} 
                        height={tech.height}
                      />
                    </div>
                  )}
                  <span>{tech.name}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
      
      <div className="bg-[rgb(31,31,31)] p-6 rounded-lg shadow-md mb-8">
        <h2 className="text-xl font-semibold mb-4 text-[#00FFFF]">Comment ça marche?</h2>
        <ol className="list-decimal pl-5 space-y-2">
          <li className='text-[#CDCDCD]'>
            <strong className='text-[#FFFFFF]'>Téléchargement du fichier</strong> - Le fichier est envoyé de manière sécurisée au serveur.
          </li>
          <li className='text-[#CDCDCD]'>
            <strong className='text-[#FFFFFF]'>Analyse du fichier</strong> - Plusieurs scanners spécialisés analysent le fichier selon son type.
          </li>
          <li className='text-[#CDCDCD]'>
            <strong className='text-[#FFFFFF]'>Détection de menaces</strong> - Le système recherche des signatures connues et des comportements suspects.
          </li>
          <li className='text-[#CDCDCD]'>
            <strong className='text-[#FFFFFF]'>Calcul du score de risque</strong> - Un score est attribué en fonction des menaces potentielles détectées.
          </li>
          <li className='text-[#CDCDCD]'>
            <strong className='text-[#FFFFFF]'>Génération du rapport</strong> - Un rapport détaillé est présenté à l&apos;utilisateur.
          </li>
        </ol>
      </div>
      
      <div className="bg-[rgb(31,31,31)] p-6 rounded-lg shadow-md">
        <h2 className="text-xl font-semibold mb-4 text-[#00FFFF]">Notre équipe</h2>
        <p className="mb-2">
          Cette application a été réalisée dans le cadre du projet d&apos;études de l&apos;année 2024-2025.
        </p>
        <p>
          Pour toute question ou suggestion, n&apos;hésitez pas à nous contacter.
        </p>
      </div>
    </div>
  );
}
