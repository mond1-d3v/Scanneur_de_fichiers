/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      keyframes: {
        flicker: {
          '0%, 100%': { 
            borderColor: 'rgb(1, 235, 252)',
            boxShadow: '0px 0px 100px rgb(1, 235, 252), inset 0px 0px 10px rgb(1, 235, 252), 0px 0px 5px rgb(255, 255, 255)'
          },
          '5%': {
            borderColor: 'transparent',
            boxShadow: 'none'
          },
          '10%': {
            borderColor: 'rgb(1, 235, 252)',
            boxShadow: '0px 0px 100px rgb(1, 235, 252), inset 0px 0px 10px rgb(1, 235, 252), 0px 0px 5px rgb(255, 255, 255)'
          },
          '25%': {
            borderColor: 'transparent',
            boxShadow: 'none'
          },
          '30%': {
            borderColor: 'rgb(1, 235, 252)',
            boxShadow: '0px 0px 100px rgb(1, 235, 252), inset 0px 0px 10px rgb(1, 235, 252), 0px 0px 5px rgb(255, 255, 255)'
          }
        },
        iconflicker: {
          '0%, 100%': { opacity: 1 },
          '5%': { opacity: 0.2 },
          '10%': { opacity: 1 },
          '25%': { opacity: 0.2 },
          '30%': { opacity: 1 }
        }
      },
      animation: {
        'flicker': 'flicker 2s linear infinite',
        'iconflicker': 'iconflicker 2s linear infinite'
      },
      transitionProperty: {
        'transform': 'transform',
      },
    },
  },
  safelist: [
    'rotate-y-0',
    'rotate-y-180',
    'visible',
    'invisible',
    'perspective-[1000px]',
    'backface-hidden'
  ],
  plugins: [],
}
