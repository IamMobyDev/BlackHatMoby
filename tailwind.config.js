/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./templates/**/*.{html,js}",
    "./static/**/*.{html,js}"
  ],
  theme: {
    extend: {
      extend: {
        colors: {
          accent: '#4db8b8',
        },
        backgroundImage: {
          'diagonal-hatch': 'repeating-linear-gradient(315deg, var(--pattern-fg) 0, var(--pattern-fg) 1px, transparent 0, transparent 50%)',
          'dot-pattern': 'radial-gradient(var(--dot-color) 1px, transparent 1px)',
        },
        backgroundSize: {
          'hatch-size': '10px 10px',
          'dot-size': '16px 16px',
        },
        borderColor: {
          subtle: 'rgba(0, 0, 0, 0.05)',
          'subtle-dark': 'rgba(255, 255, 255, 0.1)',
        },
      }

    },
  },
  plugins: [],
}