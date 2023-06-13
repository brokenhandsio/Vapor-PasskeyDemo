/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./Resources/**/*.leaf",
  ],
  theme: {
    extend: {},
  },
  plugins: [
    require('@tailwindcss/forms')
  ],
}

