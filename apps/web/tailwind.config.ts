import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      // Design tokens are intentionally minimal in the Phase 0 scaffold.
      // The full design system (tokens, buttons, inputs, tables, states)
      // lands in Week 1 with the frontend shell — see ENGINEERING-PLAN.md.
    },
  },
  plugins: [],
};

export default config;
