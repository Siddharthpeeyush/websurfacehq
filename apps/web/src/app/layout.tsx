import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "WebSurfaceHQ — Your attack surface, under control.",
  description:
    "WebSurfaceHQ is a vulnerability-scanner SaaS: paste a domain you own, prove ownership, get a prioritised security report. Scaffold — coming soon.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
