import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Agent Policy Gateway Console",
  description: "Deterministic AI Policy Enforcement Console",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-kiro-bg text-kiro-text antialiased">
        {children}
      </body>
    </html>
  );
}
