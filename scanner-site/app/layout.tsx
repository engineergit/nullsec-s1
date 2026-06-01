import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Nullsec-S1 Scanner",
  description:
    "Paste source code and receive a structured Nullsec-S1 security verdict.",
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
