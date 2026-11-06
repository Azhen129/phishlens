export const isPublicDemo =
  import.meta.env.MODE === "demo" ||
  import.meta.env.VITE_PUBLIC_DEMO === "true";
