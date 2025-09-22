export type Lang = "en" | "he";
export const LANG: Lang = "he";
export const dirFor = (lang: Lang) => (lang === "he" ? "rtl" : "ltr");
export type Label = { en: string; he: string };
export const t = (lbl: Label) => lbl[LANG];