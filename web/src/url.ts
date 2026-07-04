import { LANGS } from "./constants";
import { Lang } from "./types";

// The analysis inputs are mirrored into the URL query so a given analysis is
// shareable and survives a reload. Template and payload use short keys (t, p).

export interface UrlState {
  lang?: Lang;
  dialect?: string;
  source?: string;
  template?: string;
  payload?: string;
}

const LANG_SET = new Set<string>(LANGS.map((l) => l.value));

export function readUrlState(): UrlState {
  const q = new URLSearchParams(window.location.search);
  const out: UrlState = {};

  const lang = q.get("lang");
  if (lang && LANG_SET.has(lang)) out.lang = lang as Lang;

  const dialect = q.get("dialect");
  if (dialect) out.dialect = dialect;

  const source = q.get("source");
  if (source) out.source = source;

  const template = q.get("t");
  if (template !== null) out.template = template;

  const payload = q.get("p");
  if (payload !== null) out.payload = payload;

  return out;
}

function query(s: UrlState): string {
  const q = new URLSearchParams();
  if (s.lang) q.set("lang", s.lang);
  if (s.dialect) q.set("dialect", s.dialect);
  if (s.source && s.source !== "tool_output") q.set("source", s.source);
  if (s.template) q.set("t", s.template);
  if (s.payload) q.set("p", s.payload);
  return q.toString();
}

export function writeUrlState(s: UrlState): void {
  const qs = query(s);
  const url = qs ? `${window.location.pathname}?${qs}` : window.location.pathname;
  window.history.replaceState(null, "", url);
}

export function shareLink(s: UrlState): string {
  const qs = query(s);
  const { origin, pathname } = window.location;
  return qs ? `${origin}${pathname}?${qs}` : `${origin}${pathname}`;
}
