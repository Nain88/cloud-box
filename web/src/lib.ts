export type Row = Record<string, any>;
let csrf = '';
export function setCsrf(value: string) { csrf = value; }
export class ApiError extends Error {
  constructor(message: string, public status: number, public code?: string, public requestId?: string) { super(message); }
}
export async function api<T = any>(path: string, method = 'GET', body?: unknown): Promise<T> {
  const response = await fetch('/api/v1' + path, {
    method, credentials: 'same-origin',
    headers: { ...(body !== undefined && !(body instanceof FormData) ? {'Content-Type': 'application/json'} : {}), ...(method !== 'GET' ? {'X-CSRF-Token': csrf, 'Idempotency-Key': crypto.randomUUID()} : {}) },
    body: body === undefined ? undefined : body instanceof FormData ? body : JSON.stringify(body),
  });
  const json = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401 && path !== '/auth/session') window.dispatchEvent(new Event('session-expired'));
    const detail = typeof json.detail === 'string' ? json.detail : Array.isArray(json.detail) ? json.detail.map((x: Row) => x.msg).join('; ') : 'Request could not be completed';
    throw new ApiError(detail, response.status, json.code, json.request_id || response.headers.get('X-Request-ID'));
  }
  return json;
}
export function parseJson(value: unknown, fallback: any = {}) { if (typeof value !== 'string') return value ?? fallback; try { return JSON.parse(value); } catch { return fallback; } }
export function pretty(value: unknown) { return JSON.stringify(value, null, 2); }
export function short(value: unknown, length = 12) { const s = String(value || '—'); return s.length > length ? s.slice(0,length) + '…' : s; }
export function bytes(value: unknown): string { const n = Number(value); if (!Number.isFinite(n) || value == null) return 'Unknown'; if (n < 1024) return `${n} B`; const unit = Math.min(4,Math.floor(Math.log(n)/Math.log(1024))); return `${(n/1024**unit).toFixed(1)} ${['B','KiB','MiB','GiB','TiB'][unit]}`; }
export function utc(value: unknown): string { if (!value) return 'Unknown'; const d = new Date(typeof value === 'number' ? value * 1000 : String(value)); return Number.isNaN(d.getTime()) ? 'Unknown' : d.toISOString().replace('T',' ').replace('.000','').replace('Z',' UTC'); }
export function routeQuery(path: string, values: Row) { const q = new URLSearchParams(); for (const [k,v] of Object.entries(values)) if (v !== '' && v != null) q.set(k,String(v)); return path + (q.size ? '?' + q.toString() : ''); }
export function downloadJson(filename: string, data: unknown) { const url = URL.createObjectURL(new Blob([pretty(data)],{type:'application/json'})); const a = document.createElement('a'); a.href=url; a.download=filename; a.click(); setTimeout(()=>URL.revokeObjectURL(url),1000); }
