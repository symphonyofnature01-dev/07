import crypto from 'node:crypto';
import type { SpreadsheetDatabase } from '../src/types/database';

interface ApiRequest {
  method?: string;
  body?: unknown;
}

interface ApiResponse {
  status: (code: number) => ApiResponse;
  json: (payload: unknown) => void;
  setHeader?: (name: string, value: string) => void;
}

const SHEET_SCHEMA: Record<keyof SpreadsheetDatabase, string[]> = {
  Rumah: [
    'ID',
    'Blok',
    'Nomor',
    'Alamat',
    'StatusHunian',
    'IDPemilik',
    'IDPenanggungJawabIuran',
    'PihakPembayarIuran',
    'KategoriIuran',
    'Catatan',
    'PINHash',
  ],
  Penduduk: [
    'ID',
    'NIK',
    'NamaLengkap',
    'JenisKelamin',
    'TempatLahir',
    'TanggalLahir',
    'NoHP',
    'Pekerjaan',
    'StatusPenduduk',
    'StatusData',
  ],
  Keluarga: [
    'ID',
    'IDRumah',
    'IDPenduduk',
    'IDKepalaKeluarga',
    'HubunganKeluarga',
    'Peran',
    'StatusMenghuni',
  ],
  RiwayatHunian: [
    'ID',
    'IDRumah',
    'IDKepalaKeluarga',
    'NamaKeluarga',
    'JenisHunian',
    'TanggalMulai',
    'TanggalSelesai',
    'StatusHunian',
    'Catatan',
  ],
  Pembayaran: [
    'ID',
    'AlamatRumah',
    'JenisIuran',
    'TipeIuran',
    'Periode',
    'Tahun',
    'Bulan',
    'Nominal',
    'TanggalBayar',
    'MetodeBayar',
    'BuktiURL',
    'KodeTransaksi',
    'Status',
    'PihakPembayar',
    'CatatanVerifikator',
    'DiverifikasiOleh',
    'TanggalVerifikasi',
  ],
  BukuKas: [
    'ID',
    'Tanggal',
    'Jenis',
    'Kategori',
    'Uraian',
    'Nominal',
    'SumberReferensi',
    'DicatatOleh',
  ],
  Tarif: ['ID', 'JenisIuran', 'TipeIuran', 'KategoriIuran', 'Nominal', 'Status'],
  Agenda: ['ID', 'Judul', 'Tanggal', 'Waktu', 'Lokasi', 'Deskripsi', 'Status', 'DibuatOleh'],
  Informasi: ['ID', 'Judul', 'Isi', 'Kategori', 'TanggalTerbit', 'Status', 'DibuatOleh'],
  Pengurus: ['ID', 'Nama', 'Username', 'PasswordHash', 'Jabatan', 'Role', 'Status', 'DibuatPada'],
  Pengaturan: ['Kunci', 'Nilai'],
  LogAktivitas: ['Waktu', 'User', 'Aksi', 'Detail'],
};

const NUMERIC_COLUMNS = new Set(['Tahun', 'Bulan', 'Nominal']);
const SERVICE_ACCOUNT_SCOPES = 'https://www.googleapis.com/auth/spreadsheets';

let cachedServiceToken: { token: string; expiresAt: number } | null = null;

function base64UrlEncode(input: string | Buffer): string {
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function extractSpreadsheetId(input: string): string {
  const trimmed = input.trim();
  const match = trimmed.match(/\/spreadsheets\/d\/([a-zA-Z0-9-_]+)/);
  if (match && match[1]) return match[1];
  return trimmed;
}

function normalizePrivateKey(raw: string): string {
  let key = raw.trim();
  if (
    (key.startsWith('"') && key.endsWith('"')) ||
    (key.startsWith("'") && key.endsWith("'"))
  ) {
    key = key.slice(1, -1);
  }
  return key.replace(/\\n/g, '\n');
}

function getServerEnvStatus() {
  const email = (process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL || '').trim();
  const privateKeyRaw = process.env.GOOGLE_PRIVATE_KEY || '';
  const spreadsheetIdRaw = process.env.GOOGLE_SPREADSHEET_ID || '';

  const missing: string[] = [];
  if (!email) missing.push('GOOGLE_SERVICE_ACCOUNT_EMAIL');
  if (!privateKeyRaw.trim()) missing.push('GOOGLE_PRIVATE_KEY');
  if (!spreadsheetIdRaw.trim()) missing.push('GOOGLE_SPREADSHEET_ID');

  return {
    configured: missing.length === 0,
    missing,
    email,
    privateKey: privateKeyRaw ? normalizePrivateKey(privateKeyRaw) : '',
    spreadsheetId: spreadsheetIdRaw ? extractSpreadsheetId(spreadsheetIdRaw) : '',
  };
}

async function getServiceAccountAccessToken(email: string, privateKey: string): Promise<string> {
  const nowSec = Math.floor(Date.now() / 1000);
  if (cachedServiceToken && cachedServiceToken.expiresAt - 120 > nowSec) {
    return cachedServiceToken.token;
  }

  const header = base64UrlEncode(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claimSet = base64UrlEncode(
    JSON.stringify({
      iss: email,
      scope: SERVICE_ACCOUNT_SCOPES,
      aud: 'https://oauth2.googleapis.com/token',
      exp: nowSec + 3600,
      iat: nowSec,
    })
  );

  const unsignedJwt = `${header}.${claimSet}`;
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(unsignedJwt);
  signer.end();
  const signature = base64UrlEncode(signer.sign(privateKey));
  const assertion = `${unsignedJwt}.${signature}`;

  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion,
    }).toString(),
  });

  if (!tokenRes.ok) {
    let errText = `HTTP ${tokenRes.status}`;
    try {
      const errJson = (await tokenRes.json()) as { error_description?: string; error?: string };
      errText = errJson.error_description || errJson.error || errText;
    } catch {
      // ignore
    }
    throw new Error(`Autentikasi Service Account gagal: ${errText}`);
  }

  const tokenData = (await tokenRes.json()) as { access_token?: string; expires_in?: number };
  if (!tokenData.access_token) {
    throw new Error('Token akses Service Account tidak diterima dari Google.');
  }

  cachedServiceToken = {
    token: tokenData.access_token,
    expiresAt: nowSec + (tokenData.expires_in || 3600),
  };

  return cachedServiceToken.token;
}

function quoteSheetTitle(title: string): string {
  return `'${title.replace(/'/g, "''")}'`;
}

async function googleSheetsFetch(url: string, token: string, init?: RequestInit) {
  const res = await fetch(url, {
    ...init,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      ...(init?.headers || {}),
    },
  });

  if (res.status === 401) {
    cachedServiceToken = null;
  }

  if (!res.ok) {
    let msg = `Google Sheets API HTTP ${res.status}`;
    try {
      const json = (await res.json()) as { error?: { message?: string } };
      if (json?.error?.message) msg = json.error.message;
    } catch {
      // ignore
    }
    throw new Error(msg);
  }

  return res.json();
}

function serializeSheetRows(
  sheetName: keyof SpreadsheetDatabase,
  db: Partial<SpreadsheetDatabase>
): (string | number)[][] {
  const headers = SHEET_SCHEMA[sheetName];
  const rows = ((db[sheetName] || []) as unknown) as Record<string, unknown>[];

  const dataRows = rows.map((row) =>
    headers.map((col) => {
      const raw = row[col];
      if (raw === null || raw === undefined) return '';
      if (NUMERIC_COLUMNS.has(col)) {
        const n = Number(raw);
        return Number.isFinite(n) ? n : 0;
      }
      const str = String(raw);
      if (str.length > 49500) {
        return '[Lampiran terlalu besar untuk sel Google Sheets]';
      }
      return str;
    })
  );

  return [headers, ...dataRows];
}

async function getSpreadsheetMeta(token: string, spreadsheetId: string) {
  const fields = 'spreadsheetId,properties.title,sheets.properties(sheetId,title)';
  const data = (await googleSheetsFetch(
    `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(spreadsheetId)}?fields=${encodeURIComponent(fields)}`,
    token
  )) as {
    properties?: { title?: string };
    sheets?: { properties?: { sheetId?: number; title?: string } }[];
  };

  return {
    title: data.properties?.title || 'Google Spreadsheet',
    sheets: (data.sheets || []).map((s) => ({
      sheetId: s.properties?.sheetId ?? 0,
      title: s.properties?.title ?? 'Sheet',
    })),
  };
}

async function handlePull(token: string, spreadsheetId: string) {
  const meta = await getSpreadsheetMeta(token, spreadsheetId);
  const canonicalKeys = Object.keys(SHEET_SCHEMA) as (keyof SpreadsheetDatabase)[];
  const canonicalByLower = new Map(canonicalKeys.map((k) => [k.toLowerCase(), k]));

  const matchedTabs: { canonical: keyof SpreadsheetDatabase; actualTitle: string }[] = [];
  meta.sheets.forEach((s) => {
    const found = canonicalByLower.get(s.title.toLowerCase());
    if (found) matchedTabs.push({ canonical: found, actualTitle: s.title });
  });

  const imported: Partial<SpreadsheetDatabase> = {};
  let totalRows = 0;

  if (matchedTabs.length > 0) {
    const params = new URLSearchParams();
    matchedTabs.forEach((t) => {
      params.append('ranges', `${quoteSheetTitle(t.actualTitle)}!A:Z`);
    });

    const batchRes = (await googleSheetsFetch(
      `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(spreadsheetId)}/values:batchGet?${params.toString()}`,
      token
    )) as { valueRanges?: { values?: string[][] }[] };

    const valueRanges = batchRes.valueRanges || [];
    matchedTabs.forEach((tab, idx) => {
      const grid = valueRanges[idx]?.values || [];
      if (grid.length <= 1) {
        (imported as Record<string, unknown[]>)[tab.canonical] = [];
        return;
      }

      const headers = grid[0].map((h) => String(h || '').trim());
      const rows = grid.slice(1).filter((r) => r.some((cell) => String(cell ?? '').trim() !== ''));

      const parsedRows = rows.map((row) => {
        const obj: Record<string, unknown> = {};
        headers.forEach((h, colIdx) => {
          if (!h) return;
          const rawVal = row[colIdx] ?? '';
          if (NUMERIC_COLUMNS.has(h)) {
            const num = Number(String(rawVal).replace(/[^0-9.-]/g, ''));
            obj[h] = Number.isFinite(num) ? num : 0;
          } else {
            obj[h] = String(rawVal);
          }
        });
        return obj;
      });

      totalRows += parsedRows.length;
      (imported as Record<string, unknown[]>)[tab.canonical] = parsedRows;
    });
  }

  return {
    configured: true,
    spreadsheetTitle: meta.title,
    sheetTitles: meta.sheets.map((s) => s.title),
    hasAnyData: totalRows > 0,
    totalRows,
    data: imported,
  };
}

async function handlePush(
  token: string,
  spreadsheetId: string,
  db: Partial<SpreadsheetDatabase>
) {
  const meta = await getSpreadsheetMeta(token, spreadsheetId);
  const existingTitles = new Map(meta.sheets.map((s) => [s.title.toLowerCase(), s.title]));
  const canonicalNames = Object.keys(SHEET_SCHEMA) as (keyof SpreadsheetDatabase)[];
  const missingNames = canonicalNames.filter((name) => !existingTitles.has(name.toLowerCase()));

  if (missingNames.length > 0) {
    await googleSheetsFetch(
      `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(spreadsheetId)}:batchUpdate`,
      token,
      {
        method: 'POST',
        body: JSON.stringify({
          requests: missingNames.map((name) => ({
            addSheet: {
              properties: {
                title: name,
                gridProperties: { frozenRowCount: 1 },
              },
            },
          })),
        }),
      }
    );
    missingNames.forEach((name) => existingTitles.set(name.toLowerCase(), name));
  }

  const targetRanges = canonicalNames.map((name) => {
    const actualTitle = existingTitles.get(name.toLowerCase()) || name;
    return `${quoteSheetTitle(actualTitle)}!A:Z`;
  });

  await googleSheetsFetch(
    `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(spreadsheetId)}/values:batchClear`,
    token,
    {
      method: 'POST',
      body: JSON.stringify({ ranges: targetRanges }),
    }
  );

  let totalRows = 0;
  const updatedSheets: string[] = [];
  const dataPayload = canonicalNames.map((name) => {
    const actualTitle = existingTitles.get(name.toLowerCase()) || name;
    const values = serializeSheetRows(name, db);
    totalRows += Math.max(0, values.length - 1);
    updatedSheets.push(actualTitle);
    return {
      range: `${quoteSheetTitle(actualTitle)}!A1`,
      majorDimension: 'ROWS',
      values,
    };
  });

  await googleSheetsFetch(
    `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(spreadsheetId)}/values:batchUpdate`,
    token,
    {
      method: 'POST',
      body: JSON.stringify({
        valueInputOption: 'RAW',
        data: dataPayload,
      }),
    }
  );

  return {
    ok: true,
    configured: true,
    spreadsheetTitle: meta.title,
    updatedSheets,
    totalRows,
  };
}

export default async function handler(req: ApiRequest, res: ApiResponse) {
  res.setHeader?.('Cache-Control', 'no-store');

  const env = getServerEnvStatus();
  const method = (req.method || 'GET').toUpperCase();

  if (method === 'GET') {
    if (!env.configured) {
      return res.status(200).json({
        configured: false,
        missing: env.missing,
      });
    }

    try {
      const token = await getServiceAccountAccessToken(env.email, env.privateKey);
      const result = await handlePull(token, env.spreadsheetId);
      return res.status(200).json(result);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return res.status(500).json({
        configured: true,
        error: msg,
      });
    }
  }

  if (method === 'POST') {
    if (!env.configured) {
      return res.status(400).json({
        configured: false,
        missing: env.missing,
        error: 'Konfigurasi Service Account server belum lengkap.',
      });
    }

    try {
      let body = req.body;
      if (typeof body === 'string') {
        body = JSON.parse(body);
      }
      const payload = (body || {}) as { data?: Partial<SpreadsheetDatabase> };
      if (!payload.data || typeof payload.data !== 'object') {
        return res.status(400).json({ error: 'Payload data spreadsheet tidak valid.' });
      }

      const token = await getServiceAccountAccessToken(env.email, env.privateKey);
      const result = await handlePush(token, env.spreadsheetId, payload.data);
      return res.status(200).json(result);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return res.status(500).json({
        configured: true,
        error: msg,
      });
    }
  }

  return res.status(405).json({ error: 'Method not allowed' });
}
