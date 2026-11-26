// Busca pedidos na VTEX (OMS), tira dados pessoais e grava data/pedidos.enc.json criptografado.
import { webcrypto as crypto } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";

const { VTEX_ACCOUNT, VTEX_APPKEY, VTEX_APPTOKEN, SITE_PASSWORD } = process.env;
const DIAS = Number(process.env.DIAS || 120);
if (!VTEX_ACCOUNT || !VTEX_APPKEY || !VTEX_APPTOKEN || !SITE_PASSWORD) {
  console.error("Faltam segredos: VTEX_ACCOUNT, VTEX_APPKEY, VTEX_APPTOKEN, SITE_PASSWORD");
  process.exit(1);
}

const base = `https://${VTEX_ACCOUNT}.vtexcommercestable.com.br/api/oms/pvt/orders`;
const headers = { "X-VTEX-API-AppKey": VTEX_APPKEY, "X-VTEX-API-AppToken": VTEX_APPTOKEN, Accept: "application/json" };

async function get(url, tentativas = 5) {
  for (let i = 0; i < tentativas; i++) {
    const r = await fetch(url, { headers });
    if (r.ok) return r.json();
    if (r.status === 429 || r.status >= 500) { await new Promise(s => setTimeout(s, 1500 * (i + 1))); continue; }
    throw new Error(`VTEX respondeu ${r.status} em ${url.split("?")[0]}`);
  }
  throw new Error("Muitas tentativas: " + url.split("?")[0]);
}

// 1) lista os ids dos pedidos do período
const fim = new Date(), ini = new Date(Date.now() - DIAS * 864e5);
const filtro = encodeURIComponent(`creationDate:[${ini.toISOString()} TO ${fim.toISOString()}]`);
const ids = [];
for (let p = 1, paginas = 1; p <= paginas && p <= 30; p++) {
  const d = await get(`${base}?per_page=100&page=${p}&orderBy=creationDate,desc&f_creationDate=${filtro}`);
  paginas = d.paging?.pages || 1;
  ids.push(...d.list.map(o => o.orderId));
}
console.log(`${ids.length} pedidos na lista`);

// 2) detalhe de cada pedido, só campos de análise (sem nome, telefone nem e-mail)
const pedidos = [];
for (let i = 0; i < ids.length; i += 5) {
  const lote = await Promise.all(ids.slice(i, i + 5).map(id => get(`${base}/${encodeURIComponent(id)}`)));
  for (const o of lote) {
    pedidos.push({
      id: o.orderId,
      data: o.creationDate,
      status: o.status,
      valor: (o.value || 0) / 100,
      estado: o.shippingData?.address?.state || "",
      pagamento: o.paymentData?.transactions?.[0]?.payments?.[0]?.paymentSystemName || "",
      cupom: o.marketingData?.coupon || "",
      itens: (o.items || []).map(x => ({ ref: x.refId || "", nome: x.name || "", qtd: x.quantity || 0, preco: (x.sellingPrice ?? x.price ?? 0) / 100 })),
    });
  }
}

// 3) criptografa com a senha (PBKDF2 + AES-GCM); o navegador descriptografa
const b64 = b => Buffer.from(b).toString("base64");
const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(SITE_PASSWORD), "PBKDF2", false, ["deriveKey"]);
const chave = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: 250000, hash: "SHA-256" }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
const texto = JSON.stringify({ atualizado: new Date().toISOString(), pedidos });
const cifrado = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, chave, new TextEncoder().encode(texto));

mkdirSync("data", { recursive: true });
writeFileSync("data/pedidos.enc.json", JSON.stringify({ salt: b64(salt), iv: b64(iv), dados: b64(new Uint8Array(cifrado)) }));
console.log(`Gravado: ${pedidos.length} pedidos`);
