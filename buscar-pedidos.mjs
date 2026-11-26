// Busca pedidos na VTEX (OMS), tira dados pessoais e grava data/pedidos.enc.json criptografado.
// Exige Node 18 ou mais novo.
import { webcrypto as crypto } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";

// Segredos colados no GitHub costumam vir com espaço ou quebra de linha no fim: tudo é aparado aqui.
const env = n => (process.env[n] || "").trim();
const VTEX_ACCOUNT = env("VTEX_ACCOUNT"), VTEX_APPKEY = env("VTEX_APPKEY"), VTEX_APPTOKEN = env("VTEX_APPTOKEN");
// A senha é aparada e normalizada (NFC) igual ao que o navegador faz ao digitar.
const SENHA = env("SITE_PASSWORD").normalize("NFC");
const DIAS = Number(env("DIAS")) > 0 ? Number(env("DIAS")) : 120;

if (!VTEX_ACCOUNT || !VTEX_APPKEY || !VTEX_APPTOKEN || !SENHA) {
  console.error("Faltam segredos: VTEX_ACCOUNT, VTEX_APPKEY, VTEX_APPTOKEN, SITE_PASSWORD");
  process.exit(1);
}
if (SENHA.length < 8) console.warn("Aviso: a senha tem menos de 8 caracteres. Use uma frase longa, pois o arquivo criptografado é público.");

const base = `https://${VTEX_ACCOUNT}.vtexcommercestable.com.br/api/oms/pvt/orders`;
const headers = { "X-VTEX-API-AppKey": VTEX_APPKEY, "X-VTEX-API-AppToken": VTEX_APPTOKEN, Accept: "application/json" };
const espera = ms => new Promise(s => setTimeout(s, ms));

async function get(url, tentativas = 5) {
  let ultimo = "";
  for (let i = 0; i < tentativas; i++) {
    let r;
    try { r = await fetch(url, { headers }); }
    catch (e) { ultimo = e.message; await espera(1500 * (i + 1)); continue; }
    if (r.ok) return r.json();
    if (r.status === 401 || r.status === 403) throw new Error(`VTEX negou acesso (${r.status}). Confira VTEX_ACCOUNT, VTEX_APPKEY, VTEX_APPTOKEN e se a chave pode ler pedidos (OMS).`);
    if (r.status === 429 || r.status >= 500) { ultimo = String(r.status); await espera(1500 * (i + 1)); continue; }
    throw new Error(`VTEX respondeu ${r.status} em ${url.split("?")[0]}`);
  }
  throw new Error(`Muitas tentativas (${ultimo}) em ${url.split("?")[0]}`);
}

async function main() {
  // 1) lista os ids em janelas de 10 dias (a VTEX só entrega 30 páginas por consulta)
  const fim = new Date(), inicio = new Date(Date.now() - DIAS * 864e5), JANELA = 10 * 864e5;
  const ids = new Set();
  for (let a = inicio.getTime(); a < fim.getTime(); a += JANELA) {
    const de = new Date(a), ate = new Date(Math.min(a + JANELA - 1, fim.getTime()));
    const filtro = encodeURIComponent(`creationDate:[${de.toISOString()} TO ${ate.toISOString()}]`);
    for (let p = 1, paginas = 1; p <= paginas && p <= 30; p++) {
      const d = await get(`${base}?per_page=100&page=${p}&orderBy=creationDate,desc&f_creationDate=${filtro}`);
      paginas = d.paging?.pages || 1;
      if (paginas > 30) console.warn(`Aviso: mais de 3000 pedidos entre ${de.toISOString()} e ${ate.toISOString()}; os mais antigos da janela ficaram de fora.`);
      (d.list || []).forEach(o => ids.add(o.orderId));
    }
  }
  const lista = [...ids];
  console.log(`${lista.length} pedidos na lista`);

  // 2) detalhe de cada pedido, só campos de análise (sem nome, telefone nem e-mail)
  const pedidos = [];
  for (let i = 0; i < lista.length; i += 5) {
    const lote = await Promise.all(lista.slice(i, i + 5).map(id => get(`${base}/${encodeURIComponent(id)}`)));
    for (const o of lote) {
      const total = id => (o.totals || []).find(t => t.id === id)?.value || 0;
      pedidos.push({
        id: o.orderId,
        data: o.creationDate,
        status: o.status,
        valor: (o.value || 0) / 100,
        frete: total("Shipping") / 100,
        desconto: Math.abs(total("Discounts")) / 100,
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
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(SENHA), "PBKDF2", false, ["deriveKey"]);
  const chave = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: 250000, hash: "SHA-256" }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const texto = JSON.stringify({ atualizado: new Date().toISOString(), inicio: inicio.toISOString(), pedidos });
  const cifrado = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, chave, new TextEncoder().encode(texto));

  mkdirSync("data", { recursive: true });
  writeFileSync("data/pedidos.enc.json", JSON.stringify({ salt: b64(salt), iv: b64(iv), dados: b64(new Uint8Array(cifrado)) }));
  console.log(`Gravado: ${pedidos.length} pedidos`);
}

main().catch(e => { console.error("Erro:", e.message); process.exit(1); });
