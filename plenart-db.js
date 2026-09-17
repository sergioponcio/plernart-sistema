/* =====================================================================
   PLENART — camada de banco (Supabase)

   Um arquivo só, usado pelo hub e pelos dois orçamentos. É aqui que
   mora TODA a conversa com o banco: login, sessão, gravar, ler, listar,
   excluir, e a cópia de segurança local para quando a internet cair.

   As telas não falam com o Supabase direto — elas chamam PlenartDB.
   Se um dia o banco mudar, muda só este arquivo.
   ===================================================================== */
(function () {
'use strict';

const CFG = {
    url: 'https://itdqljiixaazffgbkmiv.supabase.co',
    // chave pública (publishable). Pode ficar no arquivo: sozinha não dá
    // acesso a nada — quem controla é o RLS, dentro do banco.
    chave: 'sb_publishable_x5SEF7y5ca4Z8LWYpx0E3g_HZ6p0cUo'
};

const K_SESSAO = 'plenart_sessao';        // token do login
const K_LOCAL  = 'plenart_local';         // cópia de segurança dos orçamentos
const K_ANTIGO = 'plenart_orcamentos';    // onde ficavam os orçamentos antes do banco

let sessao = null;        // { access_token, refresh_token, expira_em, perfil }
let ouvintes = [];

/* ---------------------------------------------------------------
   utilitários
   --------------------------------------------------------------- */
function lerJSON(chave, padrao) {
    try { const v = localStorage.getItem(chave); return v ? JSON.parse(v) : padrao; } catch (e) { return padrao; }
}
function gravarJSON(chave, valor) {
    try { localStorage.setItem(chave, JSON.stringify(valor)); return true; } catch (e) { return false; }
}
function vazioNull(v) { const s = (v == null ? '' : String(v)).trim(); return s === '' ? null : s; }
function avisar() { ouvintes.forEach(f => { try { f(sessao && sessao.perfil); } catch (e) {} }); }

/* ---------------------------------------------------------------
   chamada crua
   --------------------------------------------------------------- */
const ESPERA_MAXIMA = 25000;   // 25s: se o banco não responder, é melhor avisar do que ficar pendurado

async function bruto(caminho, opc) {
    opc = opc || {};
    const cab = { 'apikey': CFG.chave, 'Content-Type': 'application/json' };
    if (opc.token) cab['Authorization'] = 'Bearer ' + opc.token;
    if (opc.prefer) cab['Prefer'] = opc.prefer;
    let resp, texto;
    const corta = (typeof AbortController !== 'undefined') ? new AbortController() : null;
    const relogio = corta ? setTimeout(() => corta.abort(), ESPERA_MAXIMA) : null;
    try {
        resp = await fetch(CFG.url + caminho, {
            method: opc.metodo || 'GET',
            headers: cab,
            body: opc.corpo === undefined ? undefined : JSON.stringify(opc.corpo),
            signal: corta ? corta.signal : undefined
        });
        texto = await resp.text();
    } catch (e) {
        const demorou = e && (e.name === 'AbortError');
        return { semRede: true, expirou: demorou, msg: demorou ? 'o banco demorou demais para responder' : ((e && e.message) || String(e)) };
    } finally {
        if (relogio) clearTimeout(relogio);
    }
    let dados = null;
    try { dados = texto ? JSON.parse(texto) : null; } catch (e) { dados = texto; }
    return { status: resp.status, ok: resp.ok, dados, contentRange: resp.headers.get('content-range') };
}

function mensagemDe(r) {
    if (r.semRede) return 'sem conexão';
    const d = r.dados || {};
    return d.message || d.msg || d.error_description || d.error || ('erro ' + r.status);
}

/* chamada já logada, renovando o token quando precisa */
async function comLogin(caminho, opc) {
    if (!sessao) return { status: 401, ok: false, dados: { message: 'não está logado' } };
    if (Date.now() > sessao.expira_em - 60000) { await renovar(); }
    if (!sessao) return { status: 401, ok: false, dados: { message: 'sessão expirada' } };
    const r = await bruto(caminho, Object.assign({}, opc, { token: sessao.access_token }));
    if (r.status === 401 && !r.semRede) {                 // token vencido no meio do caminho
        const ok = await renovar();
        if (ok) return bruto(caminho, Object.assign({}, opc, { token: sessao.access_token }));
    }
    return r;
}

/* ---------------------------------------------------------------
   sessão
   --------------------------------------------------------------- */
function guardarSessao(d, perfil) {
    sessao = {
        access_token: d.access_token,
        refresh_token: d.refresh_token,
        expira_em: Date.now() + ((d.expires_in || 3600) * 1000),
        perfil: perfil || (sessao && sessao.perfil) || null
    };
    gravarJSON(K_SESSAO, sessao);
    avisar();
}

async function renovar() {
    const guardada = sessao || lerJSON(K_SESSAO, null);
    if (!guardada || !guardada.refresh_token) { encerrar(); return false; }
    const r = await bruto('/auth/v1/token?grant_type=refresh_token', { metodo: 'POST', corpo: { refresh_token: guardada.refresh_token } });
    if (r.semRede) return false;                           // sem internet: mantém o que tem
    if (!r.ok || !r.dados || !r.dados.access_token) { encerrar(); return false; }
    guardarSessao(r.dados, guardada.perfil);
    return true;
}

function encerrar() { sessao = null; try { localStorage.removeItem(K_SESSAO); } catch (e) {} avisar(); }

async function buscarPerfil(nomeSugerido) {
    const r = await comLogin('/rest/v1/rpc/garantir_perfil', { metodo: 'POST', corpo: { p_nome: nomeSugerido || null } });
    if (r.ok && r.dados && r.dados.id) return r.dados;
    if (r.ok && Array.isArray(r.dados) && r.dados[0]) return r.dados[0];
    return null;
}

const API = {

    configurado: () => !!(CFG.url && CFG.chave),
    url: () => CFG.url,

    /* ---------- login ---------- */
    async entrar(email, senha) {
        const r = await bruto('/auth/v1/token?grant_type=password', {
            metodo: 'POST', corpo: { email: String(email || '').trim(), password: senha || '' }
        });
        if (r.semRede) return { ok: false, msg: 'Não consegui falar com o banco (' + r.msg + '). Verifique a internet.' };
        if (!r.ok || !r.dados || !r.dados.access_token) {
            const m = mensagemDe(r);
            return { ok: false, msg: /invalid login credentials/i.test(m) ? 'E-mail ou senha não conferem.' : m };
        }
        guardarSessao(r.dados, null);
        const perfil = await buscarPerfil();
        if (!perfil) { encerrar(); return { ok: false, msg: 'Entrou, mas não achei seu cadastro no sistema. Fale com o administrador.' }; }
        if (perfil.ativo === false) { encerrar(); return { ok: false, msg: 'Seu acesso está desativado. Fale com o administrador.' }; }
        guardarSessao({ access_token: sessao.access_token, refresh_token: sessao.refresh_token, expires_in: (sessao.expira_em - Date.now()) / 1000 }, perfil);
        return { ok: true, perfil };
    },

    sair() { encerrar(); },

    /* quem está logado agora (sem ir ao servidor) */
    quem() { return sessao && sessao.perfil ? sessao.perfil : null; },
    logado() { return !!(sessao && sessao.perfil); },
    ehAdmin() { return !!(sessao && sessao.perfil && sessao.perfil.admin); },

    /* recupera a sessão gravada; devolve o perfil ou null */
    async retomar() {
        const guardada = lerJSON(K_SESSAO, null);
        if (!guardada || !guardada.access_token) return null;
        sessao = guardada;
        if (Date.now() > sessao.expira_em - 60000) {
            const ok = await renovar();
            if (!ok && !sessao) return null;
        }
        if (!sessao.perfil) {
            const p = await buscarPerfil();
            if (!p) { encerrar(); return null; }
            sessao.perfil = p; gravarJSON(K_SESSAO, sessao);
        }
        avisar();
        return sessao.perfil;
    },

    aoMudarSessao(fn) { ouvintes.push(fn); },

    /* manda para a tela de login, guardando para onde voltar */
    exigirLogin(paginaLogin) {
        const destino = location.href;
        location.href = (paginaLogin || 'plenart-sistema.html') + '?voltar=' + encodeURIComponent(destino);
    },

    /* ---------- pessoas ---------- */
    async perfis() {
        const r = await comLogin('/rest/v1/perfis?select=id,nome,email,admin,ativo,criado_em&order=nome.asc');
        return r.ok && Array.isArray(r.dados) ? r.dados : [];
    },
    async atualizarPerfil(id, campos) {
        const r = await comLogin('/rest/v1/perfis?id=eq.' + encodeURIComponent(id), {
            metodo: 'PATCH', prefer: 'return=representation', corpo: campos
        });
        return r.ok ? { ok: true, perfil: Array.isArray(r.dados) ? r.dados[0] : r.dados } : { ok: false, msg: mensagemDe(r) };
    },

    /* ---------- orçamentos ---------- */

    /* lista sem trazer o orçamento inteiro (só o que a tabela mostra) */
    async listar(opc) {
        opc = opc || {};
        const campos = 'id,tipo,numero,cliente,evento,data_inicio,data_termino,status,total,criado_por,criado_por_nome,criado_em,atualizado_por,atualizado_por_nome,atualizado_em,versao';
        let q = '/rest/v1/orcamentos?select=' + campos + '&order=atualizado_em.desc&limit=' + (opc.limite || 500);
        if (opc.tipo) q += '&tipo=eq.' + encodeURIComponent(opc.tipo);
        const r = await comLogin(q);
        if (r.semRede) return { ok: false, semRede: true, lista: [] };
        if (!r.ok) return { ok: false, msg: mensagemDe(r), lista: [] };
        return { ok: true, lista: Array.isArray(r.dados) ? r.dados : [] };
    },

    /* traz o orçamento completo */
    async carregar(id) {
        const r = await comLogin('/rest/v1/orcamentos?select=*&id=eq.' + encodeURIComponent(id));
        if (r.semRede) {
            const l = API.lerLocal(id);
            return l ? { ok: true, deLocal: true, state: l.state, versao: l.versao, linha: null } : { ok: false, semRede: true };
        }
        if (!r.ok) return { ok: false, msg: mensagemDe(r) };
        const linha = Array.isArray(r.dados) ? r.dados[0] : null;
        if (!linha) return { ok: false, naoExiste: true };
        return { ok: true, state: linha.dados, versao: linha.versao, linha };
    },

    /* grava. versaoConhecida = a versão que esta tela tinha ao carregar.
       null/undefined = orçamento novo, ainda não está no banco. */
    async salvar(state, versaoConhecida) {
        const perfil = API.quem();
        if (!perfil) return { ok: false, precisaLogin: true, msg: 'Sessão encerrada. Entre de novo.' };

        API.guardarLocal(state, versaoConhecida, false, 'erro');  // cópia de segurança ANTES de tentar a rede

        const e = state.evento || {};
        const meta = state.meta || {};
        const linha = {
            id: state.id,
            tipo: state.tipo,
            numero: vazioNull(e.numOrc),
            cliente: vazioNull(e.cliente || e.unidade),
            evento: vazioNull(e.nome),
            data_inicio: vazioNull(e.dataInicio),
            data_termino: vazioNull(e.dataTermino),
            local: vazioNull(e.local),
            status: meta.status || 'Rascunho',
            total: Number(meta.total) || 0,
            dados: state,
            atualizado_por: perfil.id,
            atualizado_por_nome: perfil.nome
        };

        let r;
        if (versaoConhecida == null) {
            linha.criado_por = perfil.id;
            linha.criado_por_nome = perfil.nome;   // o dono da linha é quem está gravando: o nome tem que ser o do cadastro
            r = await comLogin('/rest/v1/orcamentos', { metodo: 'POST', prefer: 'return=representation', corpo: linha });
            if (!r.semRede && r.status === 409) {                 // já existia: vira alteração
                return API.salvar(state, (await API.versaoAtual(state.id)) || 1);
            }
        } else {
            r = await comLogin('/rest/v1/orcamentos?id=eq.' + encodeURIComponent(state.id) + '&versao=eq.' + versaoConhecida, {
                metodo: 'PATCH', prefer: 'return=representation', corpo: linha
            });
            if (!r.semRede && r.ok && Array.isArray(r.dados) && r.dados.length === 0) {
                const atual = await API.carregar(state.id);       // ninguém bateu: outra pessoa alterou antes
                if (atual.ok) {
                    API.guardarLocal(state, versaoConhecida, false, 'conflito');
                    return { ok: false, conflito: true, versaoNova: atual.versao, linha: atual.linha,
                             msg: (atual.linha && atual.linha.atualizado_por_nome ? atual.linha.atualizado_por_nome : 'Outra pessoa') + ' alterou este orçamento depois que você abriu.' };
                }
                if (atual.naoExiste) return { ok: false, apagado: true, msg: 'Este orçamento foi excluído por outra pessoa.' };
            }
        }

        if (r.semRede) {
            API.guardarLocal(state, versaoConhecida, false, 'semRede');
            return { ok: false, semRede: true, msg: 'Sem conexão — guardei uma cópia neste computador e sincronizo quando voltar.' };
        }
        if (!r.ok) return { ok: false, msg: mensagemDe(r) };

        const gravada = Array.isArray(r.dados) ? r.dados[0] : r.dados;
        const versao = gravada ? gravada.versao : (versaoConhecida || 1);
        API.guardarLocal(state, versao, true);
        return { ok: true, versao, linha: gravada };
    },

    async versaoAtual(id) {
        const r = await comLogin('/rest/v1/orcamentos?select=versao&id=eq.' + encodeURIComponent(id));
        return r.ok && Array.isArray(r.dados) && r.dados[0] ? r.dados[0].versao : null;
    },

    async excluir(id) {
        const r = await comLogin('/rest/v1/orcamentos?id=eq.' + encodeURIComponent(id), { metodo: 'DELETE', prefer: 'return=representation' });
        if (r.semRede) return { ok: false, msg: 'Sem conexão.' };
        if (!r.ok) return { ok: false, msg: mensagemDe(r) };
        if (Array.isArray(r.dados) && r.dados.length === 0) return { ok: false, msg: 'Você não pode excluir um orçamento de outra pessoa.' };
        API.esquecerLocal(id);
        return { ok: true };
    },

    /* avisa se o número já existe em outro orçamento do mesmo tipo */
    async numeroRepetido(tipo, numero, idAtual) {
        const n = vazioNull(numero); if (!n) return null;
        const r = await comLogin('/rest/v1/orcamentos?select=id,numero,cliente,criado_por_nome&tipo=eq.' + encodeURIComponent(tipo) + '&numero=eq.' + encodeURIComponent(n) + '&limit=5');
        if (!r.ok || !Array.isArray(r.dados)) return null;
        const outro = r.dados.find(o => o.id !== idAtual);
        return outro || null;
    },

    /* ---------- cópia de segurança neste computador ----------
       motivo diz por que ainda não subiu:
         'semRede'  → dá para reenviar sozinho quando a internet voltar
         'conflito' → NÃO reenviar: outra pessoa alterou, quem decide é o usuário
         'erro'     → falhou por outro motivo; fica guardado, mas não se reenvia sozinho */
    guardarLocal(state, versao, sincronizado, motivo) {
        const m = lerJSON(K_LOCAL, {});
        m[state.id] = {
            state, versao: versao == null ? null : versao,
            sincronizado: !!sincronizado, motivo: sincronizado ? null : (motivo || null),
            gravadoEm: new Date().toISOString()
        };
        gravarJSON(K_LOCAL, m);
    },
    lerLocal(id) { return lerJSON(K_LOCAL, {})[id] || null; },
    esquecerLocal(id) { const m = lerJSON(K_LOCAL, {}); delete m[id]; gravarJSON(K_LOCAL, m); },
    /* só o que ficou para trás por falta de internet entra no reenvio automático */
    pendentes() {
        const m = lerJSON(K_LOCAL, {});
        return Object.keys(m).filter(id => !m[id].sincronizado && m[id].motivo === 'semRede').map(id => m[id]);
    },
    /* tudo que está guardado aqui e ainda não subiu, inclusive conflitos */
    naoSincronizados() {
        const m = lerJSON(K_LOCAL, {});
        return Object.keys(m).filter(id => !m[id].sincronizado).map(id => m[id]);
    },

    /* tenta subir o que ficou pendente por falta de internet */
    async sincronizarPendentes() {
        const lista = API.pendentes(); let subiram = 0, falharam = 0;
        for (const p of lista) {
            const r = await API.salvar(p.state, p.versao);
            if (r.ok) subiram++; else falharam++;
        }
        return { subiram, falharam };
    },

    /* ---------- importar o que já está gravado neste navegador ---------- */
    lerAntigos() {
        const m = lerJSON(K_ANTIGO, {});
        const lista = Object.keys(m).map(id => m[id]).filter(o => o && o.id && o.tipo);
        // rascunhos do modelo mais antigo ainda (uma chave por tipo)
        ['plenart', 'sesc'].forEach(tipo => {
            const r = lerJSON('plenart_rascunho_' + tipo, null);
            if (!r || !r.evento) return;
            const temAlgo = (r.itens && r.itens.length) || r.evento.nome || r.evento.cliente || r.evento.unidade || r.evento.numOrc;
            if (!temAlgo) return;
            r.id = r.id || ('velho_' + tipo); r.tipo = r.tipo || tipo;
            r.meta = r.meta || {}; r.meta.status = r.meta.status || 'Rascunho';
            if (!lista.some(o => o.id === r.id)) lista.push(r);
        });
        return lista;
    },
    async importarAntigos(aoAndar) {
        const antigos = API.lerAntigos();
        if (!antigos.length) return { total: 0, subiram: 0, jaExistiam: 0, falharam: 0, erros: [] };
        const r = await comLogin('/rest/v1/orcamentos?select=id&limit=2000');
        const jaNoBanco = new Set((r.ok && Array.isArray(r.dados) ? r.dados : []).map(o => o.id));
        let subiram = 0, jaExistiam = 0, falharam = 0; const erros = [];
        for (let i = 0; i < antigos.length; i++) {
            const o = antigos[i];
            if (aoAndar) aoAndar(i + 1, antigos.length, o);
            if (jaNoBanco.has(o.id)) { jaExistiam++; continue; }
            const res = await API.salvar(o, null);
            if (res.ok) subiram++; else { falharam++; erros.push((o.evento && o.evento.numOrc ? 'nº ' + o.evento.numOrc : o.id) + ': ' + (res.msg || 'erro')); }
        }
        return { total: antigos.length, subiram, jaExistiam, falharam, erros };
    }
};

window.PlenartDB = API;
})();
