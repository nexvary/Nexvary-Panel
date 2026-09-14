(()=>{
  const root=document.getElementById('domainGuardianCard');if(!root)return;
  const csrf=document.querySelector('meta[name="csrf-token"]')?.content||'';
  const $=s=>root.querySelector(s);
  const api=async(url,opt={})=>{const headers={Accept:'application/json',...(opt.headers||{})};if(opt.method&&opt.method!=='GET')headers['X-CSRF-Token']=csrf;if(opt.body&&!headers['Content-Type'])headers['Content-Type']='application/json';const r=await fetch(url,{credentials:'same-origin',...opt,headers});let b={};try{b=await r.json()}catch{}if(!r.ok||b.ok===false)throw Object.assign(new Error(b.error||`HTTP ${r.status}`),{status:r.status});return b};
  const text=(id,value)=>{const el=$(id);if(el)el.textContent=String(value??'—')};
  const severityLabel=s=>String(s||'info').toUpperCase();
  function renderPlan(plan){
    const box=$('#guardianPlan');box.replaceChildren();
    if(!Array.isArray(plan)||!plan.length){const e=document.createElement('div');e.className='empty-state';e.textContent='لا توجد توصيات؛ النطاق في وضع قوي.';box.append(e);return}
    plan.forEach(item=>{const row=document.createElement('div');row.className='adv-row';const main=document.createElement('div');main.className='adv-row-main';const title=document.createElement('strong');title.textContent=item.id;const detail=document.createElement('span');detail.textContent=item.message||'';main.append(title,detail);const meta=document.createElement('div');meta.className='adv-row-actions';const badge=document.createElement('span');badge.className='adv-chip';badge.textContent=`${severityLabel(item.severity)} · ${String(item.mode||'review').toUpperCase()}`;meta.append(badge);row.append(main,meta);box.append(row)})
  }
  function renderGuardian(g){
    text('#guardianScore',`${Number(g?.score||0)}/100`);text('#guardianState',String(g?.state||'unknown').toUpperCase());text('#guardianSafeCount',Number(g?.safe_prepare_count||0));renderPlan(g?.plan||[]);
    const safety=g?.safety||{};const ready=g?.readiness||{};const mail=g?.deliverability;
    const parts=[`Readiness ${ready.score??'—'}/100`,`Change Safety ${safety.score??'—'}/100`];if(mail)parts.push(`Mail ${mail.score??'—'}/100`);parts.push(g?.live_checks?'LIVE DNS CHECKS':'CONTROL-PLANE ONLY');text('#guardianNotice',parts.join(' · '));
  }
  async function loadDomains(){
    const d=await api('/api/domain-health');const select=$('#guardianDomain');const current=select.value;select.replaceChildren();const placeholder=document.createElement('option');placeholder.value='';placeholder.textContent='اختر نطاقًا…';select.append(placeholder);(d.domains||[]).forEach(item=>{const o=document.createElement('option');o.value=item.domain;o.textContent=item.owner&&item.owner!=='admin'?`${item.domain} · ${item.owner}`:item.domain;select.append(o)});if((d.domains||[]).some(x=>x.domain===current))select.value=current;
  }
  async function analyze(){
    const domain=$('#guardianDomain').value;const selector=$('#guardianSelector').value.trim()||'default';if(!domain)throw new Error('اختر نطاقًا أولًا');text('#guardianNotice','جاري جمع Readiness وDNS وSSL وMail وChange Safety…');const d=await api(`/api/domain-guardian?domain=${encodeURIComponent(domain)}&selector=${encodeURIComponent(selector)}&live=1`);renderGuardian(d.guardian);return d.guardian;
  }
  $('#guardianDomain')?.addEventListener('change',()=>{const d=$('#guardianDomain').value;if(d&&!$('#guardianMailHost').value)$('#guardianMailHost').value=`mail.${d}`});
  $('#guardianAnalyzeBtn')?.addEventListener('click',async()=>{try{await analyze()}catch(e){text('#guardianNotice',e.message)}});
  $('#guardianPrepareBtn')?.addEventListener('click',async()=>{try{const domain=$('#guardianDomain').value;if(!domain)throw new Error('اختر نطاقًا أولًا');const payload={domain,selector:$('#guardianSelector').value.trim()||'default',contact_email:$('#guardianEmail').value.trim(),mail_host:$('#guardianMailHost').value.trim()||`mail.${domain}`,mail_ipv4:$('#guardianMailIpv4').value.trim()};const d=await api('/api/domain-guardian/prepare',{method:'POST',body:JSON.stringify(payload)});const prepared=(d.prepared||[]).map(x=>x.id).join(', ')||'none';const skipped=(d.skipped||[]).map(x=>`${x.id}: ${x.reason}`).join(' | ');text('#guardianNotice',`SAFE PREPARE · ${prepared}${skipped?` · skipped ${skipped}`:''} · لا توجد تغييرات DNS خارجية.`);await analyze()}catch(e){text('#guardianNotice',e.status===428?'Step-Up مطلوب قبل Safe Prepare.':e.message)}});
  loadDomains().catch(e=>text('#guardianNotice',`Domain Guardian unavailable: ${e.message}`));
})();
