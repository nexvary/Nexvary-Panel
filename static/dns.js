(()=>{
  'use strict';
  const root=document.getElementById('dns');if(!root)return;
  const $=(s,r=root)=>r.querySelector(s);const $$=(s,r=root)=>[...r.querySelectorAll(s)];
  const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const csrf=document.querySelector('meta[name="csrf-token"]')?.content||'';
  const stepUp=root.dataset.stepUp==='1';
  const domain=$('#dnsDomain'),button=$('#dnsInspect'),grid=$('#dnsGrid');
  const ddnsStatus=$('#ddnsStatus'),ddnsList=$('#ddnsList'),ddnsToken=$('#ddnsTokenReveal');

  const api=async(url,options={})=>{
    const opts={credentials:'same-origin',...options,headers:{Accept:'application/json',...(options.headers||{})}};
    if(opts.method&&opts.method!=='GET')opts.headers['X-CSRF-Token']=csrf;
    const res=await fetch(url,opts);let data={};try{data=await res.json()}catch{data={ok:false,error:`HTTP ${res.status}`};}
    if(!res.ok||data.ok===false){const err=new Error(data.error||`HTTP ${res.status}`);err.status=res.status;err.data=data;throw err;}return data;
  };
  const setDdnsStatus=(text,state='')=>{if(!ddnsStatus)return;ddnsStatus.textContent=text||'';ddnsStatus.className=`dns-ddns-status ${state}`.trim();};
  function setSummary(id,text,state=''){const el=$(id);if(!el)return;el.textContent=text;el.classList.remove('good','bad');if(state)el.classList.add(state)}
  function renderRecord(type,data){const card=$(`#dnsGrid [data-record-type="${type}"]`);if(!card)return;const head=$('.dns-record-head span',card),body=$('.dns-record-body',card),foot=$('footer',card);const records=data?.records||[];head.textContent=data?.ok===false?'FAILED':records.length?'READY':'EMPTY';head.className=data?.ok===false?'failed':records.length?'ready':'';body.innerHTML=records.length?records.map(v=>`<div class="dns-record-value">${esc(v)}</div>`).join(''):`<div class="dns-empty">${esc(data?.error||'لا توجد سجلات.')}</div>`;foot.innerHTML=`<span>TTL ${data?.ttl??'—'}</span><span>LATENCY ${data?.latency_ms??'—'} ms</span>`}

  async function inspect(){const value=domain?.value||'';if(!value||!grid)return;button.disabled=true;button.textContent='جاري الفحص…';$$('.dns-record-card').forEach(card=>{const head=$('.dns-record-head span',card),body=$('.dns-record-body',card);head.textContent='CHECKING';head.className='';body.innerHTML='<div class="dns-empty">جاري الاستعلام…</div>'});try{const r=await fetch(`/api/dns/inventory?domain=${encodeURIComponent(value)}`,{credentials:'same-origin',headers:{Accept:'application/json'}});let d={ok:false,error:`HTTP ${r.status}`};try{d=await r.json()}catch{}if(!r.ok||!d.ok)throw new Error(d.error||'DNS inventory failed');for(const type of ['A','AAAA','NS','MX','TXT','CAA'])renderRecord(type,d.record_types?.[type]||{});setSummary('#dnsPopulated',`${d.summary?.populated??0}/6`,(d.summary?.populated??0)>0?'good':'bad');setSummary('#dnsMxState',d.mail_posture?.mx_present?'PRESENT':'MISSING',d.mail_posture?.mx_present?'good':'bad');setSummary('#dnsDmarcState',d.mail_posture?.dmarc_present?'ENABLED':'MISSING',d.mail_posture?.dmarc_present?'good':'bad');const records=d.mail_posture?.dmarc?.records||[];$('#dnsDmarcRecord').textContent=records.length?records.join(' · '):(d.mail_posture?.dmarc?.error||'لا يوجد DMARC record ظاهر.')}catch(e){setSummary('#dnsPopulated','ERROR','bad');setSummary('#dnsMxState','—');setSummary('#dnsDmarcState','—');$('#dnsDmarcRecord').textContent=e.message||'DNS inventory failed'}finally{button.disabled=false;button.innerHTML='فحص DNS'}}

  function when(ts){if(!Number(ts))return 'لم يحدث بعد';try{return new Date(Number(ts)*1000).toLocaleString('ar-EG')}catch{return '—'}}
  function revealToken(id,token){if(!ddnsToken)return;const endpoint=`${location.origin}/api/dynamic-dns/update/${id}`;ddnsToken.hidden=false;ddnsToken.innerHTML=`<strong>احفظ الـToken الآن — لن يظهر مرة أخرى.</strong><code>${esc(token)}</code><small>POST ${esc(endpoint)} · Authorization: Bearer TOKEN · JSON: {"address":"PUBLIC_IP"}</small>`;}
  function renderDdns(rows){
    if(!ddnsList)return;
    if(!rows.length){ddnsList.innerHTML='<div class="dns-empty">لا توجد سجلات Dynamic DNS لهذا الموقع.</div>';return;}
    ddnsList.innerHTML=rows.map(row=>`<article class="dns-ddns-row"><div><b>${esc(row.hostname)}</b><span>${esc(row.record_type)} · TTL ${Number(row.ttl||0)}s</span></div><code>${esc(row.last_address||'—')}</code><small>${esc(when(row.last_update))}</small><div class="dns-ddns-actions"><button type="button" class="ghost" data-ddns-rotate="${row.id}" ${stepUp?'':'disabled'}>تدوير Token</button><button type="button" data-ddns-delete="${row.id}" ${stepUp?'':'disabled'}>حذف</button></div></article>`).join('');
  }
  async function loadDdns(){
    const value=domain?.value||'';if(!value){renderDdns([]);return;}
    ddnsToken.hidden=true;ddnsToken.textContent='';
    try{const data=await api(`/api/dynamic-dns/records?domain=${encodeURIComponent(value)}`);renderDdns(data.records||[]);setDdnsStatus(stepUp?'Dynamic DNS جاهز للتعديل.':'القراءة متاحة؛ فعّل Step-Up لإنشاء أو تدوير أو حذف السجلات.','ok');}
    catch(err){renderDdns([]);setDdnsStatus(err.status===403?'Dynamic DNS غير مفعّل لهذه الباقة أو النطاق.':err.message,'error');}
  }

  $('#ddnsForm')?.addEventListener('submit',async event=>{
    event.preventDefault();if(!stepUp){setDdnsStatus('Step-Up مطلوب قبل إنشاء Dynamic DNS.','error');return;}
    const value=domain?.value||'';if(!value){setDdnsStatus('اختر موقعًا أولًا.','error');return;}
    const fd=new FormData(event.currentTarget);const payload={domain:value,hostname:String(fd.get('hostname')||''),record_type:String(fd.get('record_type')||'A'),address:String(fd.get('address')||''),ttl:Number(fd.get('ttl')||300)};
    try{const data=await api('/api/dynamic-dns/records',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const token=data.token;event.currentTarget.reset();setDdnsStatus(`تم إنشاء ${data.hostname} وربطه بالمزوّد. احفظ الـToken المعروض الآن.`,'ok');await loadDdns();revealToken(data.id,token);}
    catch(err){setDdnsStatus(err.status===428?'انتهت نافذة Step-Up؛ أعد التحقق من Security.':err.message,'error');}
  });

  ddnsList?.addEventListener('click',async event=>{
    const rotate=event.target.closest('[data-ddns-rotate]');const del=event.target.closest('[data-ddns-delete]');if(!rotate&&!del)return;
    if(!stepUp){setDdnsStatus('Step-Up مطلوب لهذه العملية.','error');return;}
    try{
      if(rotate){const data=await api(`/api/dynamic-dns/records/${rotate.dataset.ddnsRotate}/rotate-token`,{method:'POST'});revealToken(data.id,data.token);setDdnsStatus('تم إبطال الـToken القديم وإصدار Token جديد.','ok');return;}
      await api(`/api/dynamic-dns/records/${del.dataset.ddnsDelete}`,{method:'DELETE'});setDdnsStatus('تم حذف سجل Dynamic DNS من المزوّد واللوحة.','ok');await loadDdns();
    }catch(err){setDdnsStatus(err.status===428?'انتهت نافذة Step-Up.':err.message,'error');}
  });

  button?.addEventListener('click',inspect);
  domain?.addEventListener('change',async()=>{if(domain.value)await Promise.all([inspect(),loadDdns()]);else renderDdns([])});
  if(domain?.value)loadDdns();
})();
