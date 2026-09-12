(()=>{
  'use strict';
  const $=(s,r=document)=>r.querySelector(s);const $$=(s,r=document)=>[...r.querySelectorAll(s)];
  const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const csrf=$('meta[name="csrf-token"]')?.content||'';
  async function postJson(url,body){const r=await fetch(url,{method:'POST',credentials:'same-origin',headers:{Accept:'application/json','Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify(body)});let d={ok:false,error:`HTTP ${r.status}`};try{d=await r.json()}catch{}return d}
  function safeName(name){name=String(name||'').trim();return /^[^\\/\x00]{1,180}$/.test(name)&&name!=='.'&&name!=='..'}
  function child(base,name){base=String(base||'').replace(/^\/+|\/+$/g,'');return [base,name].filter(Boolean).join('/')}

  $('#fileNewFile')?.addEventListener('click',async()=>{
    const domain=$('#fileDomain')?.value||'';if(!domain){alert('اختر موقعًا أولًا.');return}
    const name=prompt('اسم الملف الجديد، مثال index.html أو notes.txt:');if(name===null)return;
    if(!safeName(name)){alert('اسم الملف غير صالح. لا تستخدم / أو \\ أو ..');return}
    const path=child($('#filePath')?.value||'',name);
    const d=await postJson('/api/file/save',{domain,path,content:''});
    if(!d.ok){alert(d.error||'تعذر إنشاء الملف');return}
    $('#fileRefresh')?.click();
  });

  $$('.context-nav').forEach(button=>button.addEventListener('click',()=>{
    const view=button.dataset.contextView||'',domain=button.dataset.domain||'';
    const nav=$(`#nav a[href="#${CSS.escape(view)}"]`);if(!nav)return;nav.click();
    if(view==='files'){
      const select=$('#fileDomain');if(select&&[...select.options].some(o=>o.value===domain)){select.value=domain;select.dispatchEvent(new Event('change',{bubbles:true}))}
    }else if(view==='deploy'){
      const select=$('#deploy select[name="domain"]');if(select&&[...select.options].some(o=>o.value===domain)){select.value=domain;select.focus()}
    }
  }));

  const healthDialog=$('#healthDialog'),healthTitle=$('#healthTitle'),healthReport=$('#healthReport');
  function healthState(ok,text){return `<span class="health-state ${ok?'':'bad'}">${esc(text)}</span>`}
  function addresses(items,blocked=false){return (items||[]).map(ip=>`<span class="${blocked?'blocked':''}">${esc(ip)}</span>`).join('')}
  $$('.health-btn').forEach(button=>button.addEventListener('click',async()=>{
    const domain=button.dataset.domain||'';if(!domain||!healthDialog||!healthReport)return;
    healthTitle.textContent=`Health · ${domain}`;healthReport.innerHTML='<div class="health-loading">جاري فحص DNS وشهادة TLS وWeb Edge…</div>';healthDialog.showModal();
    try{
      const r=await fetch(`/api/site-health?domain=${encodeURIComponent(domain)}`,{credentials:'same-origin',headers:{Accept:'application/json'}});let d={ok:false,error:`HTTP ${r.status}`};try{d=await r.json()}catch{}
      if(!r.ok||!d.ok){healthReport.innerHTML=`<div class="health-loading">${esc(d.error||'تعذر إجراء الفحص')}</div>`;return}
      const dns=d.dns||{},tls=d.tls||{},http=tls.http||{};const days=tls.days_left;
      const tlsHealthy=Boolean(tls.ok)&&(days===null||days===undefined||Number(days)>=21);
      const httpReachable=Number(http.status||0)>0;
      const httpHealthy=httpReachable&&Number(http.status)<500;
      healthReport.innerHTML=`
        <article class="health-card"><div class="health-card-head"><b>DNS Resolution</b>${healthState(Boolean(dns.ok),'DNS '+(dns.ok?'READY':'FAILED'))}</div><dl class="health-kv"><dt>Latency</dt><dd>${esc(dns.latency_ms??0)} ms</dd><dt>Public IPs</dt><dd>${esc((dns.addresses||[]).length)}</dd><dt>Blocked IPs</dt><dd>${esc((dns.blocked||[]).length)}</dd></dl><div class="health-addresses">${addresses(dns.addresses)}${addresses(dns.blocked,true)}</div></article>
        <article class="health-card"><div class="health-card-head"><b>TLS Certificate</b>${healthState(tlsHealthy,tls.ok?(tlsHealthy?'TLS HEALTHY':'TLS WARNING'):'TLS FAILED')}</div><dl class="health-kv"><dt>Protocol</dt><dd>${esc(tls.protocol||'—')}</dd><dt>Days left</dt><dd>${days===null||days===undefined?'—':esc(days)}</dd><dt>Handshake</dt><dd>${esc(tls.latency_ms??'—')} ms</dd><dt>Probe IP</dt><dd>${esc(tls.ip||'—')}</dd></dl></article>
        <article class="health-card"><div class="health-card-head"><b>Web Edge</b>${healthState(httpHealthy,httpReachable?`HTTP ${http.status}`:'NO RESPONSE')}</div><dl class="health-kv"><dt>Status</dt><dd>${httpReachable?esc(http.status):'—'}</dd><dt>Latency</dt><dd>${esc(http.latency_ms??'—')} ms</dd><dt>HSTS</dt><dd>${http.hsts?'ENABLED':'NOT SEEN'}</dd><dt>Server</dt><dd>${esc(http.server||'—')}</dd><dt>Content-Type</dt><dd>${esc(http.content_type||'—')}</dd></dl></article>
        <article class="health-card"><div class="health-card-head"><b>Certificate Identity</b>${healthState(Boolean(tls.ok),'VERIFIED CONNECTION')}</div><dl class="health-kv"><dt>Subject</dt><dd>${esc(tls.subject||'—')}</dd><dt>Expires</dt><dd>${esc(tls.expires||'—')}</dd><dt>Cipher</dt><dd>${esc(tls.cipher||'—')}</dd><dt>Redirect</dt><dd>${esc(http.location||'—')}</dd>${tls.error?`<dt>Error</dt><dd>${esc(tls.error)}</dd>`:''}</dl></article>`;
    }catch(e){healthReport.innerHTML=`<div class="health-loading">${esc(e.message||'Health check failed')}</div>`}
  }));
  $('#closeHealth')?.addEventListener('click',()=>healthDialog?.close());

  const filterButtons=$$('.notification-filter'),rows=$$('#notificationList .notification-row'),empty=$('#notificationEmptyFilter');
  function applyNotificationFilter(mode){let visible=0;rows.forEach(row=>{const show=mode==='all'||(mode==='unread'&&row.dataset.read==='0')||(mode==='critical'&&row.dataset.level==='critical');row.classList.toggle('filter-hidden',!show);if(show)visible++});filterButtons.forEach(b=>b.classList.toggle('active',b.dataset.notificationFilter===mode));empty?.classList.toggle('hidden',visible!==0||rows.length===0)}
  filterButtons.forEach(b=>b.addEventListener('click',()=>applyNotificationFilter(b.dataset.notificationFilter||'all')));
})();
