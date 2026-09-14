(()=>{
  const root=document.getElementById('mail');
  if(!root)return;
  const domainSelect=root.querySelector('#mailTraceDomain');
  const refresh=root.querySelector('#mailTraceRefresh');
  const list=root.querySelector('#mailTraceList');
  const status=root.querySelector('#mailTraceStatus');
  if(!domainSelect||!refresh||!list||!status)return;
  const esc=value=>String(value??'').replace(/[&<>'"]/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[ch]));
  const setStatus=(message,type='')=>{status.textContent=message;status.className=`mail-status ${type}`.trim();};
  const api=async url=>{
    const response=await fetch(url,{credentials:'same-origin',headers:{Accept:'application/json'}});
    let data={};
    try{data=await response.json();}catch{data={ok:false,error:`HTTP ${response.status}`};}
    if(!response.ok||data.ok===false){const error=new Error(data.error||`HTTP ${response.status}`);error.status=response.status;throw error;}
    return data;
  };
  const address=value=>value?esc(value):'<span class="mail-trace-empty">—</span>';
  function render(events){
    if(!events.length){list.innerHTML='<div class="empty-state">لا توجد أحداث تسليم ضمن نافذة السجل الحالية لهذا النطاق.</div>';return;}
    list.innerHTML=events.map(event=>`<div class="mail-row mail-trace-row">
      <div class="mail-row-main"><strong>${address(event.sender)} → ${address(event.recipient)}</strong><span>${esc(event.timestamp)} · ${esc(event.component||'postfix')}</span></div>
      <div class="mail-row-meta"><b>${esc((event.status||'event').toUpperCase())}</b><small>DSN ${esc(event.dsn||'—')} · ${esc(event.relay||'local')}</small></div>
      <div class="mail-trace-detail"><code>${esc(event.queue_id||'—')}</code><small>${esc(event.detail||'')}</small></div>
    </div>`).join('');
  }
  async function loadDomains(){
    try{
      const data=await api('/api/mail');
      const domains=(data.available_domains||[]).map(item=>String(item.domain||'')).filter(Boolean);
      domainSelect.innerHTML='<option value="">اختر نطاقًا…</option>'+domains.map(domain=>`<option value="${esc(domain)}">${esc(domain)}</option>`).join('');
      refresh.disabled=!domains.length;
    }catch(error){setStatus(`تعذر تحميل نطاقات Track Delivery: ${error.message}`,'error');refresh.disabled=true;}
  }
  async function trace(){
    const domain=domainSelect.value;
    if(!domain){setStatus('اختر نطاقًا أولًا.','error');return;}
    refresh.disabled=true;setStatus('جاري قراءة أحدث أحداث Postfix لهذا النطاق…');
    try{
      const data=await api(`/api/mail/trace?domain=${encodeURIComponent(domain)}&limit=100`);
      render(data.events||[]);
      setStatus(`تم تحميل ${Number(data.count||0)} حدث · المصدر ${data.source||'mail provider'}`,'ok');
    }catch(error){render([]);setStatus(error.status===503?'Mail Provider أو سجل Postfix غير متاح حاليًا.':error.message,'error');}
    finally{refresh.disabled=false;}
  }
  refresh.addEventListener('click',trace);
  domainSelect.addEventListener('change',()=>{render([]);setStatus('');});
  loadDomains();
})();
