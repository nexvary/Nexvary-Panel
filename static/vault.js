(()=>{
  'use strict';
  const $=(s,r=document)=>r.querySelector(s);
  const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const csrf=()=>document.querySelector('meta[name="csrf-token"]')?.content||'';
  const grid=$('#vaultGrid');
  const message=$('#vaultMessage');
  const form=$('#vaultPutForm');

  function setMessage(text,kind=''){
    if(!message)return;
    message.textContent=text||'';
    message.className=`vault-message ${kind}`.trim();
  }

  function fmt(ts){
    if(!ts)return '—';
    try{return new Date(Number(ts)*1000).toLocaleString('ar-EG')}catch{return '—'}
  }

  function card(row){
    const id=esc(row.id);const kind=esc(row.kind);const bytes=Number(row.bytes||0);
    return `<article class="vault-card royal-frame" data-vault-id="${id}" data-vault-kind="${kind}">
      <div class="vault-card-head"><div><small>${kind.toUpperCase()}</small><b>${id}</b></div><span class="vault-sealed">SEALED</span></div>
      <div class="vault-card-meta"><span>${bytes} bytes</span><span>${esc(fmt(row.updated_at))}</span></div>
      <button type="button" class="danger-action vault-delete" data-id="${id}" data-kind="${kind}">حذف الاعتماد</button>
    </article>`;
  }

  async function loadVault(){
    if(!grid)return;
    grid.innerHTML='<div class="vault-loading royal-frame">جاري قراءة Metadata…</div>';
    try{
      const r=await fetch('/api/vault/metadata',{credentials:'same-origin',headers:{Accept:'application/json'}});
      let d={ok:false,error:`HTTP ${r.status}`};try{d=await r.json()}catch{}
      if(!r.ok||!d.ok){grid.innerHTML=`<div class="vault-loading royal-frame">${esc(d.error||'Vault unavailable')}</div>`;return}
      const rows=Array.isArray(d.entries)?d.entries:[];
      grid.innerHTML=rows.length?rows.map(card).join(''):'<div class="vault-loading royal-frame">لا توجد اعتمادات محفوظة بعد.</div>';
      grid.querySelectorAll('.vault-delete').forEach(btn=>btn.addEventListener('click',deleteSecret));
    }catch(e){grid.innerHTML=`<div class="vault-loading royal-frame">${esc(e.message||'Vault unavailable')}</div>`}
  }

  async function deleteSecret(ev){
    const btn=ev.currentTarget;const id=btn.dataset.id||'';const kind=btn.dataset.kind||'';
    if(!confirm(`حذف ${kind}:${id} من Secret Vault؟`))return;
    btn.disabled=true;setMessage('جاري حذف الاعتماد…');
    try{
      const r=await fetch('/api/vault/delete',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf(),Accept:'application/json'},body:JSON.stringify({id,kind})});
      let d={ok:false,error:`HTTP ${r.status}`};try{d=await r.json()}catch{}
      if(r.status===428){setMessage('يلزم تفعيل Step-Up من مركز الأمان أولًا.','error');return}
      if(!r.ok||!d.ok){setMessage(d.error||'فشل حذف الاعتماد.','error');return}
      setMessage('تم حذف الاعتماد من الخزنة.','ok');await loadVault();
    }catch(e){setMessage(e.message||'فشل الاتصال بالخزنة.','error')}finally{btn.disabled=false}
  }

  form?.addEventListener('submit',async ev=>{
    ev.preventDefault();
    const id=$('#vaultId')?.value.trim()||'';const kind=$('#vaultKind')?.value||'';const value=$('#vaultValue')?.value||'';
    setMessage('جاري إغلاق الاعتماد داخل الخزنة…');
    const submit=form.querySelector('button[type="submit"]');if(submit)submit.disabled=true;
    try{
      const r=await fetch('/api/vault/put',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf(),Accept:'application/json'},body:JSON.stringify({id,kind,value})});
      let d={ok:false,error:`HTTP ${r.status}`};try{d=await r.json()}catch{}
      if(r.status===428){setMessage('يلزم تفعيل Step-Up من مركز الأمان أولًا.','error');return}
      if(!r.ok||!d.ok){setMessage(d.error||'فشل حفظ الاعتماد.','error');return}
      const valueEl=$('#vaultValue');if(valueEl)valueEl.value='';
      setMessage('تم حفظ الاعتماد. لن تعرض اللوحة قيمته مرة أخرى.','ok');await loadVault();
    }catch(e){setMessage(e.message||'فشل الاتصال بالخزنة.','error')}finally{if(submit)submit.disabled=false}
  });

  $('#vaultRefresh')?.addEventListener('click',loadVault);
  $('#nav a[href="#vault"]')?.addEventListener('click',()=>setTimeout(loadVault,50));
  if(location.hash==='#vault')loadVault();
})();
