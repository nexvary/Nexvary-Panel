(()=>{
  'use strict';
  const $=(s,r=document)=>r.querySelector(s);const $$=(s,r=document)=>[...r.querySelectorAll(s)];
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

  // Keep site workflows connected: Files/Deploy actions carry the current domain into the target workspace.
  $$('.context-nav').forEach(button=>button.addEventListener('click',()=>{
    const view=button.dataset.contextView||'',domain=button.dataset.domain||'';
    const nav=$(`#nav a[href="#${CSS.escape(view)}"]`);if(!nav)return;nav.click();
    if(view==='files'){
      const select=$('#fileDomain');if(select&&[...select.options].some(o=>o.value===domain)){select.value=domain;select.dispatchEvent(new Event('change',{bubbles:true}))}
    }else if(view==='deploy'){
      const select=$('#deploy select[name="domain"]');if(select&&[...select.options].some(o=>o.value===domain)){select.value=domain;select.focus()}
    }
  }));

  const filterButtons=$$('.notification-filter'),rows=$$('#notificationList .notification-row'),empty=$('#notificationEmptyFilter');
  function applyNotificationFilter(mode){let visible=0;rows.forEach(row=>{const show=mode==='all'||(mode==='unread'&&row.dataset.read==='0')||(mode==='critical'&&row.dataset.level==='critical');row.classList.toggle('filter-hidden',!show);if(show)visible++});filterButtons.forEach(b=>b.classList.toggle('active',b.dataset.notificationFilter===mode));empty?.classList.toggle('hidden',visible!==0||rows.length===0)}
  filterButtons.forEach(b=>b.addEventListener('click',()=>applyNotificationFilter(b.dataset.notificationFilter||'all')));
})();
