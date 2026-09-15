(()=>{
  const root=document.getElementById('services');
  if(!root) return;
  const role=root.dataset.role||'';
  const stepUp=root.dataset.stepUp==='1';
  const csrf=document.querySelector('meta[name="csrf-token"]')?.content||'';
  const button=document.getElementById('doctorRemediationBtn');
  const box=document.getElementById('doctorRemediationReport');
  const state=document.getElementById('doctorRemediationState');
  const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

  async function api(url,options={}){
    const opts={credentials:'same-origin',...options,headers:{Accept:'application/json',...(options.headers||{})}};
    if(opts.method&&opts.method!=='GET'){
      opts.headers['X-CSRF-Token']=csrf;
      opts.headers['Content-Type']='application/json';
    }
    const response=await fetch(url,opts);
    let data={ok:false,error:`HTTP ${response.status}`};
    try{data=await response.json();}catch{}
    if(!response.ok){const error=new Error(data.error||`HTTP ${response.status}`);error.status=response.status;throw error;}
    return data;
  }

  function render(plan){
    if(!box) return;
    if(!plan.length){
      box.innerHTML='<div class="empty-state"><b>لا توجد إصلاحات مطلوبة</b><small>كل فحوص Doctor الحالية سليمة أو لا تحتاج إجراءً.</small></div>';
      return;
    }
    box.innerHTML=plan.map(item=>{
      const canFix=item.safe&&role==='admin';
      const disabled=!canFix||!stepUp;
      const label=item.safe?'SAFE FIX':'MANUAL';
      const buttonHtml=item.safe
        ? `<button type="button" class="ghost compact-action" data-doctor-fix="${esc(item.check)}" ${disabled?'disabled':''}>${stepUp&&canFix?'تنفيذ الإصلاح الآمن':'Step-Up مطلوب'}</button>`
        : '';
      return `<article class="doctor-item ${item.safe?'doctor-warn':'doctor-manual'}"><span>${item.safe?'↻':'!'}</span><div><b>${esc(item.check)}</b><small>${esc(item.detail)}</small><small>${esc(item.reason)}</small><em>${label}${item.service?` · ${esc(item.service)}`:''}</em>${buttonHtml}</div></article>`;
    }).join('');
    box.querySelectorAll('[data-doctor-fix]').forEach(btn=>btn.addEventListener('click',()=>applyFix(btn.dataset.doctorFix,btn)));
  }

  async function preview(){
    if(!box||!state) return;
    state.textContent='SCANNING';
    box.innerHTML='<div class="empty-state">جاري بناء خطة الإصلاح الآمنة…</div>';
    try{
      const data=await api('/api/doctor/remediation-preview');
      render(data.remediation||[]);
      const count=(data.remediation||[]).filter(x=>x.safe).length;
      state.textContent=count?`${count} SAFE FIX${count===1?'':'ES'}`:'NO SAFE FIX';
    }catch(error){
      box.innerHTML=`<div class="empty-state"><b>تعذر تحليل الإصلاحات</b><small>${esc(error.message)}</small></div>`;
      state.textContent='FAILED';
    }
  }

  async function applyFix(check,btn){
    if(role!=='admin'||!stepUp) return;
    btn.disabled=true;
    const old=btn.textContent;
    btn.textContent='VERIFYING…';
    try{
      const data=await api('/api/doctor/remediate',{method:'POST',body:JSON.stringify({check})});
      btn.textContent=data.verified?'VERIFIED':'CHECK FAILED';
      document.getElementById('doctorBtn')?.click();
      await preview();
    }catch(error){
      btn.textContent=error.status===428?'STEP-UP EXPIRED':error.message;
      setTimeout(()=>{btn.textContent=old;btn.disabled=false;},1800);
    }
  }

  button?.addEventListener('click',preview);
})();
