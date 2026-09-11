(()=>{
  const root=document.getElementById('advChangeSafetyCard');
  if(!root)return;
  const $=sel=>root.querySelector(sel);
  const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const badge=(item)=>{
    const map={preview:'PREVIEW',reversible:'ROLLBACK READY','verified-rollback':'ROLLED BACK',verified:'VERIFIED','snapshot-ready':'SNAPSHOT READY',attention:'ATTENTION'};
    return map[item.safety]||String(item.safety||'').toUpperCase();
  };
  const when=ts=>ts?new Date(Number(ts)*1000).toLocaleString():'—';

  function render(data){
    const p=data.posture||{};
    $('#changeSafetyScore').textContent=`${Number(p.score||0)}%`;
    $('#changeSafetyGrade').textContent=p.grade||'—';
    $('#changeSafetyProtected').textContent=`${Number(p.protected_changes||0)}/${Number(p.external_changes||0)}`;
    $('#changeSafetyAttention').textContent=String(Number(p.attention||0));
    const list=$('#changeSafetyEvents');
    const rows=data.events||[];
    if(!rows.length){list.innerHTML='<div class="empty-state">لا توجد تغييرات حديثة تحتاج تصنيفًا بعد.</div>';return;}
    list.innerHTML=rows.slice(0,24).map(item=>`<div class="adv-list-row change-safety-row ${item.safety==='attention'?'attention':''}"><div><b>${esc(item.label)}</b><small>${esc(item.kind.toUpperCase())}${item.domain?` · ${esc(item.domain)}`:''} · ${when(item.changed_at)}</small><span>${esc(item.guidance)}</span></div><div><strong>${esc(badge(item))}</strong><small>${item.reversible?'REVERSIBLE / PROTECTED':'NO AUTOMATIC ROLLBACK'}</small></div></div>`).join('');
  }

  async function load(){
    const list=$('#changeSafetyEvents');
    list.innerHTML='<div class="empty-state">جاري حساب Safety Posture…</div>';
    try{
      const response=await fetch('/api/change-safety',{credentials:'same-origin',headers:{Accept:'application/json'}});
      const data=await response.json();
      if(!response.ok||data.ok===false)throw new Error(data.error||`HTTP ${response.status}`);
      render(data);
    }catch(error){
      list.innerHTML=`<div class="empty-state"><b>تعذر تحليل Change Safety</b><small>${esc(error.message)}</small></div>`;
    }
  }

  $('#changeSafetyRefresh')?.addEventListener('click',load);
  load();
})();
