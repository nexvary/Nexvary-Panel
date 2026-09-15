(()=>{
  const root=document.getElementById('parity');
  if(!root)return;
  const $=sel=>root.querySelector(sel);
  const esc=v=>String(v??'').replace(/[&<>'"]/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[ch]));
  let catalog=[];let categories={};
  const weight={native:1,foundation:.65,planned:0};
  const stats=rows=>{
    const total=rows.length,native=rows.filter(x=>x.maturity==='native').length,foundation=rows.filter(x=>x.maturity==='foundation').length,planned=rows.filter(x=>x.maturity==='planned').length;
    const operational=native+foundation;
    const coverage=total?operational/total*100:0;
    const maturity=total?rows.reduce((sum,x)=>sum+(weight[x.maturity]||0),0)/total*100:0;
    return{total,native,foundation,planned,operational,coverage,maturity};
  };
  const pct=value=>`${Number(value||0).toFixed(1)}%`;

  function renderSummary(){
    const all=stats(catalog),account=stats(catalog.filter(x=>x.scope==='account')),server=stats(catalog.filter(x=>x.scope==='server'));
    $('#parityTotal').textContent=all.total;
    $('#parityOperational').textContent=`${all.operational}/${all.total}`;
    $('#parityCoverage').textContent=pct(all.coverage);
    $('#parityMaturity').textContent=pct(all.maturity);
    $('#parityAccountCoverage').textContent=pct(account.coverage);
    $('#parityAccountDetail').textContent=`${account.operational}/${account.total} operational · ${account.planned} roadmap`;
    $('#parityServerCoverage').textContent=pct(server.coverage);
    $('#parityServerDetail').textContent=`${server.operational}/${server.total} operational · ${server.planned} roadmap`;
    $('#parityVerified').textContent=String(all.native+all.foundation);
    $('#parityVerifiedDetail').textContent=`${all.native} Native · ${all.foundation} Foundation`;
  }

  function renderCategories(){
    const grouped=new Map();
    for(const row of catalog){if(!grouped.has(row.category))grouped.set(row.category,[]);grouped.get(row.category).push(row);}
    const rows=[...grouped.entries()].map(([id,items])=>({id,label:categories[id]||id,...stats(items)})).sort((a,b)=>b.coverage-a.coverage||a.label.localeCompare(b.label,'ar'));
    $('#parityCategories').innerHTML=rows.map(row=>`<div class="parity-category"><div class="parity-category-label"><b>${esc(row.label)}</b><small>${row.operational}/${row.total} · ${row.planned} roadmap</small></div><div class="parity-bar"><i style="width:${Math.max(0,Math.min(100,row.coverage))}%"></i></div><div class="parity-category-value">${pct(row.coverage)}</div></div>`).join('')||'<div class="empty-state">لا توجد بيانات.</div>';
    const categorySelect=$('#parityGapCategory');
    categorySelect.innerHTML='<option value="all">كل المجالات</option>'+rows.map(row=>`<option value="${esc(row.id)}">${esc(row.label)}</option>`).join('');
  }

  function renderGaps(){
    const scope=$('#parityGapScope').value,category=$('#parityGapCategory').value;
    let gaps=catalog.filter(x=>x.maturity==='planned');
    if(scope!=='all')gaps=gaps.filter(x=>x.scope===scope);
    if(category!=='all')gaps=gaps.filter(x=>x.category===category);
    gaps.sort((a,b)=>(a.scope===b.scope?0:a.scope==='account'?-1:1)||(categories[a.category]||a.category).localeCompare(categories[b.category]||b.category,'ar')||a.label.localeCompare(b.label));
    $('#parityGapCount').textContent=`${gaps.length} GAP${gaps.length===1?'':'S'}`;
    $('#parityGaps').innerHTML=gaps.length?gaps.map(row=>`<div class="parity-gap"><div><b>${esc(row.label)}</b><code>${esc(row.feature_id)}</code></div><em>${esc(row.scope)}</em><small>${esc(categories[row.category]||row.category)}${row.provider&&row.provider!=='native'?` · provider: ${esc(row.provider)}`:''}</small></div>`).join(''):'<div class="empty-state">لا توجد فجوات ضمن هذا الفلتر.</div>';
  }

  async function load(){
    try{
      const res=await fetch('/api/hosting/catalog',{credentials:'same-origin',headers:{Accept:'application/json'}});
      const data=await res.json();if(!res.ok||data.ok===false)throw new Error(data.error||`HTTP ${res.status}`);
      catalog=data.catalog||[];categories=data.categories||{};
      renderSummary();renderCategories();renderGaps();
    }catch(err){$('#parityCategories').innerHTML=`<div class="empty-state">تعذر حساب Parity Center: ${esc(err.message)}</div>`;}
  }
  $('#parityGapScope')?.addEventListener('change',renderGaps);
  $('#parityGapCategory')?.addEventListener('change',renderGaps);
  load();
})();
