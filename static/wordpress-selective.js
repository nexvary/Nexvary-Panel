(()=>{
  const root=document.getElementById('wordpress');if(!root)return;
  const panel=root.querySelector('#wpStagingPanel');if(!panel)return;
  const sourceSelect=root.querySelector('#wpLifecycleDomain');
  const csrf=document.querySelector('meta[name="csrf-token"]')?.content||'';
  const stepUp=root.dataset.stepUp==='1';
  const result=root.querySelector('#wpStagingResult');
  const form=panel.querySelector('.adv-form');
  if(form&&!root.querySelector('#wpSelectivePublishControls')){
    const controls=document.createElement('div');
    controls.id='wpSelectivePublishControls';
    controls.className='adv-inline';
    controls.innerHTML=`<label>Selective Scope<select id="wpSelectiveScope"><option value="plugins_themes">Plugins + Themes only</option></select></label><button id="wpSelectivePublishBtn" type="button" class="tiny danger" ${stepUp?'':'disabled'}>Selective Safe Publish</button><button id="wpPublishHistoryBtn" type="button" class="tiny ghost">Publish History</button>`;
    form.appendChild(controls);
  }
  let history=root.querySelector('#wpPublishHistory');
  if(!history){
    history=document.createElement('div');history.id='wpPublishHistory';history.className='application-grid';
    history.innerHTML='<div class="empty">اختر Live WordPress لعرض سجل النشر.</div>';
    result?.insertAdjacentElement('afterend',history);
  }
  const $=s=>root.querySelector(s);
  const source=()=>sourceSelect?.value||'';
  const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const api=async(url,opt={})=>{const headers={Accept:'application/json',...(opt.headers||{})};if(opt.method&&opt.method!=='GET')headers['X-CSRF-Token']=csrf;if(opt.body&&!headers['Content-Type'])headers['Content-Type']='application/json';const res=await fetch(url,{credentials:'same-origin',...opt,headers});let body={};try{body=await res.json()}catch{}if(!res.ok)throw Object.assign(new Error(body.error||`HTTP ${res.status}`),{status:res.status});return body};
  function render(rows){
    if(!rows?.length){history.innerHTML='<div class="empty">لا يوجد Publish History لهذا الموقع بعد.</div>';return;}
    history.innerHTML=rows.map(row=>`<article class="wp-card"><div class="application-card-top"><div class="application-title"><b>${esc(row.scope==='full'?'Full Safe Publish':'Plugins + Themes')}</b><small>${esc(row.snapshot_id)}</small></div><span class="live-chip"><i></i>${esc(String(row.status||'').toUpperCase())}</span></div><div class="application-meta"><span>${new Date(Number(row.created_at||0)*1000).toLocaleString()}</span><span>${esc(row.version||'')}</span></div><small>${esc(row.detail||'')}</small>${row.can_rollback?`<button type="button" class="tiny ghost" data-history-rollback="${esc(row.snapshot_id)}" ${stepUp?'':'disabled'}>Rollback this snapshot</button>`:''}</article>`).join('');
  }
  async function loadHistory(){const d=source();if(!d){render([]);return;}try{const data=await api(`/api/wordpress/staging/history?domain=${encodeURIComponent(d)}`);render(data.history||[]);}catch(e){if(e.status===404)render([]);else history.innerHTML=`<div class="empty">${esc(e.message)}</div>`;}}
  $('#wpSelectivePublishBtn')?.addEventListener('click',async()=>{try{if(!stepUp)throw Object.assign(new Error('Step-Up مطلوب للنشر الانتقائي.'),{status:428});const d=source();if(!d)throw new Error('اختر Live WordPress أولًا.');const scope=$('#wpSelectiveScope')?.value||'';result.textContent='جاري إنشاء Snapshot كامل ثم نشر plugins/themes فقط دون DB أو uploads…';const data=await api('/api/wordpress/staging/publish-selective',{method:'POST',body:JSON.stringify({source_domain:d,scope})});const p=data.published||{};result.textContent=`SELECTIVE SAFE PUBLISH: COMPLETE\nLive: ${data.source_domain}\nStaging: ${data.target_domain}\nPlugins files: ${Number(p.plugins||0).toLocaleString()}\nTheme files: ${Number(p.themes||0).toLocaleString()}\nDatabase changed: NO\nUploads changed: NO\nRollback snapshot: ${data.snapshot_id}`;render(data.history||[]);}catch(e){result.textContent=e.status===428?'Step-Up مطلوب من Security قبل Selective Publish.':e.message;}});
  $('#wpPublishHistoryBtn')?.addEventListener('click',loadHistory);
  history.addEventListener('click',async event=>{const btn=event.target.closest('[data-history-rollback]');if(!btn)return;try{if(!stepUp)throw Object.assign(new Error('Step-Up مطلوب للRollback.'),{status:428});const d=source();const snapshot=btn.dataset.historyRollback;result.textContent=`جاري Rollback من Snapshot ${snapshot}…`;const data=await api(`/api/wordpress/staging/history/${encodeURIComponent(snapshot)}/rollback`,{method:'POST',body:JSON.stringify({source_domain:d})});result.textContent=`PUBLISH HISTORY ROLLBACK: COMPLETE\nLive: ${data.source_domain}\nSnapshot: ${data.snapshot_id}\nWordPress: ${data.version||'unknown'}`;render(data.history||[]);}catch(e){result.textContent=e.status===428?'Step-Up مطلوب من Security قبل Rollback.':e.message;}});
  sourceSelect?.addEventListener('change',loadHistory);
  $('#wpStageRefreshBtn')?.addEventListener('click',()=>setTimeout(loadHistory,0));
  if(source())loadHistory();
})();
