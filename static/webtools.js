(()=>{
  const root=document.getElementById('webtools');
  if(!root) return;
  const csrf=document.querySelector('meta[name="csrf-token"]')?.content||'';
  const stepUp=root.dataset.stepUp==='1';
  const $=sel=>root.querySelector(sel);
  const esc=v=>String(v??'').replace(/[&<>'"]/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[ch]));
  const status=(node,msg,type='')=>{if(!node)return;node.textContent=msg;node.className=`webtools-status ${type}`.trim();};
  const bytes=n=>{let v=Number(n||0);for(const u of ['B','KB','MB','GB','TB']){if(v<1024||u==='TB')return `${v.toFixed(v>=10||u==='B'?0:1)} ${u}`;v/=1024;}return '0 B';};
  const api=async(url,options={})=>{
    const opts={credentials:'same-origin',...options,headers:{Accept:'application/json',...(options.headers||{})}};
    if(opts.method&&opts.method!=='GET') opts.headers['X-CSRF-Token']=csrf;
    const res=await fetch(url,opts);let data={};
    try{data=await res.json();}catch{data={ok:false,error:`HTTP ${res.status}`};}
    if(!res.ok||data.ok===false){const err=new Error(data.error||`HTTP ${res.status}`);err.status=res.status;throw err;}
    return data;
  };
  const selectedDomain=()=>$('#webtoolsDomain')?.value||'';

  async function loadSites(){
    const data=await api('/api/webtools/sites');
    const select=$('#webtoolsDomain');
    const sites=data.sites||[];
    $('#webtoolsSiteCount').textContent=String(sites.length);
    select.innerHTML='<option value="">اختر موقعًا…</option>'+sites.map(s=>`<option value="${esc(s.domain)}">${esc(s.domain)} · ${esc(s.kind)}</option>`).join('');
    if(sites.length){select.value=sites[0].domain;await loadAll();}
  }

  function renderRedirects(rows){
    $('#webtoolsRedirectCount').textContent=String(rows.length);
    const target=$('#redirectList');
    if(!rows.length){target.innerHTML='<div class="empty-state">لا توجد Redirects لهذا الموقع.</div>';return;}
    target.innerHTML=rows.map(row=>`<div class="webtools-row"><code>${esc(row.source_path)}</code><span class="code">${esc(row.status_code)}</span><span class="target">${esc(row.target)}</span><button type="button" data-delete-redirect="${row.id}" ${stepUp?'':'disabled'}>حذف</button></div>`).join('');
  }
  async function loadRedirects(){
    const domain=selectedDomain();if(!domain){renderRedirects([]);return;}
    try{const data=await api(`/api/webtools/redirects?domain=${encodeURIComponent(domain)}`);renderRedirects(data.redirects||[]);}catch(err){status($('#redirectStatus'),err.message,'error');}
  }

  function renderErrorPages(rows){
    $('#webtoolsErrorCount').textContent=String(rows.length);
    const target=$('#errorPageList');
    if(!rows.length){target.innerHTML='<div class="empty-state">لا توجد صفحات أخطاء مخصصة.</div>';return;}
    target.innerHTML=rows.map(row=>`<div class="webtools-code-card"><b>${row.status_code}</b><small>${Number(new Blob([row.html||'']).size).toLocaleString()} bytes</small><button type="button" class="ghost" data-edit-error="${row.status_code}">تحرير</button><button type="button" data-delete-error="${row.status_code}" ${stepUp?'':'disabled'}>حذف</button></div>`).join('');
    target.querySelectorAll('[data-edit-error]').forEach(btn=>btn.addEventListener('click',()=>{
      const code=Number(btn.dataset.editError);const row=rows.find(x=>Number(x.status_code)===code);if(!row)return;
      $('#errorStatusCode').value=String(code);$('#errorHtml').value=row.html||'';$('#errorHtml').focus();
    }));
  }
  async function loadErrorPages(){
    const domain=selectedDomain();if(!domain){renderErrorPages([]);return;}
    try{const data=await api(`/api/webtools/error-pages?domain=${encodeURIComponent(domain)}`);renderErrorPages(data.pages||[]);}catch(err){status($('#errorPageStatus'),err.message,'error');}
  }

  function renderMetrics(m){
    $('#webtoolsRequestCount').textContent=Number(m.requests||0).toLocaleString();
    $('#metricRequests').textContent=Number(m.requests||0).toLocaleString();
    $('#metricVisitors').textContent=Number(m.visitors||0).toLocaleString();
    $('#metricBandwidth').textContent=bytes(m.bandwidth_bytes||0);
    const success=Object.entries(m.status||{}).filter(([k])=>String(k).startsWith('2')).reduce((a,[,v])=>a+Number(v||0),0);
    $('#metricSuccess').textContent=success.toLocaleString();
    const paths=$('#metricPaths'),statuses=$('#metricStatuses');
    const pathRows=m.top_paths||[];
    paths.innerHTML=pathRows.length?pathRows.map(x=>`<div class="metric-row"><code>${esc(x.path)}</code><b>${Number(x.requests||0).toLocaleString()}</b></div>`).join(''):'<div class="empty-state">لا توجد طلبات في نافذة السجل الحالية.</div>';
    const stats=Object.entries(m.status||{});
    statuses.innerHTML=stats.length?stats.map(([code,count])=>`<div class="metric-row"><code>HTTP ${esc(code)}</code><b>${Number(count||0).toLocaleString()}</b></div>`).join(''):'<div class="empty-state">لا توجد Status Codes بعد.</div>';
  }
  async function loadMetrics(){
    const domain=selectedDomain();if(!domain){renderMetrics({});return;}
    try{const data=await api(`/api/webtools/metrics?domain=${encodeURIComponent(domain)}`);renderMetrics(data.metrics||{});}catch{renderMetrics({});}
  }
  async function loadAll(){await Promise.all([loadRedirects(),loadErrorPages(),loadMetrics()]);}

  $('#webtoolsDomain')?.addEventListener('change',loadAll);
  $('#refreshMetrics')?.addEventListener('click',loadMetrics);
  $('#redirectForm')?.addEventListener('submit',async event=>{
    event.preventDefault();const out=$('#redirectStatus');
    if(!stepUp){status(out,'Step-Up مطلوب قبل تعديل NGINX.','error');return;}
    const domain=selectedDomain();if(!domain){status(out,'اختر موقعًا أولًا.','error');return;}
    const fd=new FormData(event.currentTarget);
    const payload={domain,source_path:fd.get('source_path'),target:fd.get('target'),status_code:Number(fd.get('status_code'))};
    try{const data=await api('/api/webtools/redirects',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});renderRedirects(data.redirects||[]);event.currentTarget.reset();status(out,'تم تطبيق Redirect بعد نجاح nginx -t وإعادة التحميل.','ok');}
    catch(err){status(out,err.status===428?'انتهت نافذة Step-Up؛ أعد التحقق من Security.':err.message,'error');}
  });
  $('#redirectList')?.addEventListener('click',async event=>{
    const btn=event.target.closest('[data-delete-redirect]');if(!btn)return;
    if(!stepUp){status($('#redirectStatus'),'Step-Up مطلوب.','error');return;}
    try{const data=await api(`/api/webtools/redirects/${btn.dataset.deleteRedirect}`,{method:'DELETE'});renderRedirects(data.redirects||[]);status($('#redirectStatus'),'تم حذف Redirect وتحديث NGINX.','ok');}
    catch(err){status($('#redirectStatus'),err.message,'error');}
  });
  $('#errorPageForm')?.addEventListener('submit',async event=>{
    event.preventDefault();const out=$('#errorPageStatus');
    if(!stepUp){status(out,'Step-Up مطلوب قبل تعديل إعداد NGINX.','error');return;}
    const domain=selectedDomain();if(!domain){status(out,'اختر موقعًا أولًا.','error');return;}
    const fd=new FormData(event.currentTarget);const code=Number(fd.get('status_code'));const html=String(fd.get('html')||'');
    try{const data=await api(`/api/webtools/error-pages/${code}`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain,html})});renderErrorPages(data.pages||[]);status(out,`تم حفظ صفحة ${code} وتفعيلها في NGINX.`,'ok');}
    catch(err){status(out,err.status===428?'انتهت نافذة Step-Up؛ أعد التحقق.':err.message,'error');}
  });
  $('#errorPageList')?.addEventListener('click',async event=>{
    const btn=event.target.closest('[data-delete-error]');if(!btn)return;
    const domain=selectedDomain();if(!domain)return;
    try{const data=await api(`/api/webtools/error-pages/${btn.dataset.deleteError}?domain=${encodeURIComponent(domain)}`,{method:'DELETE'});renderErrorPages(data.pages||[]);status($('#errorPageStatus'),'تم حذف صفحة الخطأ المخصصة.','ok');}
    catch(err){status($('#errorPageStatus'),err.message,'error');}
  });

  loadSites().catch(err=>status($('#redirectStatus'),`تعذر تحميل Web Tools: ${err.message}`,'error'));
})();
