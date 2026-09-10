(()=>{
  const root=document.getElementById('webtools');
  if(!root) return;
  const csrf=document.querySelector('meta[name="csrf-token"]')?.content||'';
  const stepUp=root.dataset.stepUp==='1';
  const $=sel=>root.querySelector(sel);
  const esc=v=>String(v??'').replace(/[&<>'"]/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[ch]));
  const status=(node,msg,type='')=>{if(!node)return;node.textContent=msg;node.className=`webtools-status ${type}`.trim();};
  const bytes=n=>{let v=Number(n||0);for(const u of ['B','KB','MB','GB','TB']){if(v<1024||u==='TB')return `${v.toFixed(v>=10||u==='B'?0:1)} ${u}`;v/=1024;}return '0 B';};
  const when=ts=>{const n=Number(ts||0);return n?new Date(n*1000).toLocaleString():'لم يُفحص بعد';};
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

  function renderAliases(rows,quota={}){
    const target=$('#domainAliasList');
    const used=Number(quota.used??rows.length),limit=Number(quota.limit??0),remaining=Number(quota.remaining??Math.max(0,limit-used));
    $('#domainAliasQuota').textContent=limit>0?`الاستخدام ${used} / ${limit} · المتبقي ${remaining}`:`الاستخدام ${used}`;
    if(!rows.length){target.innerHTML='<div class="empty-state">لا توجد Aliases أو نطاقات فرعية لهذا الموقع.</div>';return;}
    target.innerHTML=rows.map(row=>`<div class="webtools-row"><code>${esc(row.alias)}</code><span class="code">${esc(row.kind||'alias')}</span><span class="target">${esc(row.domain)}</span><button type="button" data-delete-domain-alias="${row.id}" ${stepUp?'':'disabled'}>حذف</button></div>`).join('');
  }

  function renderLifecycle(data){
    renderAliases(data.aliases||[],data.alias_quota||{});
    const binding=data.dns_binding;
    const provider=binding?.provider?String(binding.provider).toUpperCase():'UNBOUND';
    $('#domainDnsProvider').textContent=provider;
    $('#domainDnsEndpoint').textContent=binding?.name||binding?.endpoint||'اربط DNS Provider من Advanced Ops';
    $('#domainDnsHero').textContent=binding?.provider?'BOUND':'OFF';

    const ssl=data.ssl||{};
    const installed=ssl.ok===true&&ssl.installed===true;
    $('#domainSslState').textContent=installed?'INSTALLED':(ssl.ok===false?'PROVIDER OFFLINE':'NOT ISSUED');
    $('#domainSslDetail').textContent=installed?String(ssl.detail||'Certificate active').split('\n')[0].slice(0,120):String(ssl.error||'No certificate').slice(0,120);
    $('#domainSslHero').textContent=installed?'ON':'OFF';

    const policy=data.ssl_policy||{};
    $('#domainAutoSslState').textContent=Number(policy.auto_renew||0)?'ON':'OFF';
    $('#domainSslLast').textContent=`${esc(policy.last_status||'unknown')} · ${when(policy.last_check)}`;
    const form=$('#sslPolicyForm');
    if(form){
      form.elements.contact_email.value=policy.contact_email||'';
      form.elements.renew_before_days.value=String(policy.renew_before_days||30);
      form.elements.auto_renew.checked=Boolean(Number(policy.auto_renew||0));
    }
    const suggestions=data.dns_suggestions||[];
    $('#domainDnsSuggestions').innerHTML=suggestions.length?suggestions.map(row=>`<div class="webtools-row dns-suggestion"><code>${esc(row.record_name)}</code><span class="code">${esc(row.record_type)}</span><span class="target">→ ${esc(row.record_value)} · TTL ${Number(row.ttl||300)}</span></div>`).join(''):'<div class="empty-state">لا توجد اقتراحات DNS؛ أضف Alias/Subdomain لعرض سجلات CNAME المقترحة.</div>';
  }

  async function loadLifecycle(){
    const domain=selectedDomain();
    if(!domain){renderAliases([],{});return;}
    try{const data=await api(`/api/domains/lifecycle?domain=${encodeURIComponent(domain)}`);renderLifecycle(data);status($('#domainAliasStatus'),'','');}
    catch(err){renderAliases([],{});status($('#domainAliasStatus'),err.message,'error');}
  }

  function renderRedirects(rows){
    const counter=$('#webtoolsRedirectCount');if(counter)counter.textContent=String(rows.length);
    const target=$('#redirectList');
    if(!rows.length){target.innerHTML='<div class="empty-state">لا توجد Redirects لهذا الموقع.</div>';return;}
    target.innerHTML=rows.map(row=>`<div class="webtools-row"><code>${esc(row.source_path)}</code><span class="code">${esc(row.status_code)}</span><span class="target">${esc(row.target)}</span><button type="button" data-delete-redirect="${row.id}" ${stepUp?'':'disabled'}>حذف</button></div>`).join('');
  }
  async function loadRedirects(){
    const domain=selectedDomain();if(!domain){renderRedirects([]);return;}
    try{const data=await api(`/api/webtools/redirects?domain=${encodeURIComponent(domain)}`);renderRedirects(data.redirects||[]);}catch(err){status($('#redirectStatus'),err.message,'error');}
  }

  function renderErrorPages(rows){
    const counter=$('#webtoolsErrorCount');if(counter)counter.textContent=String(rows.length);
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
  async function loadAll(){await Promise.all([loadLifecycle(),loadRedirects(),loadErrorPages(),loadMetrics()]);}

  $('#webtoolsDomain')?.addEventListener('change',loadAll);
  $('#refreshMetrics')?.addEventListener('click',loadMetrics);

  $('#domainAliasForm')?.addEventListener('submit',async event=>{
    event.preventDefault();const out=$('#domainAliasStatus');
    if(!stepUp){status(out,'Step-Up مطلوب قبل تعديل Domain Lifecycle.','error');return;}
    const domain=selectedDomain();if(!domain){status(out,'اختر موقعًا أولًا.','error');return;}
    const fd=new FormData(event.currentTarget);const alias=String(fd.get('alias')||'').trim().toLowerCase();
    try{await api('/api/domains/aliases',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain,alias})});event.currentTarget.reset();status(out,'تم ربط النطاق وتحديث جميع HTTP/TLS server blocks بنجاح.','ok');await loadLifecycle();}
    catch(err){status(out,err.status===428?'انتهت نافذة Step-Up؛ أعد التحقق من Security.':err.message,'error');}
  });
  $('#domainAliasList')?.addEventListener('click',async event=>{
    const btn=event.target.closest('[data-delete-domain-alias]');if(!btn)return;
    if(!stepUp){status($('#domainAliasStatus'),'Step-Up مطلوب.','error');return;}
    try{await api(`/api/domains/aliases/${btn.dataset.deleteDomainAlias}`,{method:'DELETE'});status($('#domainAliasStatus'),'تم حذف الربط وإعادة مزامنة NGINX.','ok');await loadLifecycle();}
    catch(err){status($('#domainAliasStatus'),err.message,'error');}
  });

  $('#sslPolicyForm')?.addEventListener('submit',async event=>{
    event.preventDefault();const out=$('#domainSslStatus');
    if(!stepUp){status(out,'Step-Up مطلوب لتغيير سياسة AutoSSL.','error');return;}
    const domain=selectedDomain();if(!domain){status(out,'اختر موقعًا أولًا.','error');return;}
    const fd=new FormData(event.currentTarget);
    const payload={domain,contact_email:String(fd.get('contact_email')||'').trim().toLowerCase(),auto_renew:event.currentTarget.elements.auto_renew.checked,renew_before_days:Number(fd.get('renew_before_days')||30)};
    try{await api('/api/domains/ssl-policy',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});status(out,'تم حفظ سياسة AutoSSL. الـworker يفحص السياسات كل 6 ساعات مع Randomized Delay.','ok');await loadLifecycle();}
    catch(err){status(out,err.status===428?'انتهت نافذة Step-Up؛ أعد التحقق.':err.message,'error');}
  });

  $('#domainSslIssue')?.addEventListener('click',async()=>{
    const out=$('#domainSslStatus');if(!stepUp){status(out,'Step-Up مطلوب.','error');return;}
    const domain=selectedDomain(),email=String($('#sslPolicyForm')?.elements.contact_email.value||'').trim().toLowerCase();
    if(!domain||!email){status(out,'اختر موقعًا وأدخل Contact Email أولًا.','error');return;}
    try{status(out,'جاري طلب الشهادة والتحقق من NGINX…','');await api('/api/domains/ssl/issue',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain,contact_email:email})});status(out,'تم إصدار/ربط الشهادة بنجاح.','ok');await loadLifecycle();}
    catch(err){status(out,err.message,'error');}
  });
  $('#domainSslRenew')?.addEventListener('click',async()=>{
    const out=$('#domainSslStatus');if(!stepUp){status(out,'Step-Up مطلوب.','error');return;}
    const domain=selectedDomain();if(!domain){status(out,'اختر موقعًا أولًا.','error');return;}
    try{status(out,'جاري فحص وتجديد الشهادة…','');await api('/api/domains/ssl/renew',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain})});status(out,'اكتملت دورة التجديد وربط NGINX.','ok');await loadLifecycle();}
    catch(err){status(out,err.message,'error');}
  });

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

  loadSites().catch(err=>status($('#domainAliasStatus'),`تعذر تحميل Domain Control Center: ${err.message}`,'error'));
})();
