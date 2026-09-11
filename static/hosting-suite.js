(()=>{
  const root=document.getElementById('hosting');
  if(!root) return;
  const admin=root.dataset.admin==='1';
  const stepUp=root.dataset.stepUp==='1';
  const csrf=document.querySelector('meta[name="csrf-token"]')?.content||'';
  let catalog=[];
  let categories={};
  let packageState={packages:[],feature_overrides:{},assignments:[]};

  const $=sel=>root.querySelector(sel);
  const esc=value=>String(value??'').replace(/[&<>'"]/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[ch]));
  const api=async(url,options={})=>{
    const opts={credentials:'same-origin',...options,headers:{Accept:'application/json',...(options.headers||{})}};
    if(opts.method&&opts.method!=='GET') opts.headers['X-CSRF-Token']=csrf;
    const res=await fetch(url,opts);
    let data={};
    try{data=await res.json();}catch{data={ok:false,error:`HTTP ${res.status}`};}
    if(!res.ok||data.ok===false){const err=new Error(data.error||`HTTP ${res.status}`);err.status=res.status;err.data=data;throw err;}
    return data;
  };
  const status=(node,message,type='')=>{if(!node)return;node.textContent=message;node.className=`hosting-status ${type}`.trim();};
  const quotaLabels={disk_mb:'Disk',bandwidth_mb:'Bandwidth',max_sites:'Sites',max_databases:'Databases',max_mailboxes:'Mailboxes',max_ftp_accounts:'FTP',max_cron_jobs:'Cron',max_subdomains:'Subdomains',max_backups:'Backups'};

  function renderCatalog(){
    const q=($('#hostingSearch')?.value||'').trim().toLowerCase();
    const category=$('#hostingCategory')?.value||'';
    const maturity=$('#hostingMaturity')?.value||'';
    const rows=catalog.filter(item=>(!category||item.category===category)&&(!maturity||item.maturity===maturity)&&(!q||`${item.label} ${item.feature_id} ${item.description||''} ${categories[item.category]||''}`.toLowerCase().includes(q)));
    const grid=$('#hostingFeatureGrid');
    if(!grid)return;
    if(!rows.length){grid.innerHTML='<div class="empty-state">لا توجد وظائف مطابقة للفلتر.</div>';return;}
    grid.innerHTML=rows.map(item=>{
      const state=item.maturity==='planned'?'roadmap':item.enabled?'enabled':'';
      const stateLabel=item.maturity==='planned'?'ROADMAP':item.enabled?'ENABLED':'DISABLED';
      const icon=(item.category||'?').slice(0,1).toUpperCase();
      return `<article class="hosting-feature-card" data-feature="${esc(item.feature_id)}">
        <span class="hosting-feature-icon">${esc(icon)}</span>
        <div class="hosting-feature-copy"><b>${esc(item.label)}</b><small>${esc(item.description||categories[item.category]||item.category)}</small>
          <div class="hosting-feature-meta"><span class="${esc(item.maturity)}">${esc(item.maturity)}</span><span>${esc(item.scope)}</span><span>${esc(item.provider)}</span>${item.risk!=='normal'?`<span>${esc(item.risk)}</span>`:''}</div>
        </div>
        <span class="hosting-feature-state ${state}"><i></i>${stateLabel}</span>
      </article>`;
    }).join('');
  }

  function renderQuotas(pkg){
    const target=$('#hostingQuotaGrid');
    if(!target)return;
    if(!pkg){target.innerHTML='<div class="empty-state">لا توجد حزمة مرتبطة بالحساب.</div>';return;}
    target.innerHTML=Object.entries(quotaLabels).map(([key,label])=>{
      const value=Number(pkg[key]||0);
      const shown=(key==='disk_mb'||key==='bandwidth_mb')?`${value.toLocaleString()} MB`:value.toLocaleString();
      return `<div class="hosting-quota"><small>${esc(label)}</small><b>${esc(shown)}</b></div>`;
    }).join('');
  }

  async function loadCatalog(){
    const data=await api('/api/hosting/catalog');
    catalog=data.catalog||[];
    categories=data.categories||{};
    const maturity=data.maturity||{};
    $('#hostingFeatureCount').textContent=String(catalog.length);
    $('#hostingNativeCount').textContent=String(maturity.native||0);
    $('#hostingFoundationCount').textContent=String(maturity.foundation||0);
    $('#hostingPlannedCount').textContent=String(maturity.planned||0);
    $('#hostingCurrentPackage').textContent=data.package?.name||'—';
    renderQuotas(data.package);
    const categorySelect=$('#hostingCategory');
    if(categorySelect&&categorySelect.options.length===1){
      Object.entries(categories).forEach(([key,label])=>categorySelect.insertAdjacentHTML('beforeend',`<option value="${esc(key)}">${esc(label)}</option>`));
    }
    renderCatalog();
  }

  function fillPackageSelect(select,placeholder='اختر حزمة…'){
    if(!select)return;
    const selected=select.value;
    select.innerHTML=`<option value="">${esc(placeholder)}</option>`+packageState.packages.filter(p=>p.enabled).map(p=>`<option value="${p.id}">${esc(p.name)}</option>`).join('');
    if([...select.options].some(o=>o.value===selected)) select.value=selected;
  }

  function renderPolicy(){
    const packageId=$('#hostingPolicyPackage')?.value||'';
    const target=$('#hostingPolicyFeatures');
    if(!target)return;
    if(!packageId){target.innerHTML='<div class="empty-state">اختر حزمة لعرض السياسات.</div>';return;}
    const overrides=packageState.feature_overrides?.[String(packageId)]||{};
    target.innerHTML=catalog.map(item=>{
      const checked=Object.prototype.hasOwnProperty.call(overrides,item.feature_id)?Boolean(overrides[item.feature_id]):item.maturity!=='planned';
      const disabled=!stepUp||item.maturity==='planned';
      return `<div class="hosting-policy-row"><div><b>${esc(item.label)}</b><small>${esc(item.feature_id)} · ${esc(item.maturity)}</small></div>
        <label class="hosting-switch"><input type="checkbox" data-feature-id="${esc(item.feature_id)}" ${checked?'checked':''} ${disabled?'disabled':''}><span></span></label></div>`;
    }).join('');
  }

  async function loadPackages(){
    if(!admin)return;
    packageState=await api('/api/hosting/packages');
    fillPackageSelect($('#hostingPolicyPackage'));
    fillPackageSelect($('#hostingAssignPackage'));
    renderPolicy();
  }

  function impactInput(){
    return {
      username:String($('#hostingAssignUsername')?.value||'').trim(),
      package_id:Number($('#hostingAssignPackage')?.value||0)
    };
  }

  function renderImpact(impact){
    const out=$('#hostingImpactResult');
    if(!out)return;
    const violations=impact?.violations||[];
    const removed=impact?.removed_features||[];
    const unmeasured=impact?.unmeasured||[];
    const current=impact?.current_package?.name||'Default';
    const target=impact?.target_package?.name||'—';
    const quotaText=violations.length
      ? violations.map(v=>`${quotaLabels[v.limit]||v.limit}: ${v.used}/${v.target} (+${v.excess})`).join(' · ')
      : 'لا توجد تجاوزات في الحدود القابلة للقياس.';
    const featureText=removed.length?`سيتم تعطيل ${removed.length} ميزة: ${removed.slice(0,5).join(', ')}${removed.length>5?'…':''}`:'لا توجد ميزات ستُسحب.';
    const measurement=unmeasured.length?`Disk/Bandwidth غير مقاسين لحظيًا ولن يُدّعى أنهما متوافقان.`:'';
    out.innerHTML=`<b>${impact.safe_to_assign?'SAFE TO ASSIGN':'ASSIGNMENT BLOCKED'}</b><br><small>${esc(current)} → ${esc(target)}</small><br><span>${esc(quotaText)}</span><br><span>${esc(featureText)}</span>${measurement?`<br><span>${esc(measurement)}</span>`:''}`;
    out.className=`hosting-status ${impact.safe_to_assign?'ok':'error'}`;
  }

  async function simulateImpact(){
    const input=impactInput();
    if(!input.username||!input.package_id){status($('#hostingImpactResult'),'أدخل Username واختر الحزمة أولًا.','error');return null;}
    try{
      const data=await api('/api/hosting/package-impact',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(input)});
      renderImpact(data.impact);
      return data.impact;
    }catch(err){status($('#hostingImpactResult'),err.message,'error');return null;}
  }

  $('#hostingSearch')?.addEventListener('input',renderCatalog);
  $('#hostingCategory')?.addEventListener('change',renderCatalog);
  $('#hostingMaturity')?.addEventListener('change',renderCatalog);
  $('#hostingPolicyPackage')?.addEventListener('change',renderPolicy);
  $('#hostingImpactBtn')?.addEventListener('click',simulateImpact);
  $('#hostingAssignPackage')?.addEventListener('change',()=>{status($('#hostingImpactResult'),'تغيرت الحزمة؛ أعد محاكاة التأثير قبل التعيين.','');});
  $('#hostingAssignUsername')?.addEventListener('input',()=>{status($('#hostingImpactResult'),'تغير المستخدم؛ أعد محاكاة التأثير قبل التعيين.','');});

  $('#hostingPackageForm')?.addEventListener('submit',async event=>{
    event.preventDefault();
    const out=$('#hostingPackageStatus');
    if(!stepUp){status(out,'فعّل Step-Up Authentication من Security أولًا.','error');return;}
    const form=new FormData(event.currentTarget);
    const payload={name:form.get('name'),description:form.get('description'),enabled:true};
    ['disk_mb','bandwidth_mb','max_sites','max_databases','max_mailboxes','max_ftp_accounts','max_cron_jobs','max_subdomains','max_backups'].forEach(k=>payload[k]=Number(form.get(k)));
    try{
      await api('/api/hosting/packages',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
      status(out,'تم إنشاء الحزمة وتسجيل العملية في Audit.','ok');
      await loadPackages();
    }catch(err){status(out,err.status===428?'انتهت نافذة Step-Up؛ أعد التحقق من Security.':err.message,'error');}
  });

  $('#hostingPolicyFeatures')?.addEventListener('change',async event=>{
    const input=event.target.closest('input[data-feature-id]');
    if(!input)return;
    const packageId=$('#hostingPolicyPackage')?.value;
    if(!packageId)return;
    const featureId=input.dataset.featureId;
    const previous=!input.checked;
    input.disabled=true;
    try{
      await api(`/api/hosting/packages/${encodeURIComponent(packageId)}/features/${encodeURIComponent(featureId)}`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:input.checked})});
      packageState.feature_overrides[String(packageId)]??={};
      packageState.feature_overrides[String(packageId)][featureId]=input.checked;
    }catch(err){input.checked=previous;status($('#hostingPackageStatus'),err.status===428?'Step-Up مطلوب لتعديل Feature Manager.':err.message,'error');}
    finally{input.disabled=!stepUp||catalog.find(x=>x.feature_id===featureId)?.maturity==='planned';}
  });

  $('#hostingAssignForm')?.addEventListener('submit',async event=>{
    event.preventDefault();
    const out=$('#hostingAssignStatus');
    if(!stepUp){status(out,'Step-Up مطلوب قبل تغيير حزمة المستخدم.','error');return;}
    const impact=await simulateImpact();
    if(!impact)return;
    if(!impact.safe_to_assign){status(out,'تم منع تغيير الحزمة لأن الاستخدام الحالي يتجاوز حدود الحزمة المستهدفة.','error');return;}
    const input=impactInput();
    try{
      const data=await api(`/api/hosting/users/${encodeURIComponent(input.username)}/package`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({package_id:input.package_id})});
      renderImpact(data.impact||impact);
      status(out,`تم تعيين الحزمة للمستخدم ${input.username} بعد اجتياز Impact Gate.`,'ok');
      await loadPackages();
    }catch(err){
      if(err.data?.impact)renderImpact(err.data.impact);
      status(out,err.status===428?'Step-Up مطلوب أو انتهت صلاحيته.':err.message,'error');
    }
  });

  Promise.all([loadCatalog(),loadPackages()]).catch(err=>{
    const grid=$('#hostingFeatureGrid');
    if(grid)grid.innerHTML=`<div class="empty-state">تعذر تحميل Hosting Suite: ${esc(err.message)}</div>`;
  });
})();
