(()=>{
  const root=document.getElementById('advancedops');
  const card=document.getElementById('advServerLifecycleCard');
  if(!root||!card)return;
  const csrf=document.querySelector('meta[name="csrf-token"]')?.content||'';
  const $=sel=>card.querySelector(sel);
  const text=(sel,value)=>{const node=$(sel);if(node)node.textContent=String(value??'—');};
  const safe=v=>String(v??'');
  const api=async(url,options={})=>{
    const opts={credentials:'same-origin',...options,headers:{Accept:'application/json',...(options.headers||{})}};
    if(opts.method&&opts.method!=='GET')opts.headers['X-CSRF-Token']=csrf;
    const response=await fetch(url,opts);
    let data={};
    try{data=await response.json();}catch{data={ok:false,error:`HTTP ${response.status}`};}
    if(!response.ok||data.ok===false){const error=new Error(data.error||`HTTP ${response.status}`);error.status=response.status;throw error;}
    return data;
  };
  const status=(message,type='')=>{const node=$('#serverLifecycleMeta');if(!node)return;node.textContent=message;node.className=`adv-result ${type}`.trim();};
  const formatDuration=seconds=>{
    let value=Math.max(0,Number(seconds||0));
    const days=Math.floor(value/86400);value%=86400;
    const hours=Math.floor(value/3600);value%=3600;
    const mins=Math.floor(value/60);
    return `${days}d ${hours}h ${mins}m`;
  };
  const stamp=epoch=>epoch?new Date(Number(epoch)*1000).toLocaleString():'—';
  const makeRow=(left,right)=>{
    const row=document.createElement('div');row.className='adv-row';
    const a=document.createElement('span');a.textContent=left;
    const b=document.createElement('b');b.textContent=right;
    row.append(a,b);return row;
  };

  function renderOverview(data){
    text('#serverLifecycleHost',data.hostname||'—');
    text('#serverLifecycleOs',data.os||'—');
    text('#serverLifecycleReboot',data.reboot_required?'REQUIRED':'CLEAR');
    const input=$('#serverLifecycleHostnameInput');
    if(input&&!input.value)input.value=data.hostname||'';
    const t=data.time||{};
    status(`SERVER ONLINE · kernel ${safe(data.kernel)||'—'} · uptime ${formatDuration(data.uptime_seconds)} · timezone ${safe(t.timezone)||'—'} · NTP ${t.ntp?'ON':'OFF'} · synced ${t.synchronized?'YES':'NO'}`,'ok');
  }
  function renderNetwork(data){
    const target=$('#serverLifecycleNetwork');if(!target)return;target.replaceChildren();
    const addresses=Array.isArray(data.addresses)?data.addresses:[];
    const routes=Array.isArray(data.default_routes)?data.default_routes:[];
    const nameservers=Array.isArray(data.nameservers)?data.nameservers:[];
    if(!addresses.length&&!routes.length&&!nameservers.length){target.append(makeRow('Network','No inventory'));return;}
    for(const row of addresses.slice(0,10))target.append(makeRow(`${safe(row.interface)} · ${safe(row.family)}`,`${safe(row.address)}/${Number(row.prefixlen||0)}`));
    for(const row of routes.slice(0,4))target.append(makeRow('Default route',`${safe(row.gateway)||'direct'} · ${safe(row.dev)}`));
    for(const resolver of nameservers.slice(0,8))target.append(makeRow('Resolver',safe(resolver)));
  }
  function renderProcesses(data){
    const target=$('#serverLifecycleProcesses');if(!target)return;target.replaceChildren();
    const rows=Array.isArray(data.processes)?data.processes:[];
    if(!rows.length){target.append(makeRow('Processes','No inventory'));return;}
    for(const row of rows.slice(0,12))target.append(makeRow(`#${Number(row.pid||0)} ${safe(row.command)} · ${safe(row.user)}`,`${Number(row.cpu||0).toFixed(1)}% CPU · ${Number(row.memory||0).toFixed(1)}% RAM`));
  }
  function renderUpdates(data){
    text('#serverLifecycleUpdates',Number(data.count||0));
    const note=Number(data.count||0)===0?'لا توجد تحديثات في المحاكاة الحالية.':`${Number(data.count||0)} package(s) في apt simulation. Apply غير متاح من Platform 0.7.`;
    status(note,data.count?'warning':'ok');
  }
  function renderMaintenance(data){
    const target=$('#serverLifecycleMaintenance');if(!target)return;target.replaceChildren();
    const rows=Array.isArray(data.previews)?data.previews:[];
    if(!rows.length){target.append(makeRow('Maintenance','لا توجد Previews.'));return;}
    for(const item of rows.slice(0,20)){
      const row=document.createElement('div');row.className='adv-row server-maintenance-row';
      const copy=document.createElement('span');
      const snapshot=item.snapshot&&typeof item.snapshot==='object'?item.snapshot:{};
      let extra='';
      if(item.kind==='system-updates')extra=`${Number(snapshot.count||0)} updates`;
      else if(item.kind==='hostname')extra=`${safe(snapshot.current_hostname)} → ${safe(snapshot.desired_hostname)}`;
      else extra=`reboot_required=${snapshot.reboot_required?'yes':'no'}`;
      const when=item.status==='applied'?`applied ${stamp(item.applied_at)}`:`expires ${stamp(item.expires_at)}`;
      copy.textContent=`#${Number(item.id)} · ${safe(item.kind)} · ${safe(item.status)} · ${extra} · ${when}`;
      row.append(copy);
      if(item.status==='preview'&&item.kind==='hostname'){
        const apply=document.createElement('button');apply.type='button';apply.className='tiny danger';apply.textContent='Apply Hostname';apply.dataset.applyMaintenance=String(item.id);row.append(apply);
      }
      if(item.status==='preview'){
        const cancel=document.createElement('button');cancel.type='button';cancel.className='tiny ghost';cancel.textContent='إلغاء Preview';cancel.dataset.cancelMaintenance=String(item.id);row.append(cancel);
      }
      target.append(row);
    }
  }

  async function loadAll(){
    const settled=await Promise.allSettled([
      api('/api/server-lifecycle/overview'),
      api('/api/server-lifecycle/network'),
      api('/api/server-lifecycle/processes'),
      api('/api/server-lifecycle/updates'),
      api('/api/server-lifecycle/maintenance'),
    ]);
    const [overview,network,processes,updates,maintenance]=settled;
    if(overview.status==='fulfilled')renderOverview(overview.value);else status(`SERVER PROVIDER OFFLINE · ${overview.reason?.message||'unavailable'}`,'error');
    if(network.status==='fulfilled')renderNetwork(network.value);
    if(processes.status==='fulfilled')renderProcesses(processes.value);
    if(updates.status==='fulfilled')renderUpdates(updates.value);else text('#serverLifecycleUpdates','OFFLINE');
    if(maintenance.status==='fulfilled')renderMaintenance(maintenance.value);
  }

  async function mutation(url,body){
    try{
      return await api(url,{method:'POST',headers:{'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});
    }catch(error){
      status(error.status===428?'Step-Up مطلوب قبل عملية الصيانة.':error.message,'error');
      throw error;
    }
  }

  $('#serverLifecycleRefresh')?.addEventListener('click',()=>loadAll());
  $('#serverLifecycleNtp')?.addEventListener('click',async()=>{
    try{const data=await mutation('/api/server-lifecycle/time/enable-ntp',{});status(`NTP enabled · synchronized ${data.time?.synchronized?'YES':'PENDING'}`,'ok');await loadAll();}catch{}
  });
  $('#serverLifecycleHostnamePreview')?.addEventListener('click',async()=>{
    try{
      const hostname=($('#serverLifecycleHostnameInput')?.value||'').trim().toLowerCase().replace(/\.$/,'');
      if(!hostname)throw new Error('أدخل Server FQDN أولًا.');
      const data=await mutation('/api/server-lifecycle/hostname/preview',{hostname});
      status(`Hostname preview #${data.preview.id}: ${safe(data.preview.snapshot?.current_hostname)} → ${safe(data.preview.snapshot?.desired_hostname)}. راجع ثم Apply.`,'warning');
      await loadAll();
    }catch{}
  });
  $('#serverLifecycleUpdatePreview')?.addEventListener('click',async()=>{
    try{const data=await mutation('/api/server-lifecycle/maintenance/preview',{kind:'system-updates'});status(`Update preview #${data.preview.id} created · fingerprint ${safe(data.preview.fingerprint).slice(0,16)}…`,'ok');await loadAll();}catch{}
  });
  $('#serverLifecycleRebootPreview')?.addEventListener('click',async()=>{
    try{const data=await mutation('/api/server-lifecycle/maintenance/preview',{kind:'reboot'});status(`Reboot impact preview #${data.preview.id} created. No reboot executed.`,'warning');await loadAll();}catch{}
  });
  $('#serverLifecycleMaintenance')?.addEventListener('click',async event=>{
    const apply=event.target.closest('[data-apply-maintenance]');
    if(apply){
      try{const data=await mutation(`/api/server-lifecycle/maintenance/${encodeURIComponent(apply.dataset.applyMaintenance)}/apply`,{});status(`Hostname applied: ${safe(data.previous_hostname)} → ${safe(data.hostname)}`,'ok');const input=$('#serverLifecycleHostnameInput');if(input)input.value=data.hostname||'';await loadAll();}catch{}
      return;
    }
    const cancel=event.target.closest('[data-cancel-maintenance]');if(!cancel)return;
    try{await mutation(`/api/server-lifecycle/maintenance/${encodeURIComponent(cancel.dataset.cancelMaintenance)}/cancel`,{});status('Maintenance preview cancelled.','ok');await loadAll();}catch{}
  });
  root.querySelector('[data-adv-tab="server"]')?.addEventListener('click',()=>loadAll());
  loadAll();
})();
