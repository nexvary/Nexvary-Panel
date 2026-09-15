(()=>{
  const root=document.getElementById('advFleetCard');
  if(!root)return;
  const csrf=document.querySelector('meta[name="csrf-token"]')?.content||'';
  const $=sel=>root.querySelector(sel);
  const status=document.getElementById('advStatus');
  let nodes=[];
  const say=(message,kind='')=>{if(!status)return;status.textContent=message||'';status.className=`adv-status ${kind}`.trim();};
  const api=async(url,options={})=>{
    const headers={Accept:'application/json',...(options.headers||{})};
    if(options.method&&options.method!=='GET')headers['X-CSRF-Token']=csrf;
    if(options.body&&!headers['Content-Type'])headers['Content-Type']='application/json';
    const response=await fetch(url,{credentials:'same-origin',...options,headers});
    let body={};try{body=await response.json();}catch{}
    if(!response.ok||body.ok===false)throw Object.assign(new Error(body.error||`HTTP ${response.status}`),{status:response.status,body});
    return body;
  };
  const button=(text,cls,handler)=>{const el=document.createElement('button');el.type='button';el.className=cls;el.textContent=text;el.addEventListener('click',handler);return el;};
  const render=()=>{
    const online=nodes.filter(n=>n.status==='online').length;
    const degraded=nodes.filter(n=>n.status==='degraded').length;
    const offline=nodes.filter(n=>n.status==='offline').length;
    $('#fleetNodeCount').textContent=String(nodes.length);
    $('#fleetOnlineCount').textContent=String(online);
    $('#fleetDegradedCount').textContent=String(degraded);
    $('#fleetOfflineCount').textContent=String(offline);
    const box=$('#fleetOrchestrationList');box.replaceChildren();
    if(!nodes.length){const e=document.createElement('div');e.className='empty-state';e.textContent='لا توجد Fleet Nodes.';box.append(e);return;}
    for(const node of nodes){
      const item=document.createElement('div');item.className='adv-row';item.dataset.nodeId=String(node.id);
      const main=document.createElement('div');main.className='adv-row-main';
      const strong=document.createElement('strong');strong.textContent=node.name;
      const latest=node.latest_probe||{};const capCount=Object.values(latest.capabilities||{}).filter(Boolean).length;
      const span=document.createElement('span');span.textContent=`${node.endpoint} · ${String(node.status).toUpperCase()} · ${latest.remote_version||'version ?'} · ${latest.latency_ms??'—'} ms · ${capCount} capabilities`;
      main.append(strong,span);
      const actions=document.createElement('div');actions.className='adv-row-actions';
      actions.append(button('Probe','tiny ghost',()=>probe(node.id)),button('حذف','tiny danger',()=>remove(node.id)));
      item.append(main,actions);box.append(item);
    }
  };
  async function load(){const body=await api('/api/fleet');nodes=body.nodes||[];render();}
  async function probe(id){try{const body=await api(`/api/fleet/${id}/probe`,{method:'POST'});const updated=body.node;nodes=nodes.map(n=>n.id===updated.id?updated:n);render();say(`${updated.name}: ${String(updated.status).toUpperCase()} · ${updated.latest_probe?.latency_ms??'—'} ms`,'ok');}catch(error){say(error.message,'error');}}
  async function remove(id){try{await api(`/api/fleet/${id}`,{method:'DELETE'});say('تم حذف Fleet Node.','ok');await load();}catch(error){say(error.status===428?'Step-Up مطلوب لحذف Fleet Node.':error.message,'error');}}
  $('#fleetCreateForm')?.addEventListener('submit',async event=>{event.preventDefault();try{await api('/api/fleet',{method:'POST',body:JSON.stringify({name:$('#fleetName').value.trim(),endpoint:$('#fleetEndpoint').value.trim()})});event.currentTarget.reset();say('تمت إضافة Fleet Node بعد فحص endpoint policy.','ok');await load();}catch(error){say(error.status===428?'Step-Up مطلوب لإضافة Fleet Node.':error.message,'error');}});
  $('#fleetProbeAllBtn')?.addEventListener('click',async()=>{try{const body=await api('/api/fleet/probe-all',{method:'POST',body:JSON.stringify({node_ids:nodes.slice(0,25).map(n=>n.id)})});nodes=body.nodes||nodes;render();say(`تم Probe لـ ${body.probed} Node بدون تنفيذ أي Remote action.`,'ok');}catch(error){say(error.message,'error');}});
  $('#fleetPlanBtn')?.addEventListener('click',async()=>{try{if(!nodes.length)throw new Error('أضف Fleet Node أولًا.');const operation=$('#fleetPlanOperation').value;const body=await api('/api/fleet/plan',{method:'POST',body:JSON.stringify({node_ids:nodes.slice(0,25).map(n=>n.id),operation})});const lines=[`ORCHESTRATION PREVIEW · ${body.operation}`,`Required capability: ${body.required_capability}`,`Ready: ${body.ready_count} · Blocked: ${body.blocked_count}`,`Remote Apply: ${body.apply_supported?'ENABLED':'DISABLED BY POLICY'}`,''];for(const node of body.nodes||[])lines.push(`${node.ready?'READY':'BLOCKED'} · ${node.name} · ${node.status} · ${node.remote_version||'version ?'} · ${node.reason}`);lines.push('',body.policy||'');$('#fleetPlanResult').textContent=lines.join('\n');say('تم إنشاء Fleet Orchestration Preview فقط؛ لم تُرسل أوامر Remote.','ok');}catch(error){say(error.message,'error');}});
  load().catch(error=>say(`Fleet: ${error.message}`,'error'));
})();
