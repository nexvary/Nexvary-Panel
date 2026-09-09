(()=>{
  const root=document.getElementById('transfers');
  if(!root)return;
  const csrf=document.querySelector('meta[name="csrf-token"]')?.content||'';
  const providerState=document.getElementById('transferProviderState');
  const providerEngine=document.getElementById('transferProviderEngine');
  const notice=document.getElementById('transferNotice');
  const usage=document.getElementById('transferUsage');
  const domainSelect=document.getElementById('transferDomain');
  const list=document.getElementById('transferList');
  const status=document.getElementById('transferStatus');
  const dialog=document.getElementById('transferKeyDialog');
  const keyForm=document.getElementById('transferKeyForm');
  let state={accounts:[],sites:[],provider:{online:false,engine:'offline'},used:0,limit:0};

  const say=(msg,kind='')=>{status.textContent=msg||'';status.className=`transfer-status ${kind}`.trim();};
  const api=async(url,opts={})=>{const headers={...(opts.headers||{})};if(opts.method&&opts.method!=='GET')headers['X-CSRF-Token']=csrf;if(opts.body&&!headers['Content-Type'])headers['Content-Type']='application/json';const r=await fetch(url,{credentials:'same-origin',...opts,headers});let body={};try{body=await r.json();}catch{}if(!r.ok)throw new Error(body.error||`HTTP ${r.status}`);return body;};
  const empty=(text)=>{const d=document.createElement('div');d.className='empty-state';d.textContent=text;return d;};
  const actionButton=(text,action,id,cls='tiny ghost')=>{const b=document.createElement('button');b.type='button';b.className=cls;b.textContent=text;b.dataset.action=action;b.dataset.id=String(id);return b;};

  function renderProvider(){const online=!!state.provider?.online;root.classList.toggle('transfer-provider-offline',!online);providerState.textContent=online?'ONLINE':'OFFLINE';providerState.style.color=online?'#48ffae':'#ff7d7d';providerEngine.textContent=state.provider?.engine||'offline';notice.className=`transfer-notice royal-frame ${online?'online':'offline'}`;notice.textContent=online?'OpenSSH Transfer Agent متصل. الحسابات الجديدة تعمل بمفتاح عام داخل Chroot للموقع فقط.':'SFTP Provider غير متصل. ثبّت/فعّل Transfer Center بخيار --with-sftp؛ لن يتم إنشاء بيانات وهمية أثناء وضع Offline.';}
  function renderSites(){const current=domainSelect.value;domainSelect.replaceChildren();const rows=(state.sites||[]).filter(s=>s.enabled&&s.limit>0&&s.used<s.limit);if(!rows.length){const o=document.createElement('option');o.value='';o.textContent='لا توجد مواقع متاحة ضمن السياسة والـQuota';domainSelect.append(o);domainSelect.disabled=true;return;}domainSelect.disabled=false;for(const s of rows){const o=document.createElement('option');o.value=s.domain;o.textContent=s.owner==='admin'?`${s.domain} · ${s.used}/${s.limit}`:`${s.domain} · ${s.owner} · ${s.used}/${s.limit}`;domainSelect.append(o);}if(rows.some(s=>s.domain===current))domainSelect.value=current;}
  function renderAccounts(){list.replaceChildren();if(!state.accounts.length){list.append(empty('لا توجد حسابات SFTP حتى الآن.'));return;}for(const a of state.accounts){const row=document.createElement('div');row.className='transfer-row';const main=document.createElement('div');main.className='transfer-main';const name=document.createElement('strong');name.textContent=a.label;const domain=document.createElement('span');domain.textContent=`${a.domain} · ${a.owner}`;const user=document.createElement('code');user.textContent=`SFTP user: ${a.system_user}`;main.append(name,domain,user);const meta=document.createElement('div');meta.className='transfer-meta';const active=document.createElement('b');active.textContent=a.enabled?'ACTIVE':'DISABLED';const fp=document.createElement('span');fp.textContent=a.key_fingerprint;const path=document.createElement('small');path.textContent='/site · port 22 · no shell';meta.append(active,fp,path);const actions=document.createElement('div');actions.className='transfer-actions';actions.append(actionButton('تدوير المفتاح','rotate',a.id),actionButton('حذف','delete',a.id,'tiny danger'));row.append(main,meta,actions);list.append(row);}}
  function render(){renderProvider();renderSites();usage.textContent=`${state.used??0} / ${state.limit??0}`;renderAccounts();}
  async function load(){try{state=await api('/api/transfers');render();}catch(e){say(e.message,'error');notice.textContent='تعذر قراءة حالة Transfer Center.';notice.className='transfer-notice royal-frame offline';}}

  document.getElementById('transferRefresh')?.addEventListener('click',load);
  document.getElementById('transferForm')?.addEventListener('submit',async(e)=>{e.preventDefault();if(!state.provider?.online)return say('SFTP Provider غير متصل.','error');say('جاري إنشاء حساب SFTP محصور…');try{await api('/api/transfers',{method:'POST',body:JSON.stringify({label:document.getElementById('transferLabel').value.trim(),domain:domainSelect.value,public_key:document.getElementById('transferPublicKey').value.trim()})});e.currentTarget.reset();say('تم إنشاء SFTP Account بدون Shell وبمفتاح عام فقط.','ok');await load();}catch(err){say(err.message.includes('step-up')?'يلزم Step-Up Authentication من صفحة الأمن أولًا.':err.message,'error');}});
  list?.addEventListener('click',async(e)=>{const b=e.target.closest('button[data-action][data-id]');if(!b)return;const id=Number(b.dataset.id);const a=state.accounts.find(x=>x.id===id);if(!a)return;if(b.dataset.action==='rotate'){document.getElementById('transferKeyId').value=String(id);document.getElementById('transferNewKey').value='';dialog.showModal();return;}if(!state.provider?.online)return say('SFTP Provider غير متصل.','error');b.disabled=true;try{await api(`/api/transfers/${id}`,{method:'DELETE'});say('تم حذف حساب النقل وإزالة Chroot/ACL الخاصة به.','ok');await load();}catch(err){say(err.message,'error');b.disabled=false;}});
  document.getElementById('transferKeyClose')?.addEventListener('click',()=>dialog.close());
  keyForm?.addEventListener('submit',async(e)=>{e.preventDefault();if(!state.provider?.online)return say('SFTP Provider غير متصل.','error');const id=Number(document.getElementById('transferKeyId').value);try{await api(`/api/transfers/${id}/key`,{method:'PUT',body:JSON.stringify({public_key:document.getElementById('transferNewKey').value.trim()})});dialog.close();say('تم تدوير المفتاح العام.','ok');await load();}catch(err){say(err.message.includes('step-up')?'يلزم Step-Up Authentication أولًا.':err.message,'error');}});
  load();
})();
