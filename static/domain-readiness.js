(()=>{
  const root=document.getElementById('advancedops');if(!root)return;
  const card=root.querySelector('#advDomainReadinessCard');
  const select=root.querySelector('#domainReadinessDomain');
  const refresh=root.querySelector('#domainReadinessRefresh');
  const score=root.querySelector('#domainReadinessScore');
  const grade=root.querySelector('#domainReadinessGrade');
  const meta=root.querySelector('#domainReadinessMeta');
  const list=root.querySelector('#domainReadinessChecks');
  if(!card||!select||!refresh||!score||!grade||!meta||!list)return;

  const api=async(url)=>{const r=await fetch(url,{credentials:'same-origin',headers:{Accept:'application/json'}});let b={};try{b=await r.json()}catch{}if(!r.ok||b.ok===false)throw new Error(b.error||`HTTP ${r.status}`);return b};
  const option=(value,text)=>{const o=document.createElement('option');o.value=value;o.textContent=text;return o};
  const clear=()=>{score.textContent='—';grade.textContent='—';meta.textContent='اختر نطاقًا لعرض Control-plane Readiness.';list.replaceChildren()};

  function ensureFleet(){
    let wrap=card.querySelector('#domainReadinessFleet');
    if(wrap)return wrap;
    wrap=document.createElement('div');wrap.id='domainReadinessFleet';
    wrap.innerHTML=`<div class="metrics-summary domain-fleet-summary"><div><small>DOMAINS</small><b id="domainFleetTotal">—</b></div><div><small>A GRADE</small><b id="domainFleetA">—</b></div><div><small>ATTENTION</small><b id="domainFleetAttention">—</b></div><div><small>WORST</small><b id="domainFleetWorst">—</b></div></div><div id="domainFleetProblems" class="adv-list"><div class="empty-state">جاري بناء Fleet Health…</div></div>`;
    meta.before(wrap);
    return wrap;
  }

  function checkRow(item){
    const row=document.createElement('div');row.className='adv-row';
    const main=document.createElement('div');main.className='adv-row-main';
    const title=document.createElement('strong');title.textContent=`${item.ok?'✓':'⚠'} ${item.label}`;
    const detail=document.createElement('span');detail.textContent=item.detail||'';
    if(item.ok)title.style.color='#37ff9a';else title.style.color='#ffd873';
    main.append(title,detail);row.append(main);
    if(!item.ok&&item.view){const actions=document.createElement('div');actions.className='adv-row-actions';const link=document.createElement('a');link.className='tiny ghost';link.href=`#${item.view}`;link.textContent='فتح القسم';actions.append(link);row.append(actions)}
    return row;
  }

  function render(r){
    score.textContent=`${Number(r.score||0)}%`;grade.textContent=r.grade||'—';
    score.style.color=Number(r.score||0)>=90?'#37ff9a':Number(r.score||0)>=75?'#ffd873':'#ff7d7d';
    grade.style.color=score.style.color;
    const dns=r.dns||{},ssl=r.ssl||{},mail=r.mail||{},life=r.domain_lifecycle||{};
    meta.textContent=`${r.domain} · ${r.kind} · DNS ${dns.bound?(dns.provider||'BOUND').toUpperCase():'UNBOUND'} · ${dns.pending_previews||0} pending preview · AutoSSL ${ssl.auto_renew?'ON':'OFF'} · DNSSEC ${dns.dnssec?.supported_by_bound_provider?'CAPABLE':'UNAVAILABLE'} · ${life.aliases||0} aliases · Mail ${mail.enabled?'ON':'OFF'}`;
    list.replaceChildren();(r.checks||[]).forEach(item=>list.append(checkRow(item)));
    if(!(r.checks||[]).length){const e=document.createElement('div');e.className='empty-state';e.textContent='لا توجد checks.';list.append(e)}
  }

  function renderFleet(rows){
    ensureFleet();
    const ordered=[...rows].sort((a,b)=>Number(a.score||0)-Number(b.score||0)||String(a.domain).localeCompare(String(b.domain)));
    const aCount=ordered.filter(x=>Number(x.score||0)>=90).length;
    const attention=ordered.filter(x=>Number(x.score||0)<75).length;
    card.querySelector('#domainFleetTotal').textContent=String(ordered.length);
    card.querySelector('#domainFleetA').textContent=String(aCount);
    card.querySelector('#domainFleetAttention').textContent=String(attention);
    card.querySelector('#domainFleetWorst').textContent=ordered.length?`${Number(ordered[0].score||0)}%`:'—';
    const problems=card.querySelector('#domainFleetProblems');
    const focus=ordered.filter(x=>Number(x.score||0)<90).slice(0,5);
    problems.replaceChildren();
    if(!focus.length){const e=document.createElement('div');e.className='empty-state';e.textContent=ordered.length?'كل النطاقات الحالية A-grade.':'لا توجد نطاقات مُدارة.';problems.append(e);return;}
    focus.forEach(item=>{
      const row=document.createElement('div');row.className='adv-row';
      const main=document.createElement('div');main.className='adv-row-main';
      const title=document.createElement('strong');title.textContent=`${item.domain} · ${Number(item.score||0)}% · ${item.grade||'—'}`;
      title.style.color=Number(item.score||0)>=75?'#ffd873':'#ff7d7d';
      const detail=document.createElement('span');detail.textContent=`${(item.recommendations||[]).length} توصية · ${item.owner||''}`;
      main.append(title,detail);row.append(main);
      const actions=document.createElement('div');actions.className='adv-row-actions';
      const pick=document.createElement('button');pick.type='button';pick.className='tiny ghost';pick.dataset.domainReadinessPick=item.domain;pick.textContent='فتح';actions.append(pick);row.append(actions);
      problems.append(row);
    });
    problems.querySelectorAll('[data-domain-readiness-pick]').forEach(btn=>btn.addEventListener('click',()=>{select.value=btn.dataset.domainReadinessPick;const row=ordered.find(x=>x.domain===select.value);if(row)render(row)}));
  }

  async function loadDomain(){const domain=select.value;if(!domain){clear();return}try{refresh.disabled=true;const d=await api(`/api/domain-health?domain=${encodeURIComponent(domain)}`);render(d.readiness||{})}catch(e){meta.textContent=`Domain Readiness: ${e.message}`}finally{refresh.disabled=false}}
  async function init(){
    try{
      const d=await api('/api/domain-health');
      const rows=d.domains||[];
      const ordered=[...rows].sort((a,b)=>Number(a.score||0)-Number(b.score||0)||String(a.domain).localeCompare(String(b.domain)));
      select.replaceChildren(option('','اختر نطاقًا…'));
      ordered.forEach(r=>select.append(option(r.domain,r.owner&&r.owner!=='admin'?`${r.domain} · ${r.owner} · ${r.score}%`: `${r.domain} · ${r.score}%`)));
      renderFleet(ordered);
      if(ordered.length){select.value=ordered[0].domain;render(ordered[0])}else clear();
    }catch(e){meta.textContent=`تعذر تحميل Domain Readiness: ${e.message}`}
  }
  select.addEventListener('change',loadDomain);refresh.addEventListener('click',async()=>{await init();await loadDomain()});init();
})();
