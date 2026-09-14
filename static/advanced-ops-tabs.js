(()=>{
  const root=document.getElementById('advancedops');
  if(!root)return;

  const groups={
    trust:['#advDomainReadinessCard','#advChangeSafetyCard','#domainGuardianCard'],
    edge:['#advDnsCard','#advSslCard','#advMailOpsCard'],
    runtime:['#advPhpCard','#advPostgresCard','#advMigrationCard'],
    server:['#advServicesCard','#advFleetCard'],
  };
  const tabs=[...root.querySelectorAll('[data-adv-tab]')];
  const selectors=Object.values(groups).flat();

  function setTab(requested,{focus=false}={}){
    const name=groups[requested]&&tabs.some(tab=>tab.dataset.advTab===requested)?requested:'trust';
    const visible=new Set(groups[name]);
    for(const selector of selectors){
      const card=root.querySelector(selector);
      if(card)card.hidden=!visible.has(selector);
    }
    for(const tab of tabs){
      const active=tab.dataset.advTab===name;
      tab.classList.toggle('active',active);
      tab.setAttribute('aria-selected',active?'true':'false');
      tab.tabIndex=active?0:-1;
      if(active&&focus)tab.focus({preventScroll:true});
    }
    root.dataset.advActiveTab=name;
    try{sessionStorage.setItem('nvp-advancedops-tab',name);}catch{}
  }

  tabs.forEach((tab,index)=>{
    tab.addEventListener('click',()=>setTab(tab.dataset.advTab));
    tab.addEventListener('keydown',event=>{
      if(!['ArrowLeft','ArrowRight','Home','End'].includes(event.key))return;
      event.preventDefault();
      let target=index;
      if(event.key==='ArrowLeft')target=(index-1+tabs.length)%tabs.length;
      if(event.key==='ArrowRight')target=(index+1)%tabs.length;
      if(event.key==='Home')target=0;
      if(event.key==='End')target=tabs.length-1;
      setTab(tabs[target].dataset.advTab,{focus:true});
    });
  });

  let initial='trust';
  try{
    const remembered=sessionStorage.getItem('nvp-advancedops-tab');
    if(remembered&&groups[remembered])initial=remembered;
  }catch{}
  setTab(initial);
})();
