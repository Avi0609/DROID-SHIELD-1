const input=document.getElementById("apk");
const btn=document.getElementById("analyzeBtn");
const filename=document.getElementById("filename");
let chart;

input.addEventListener("change",()=>{
  const f=input.files[0];
  filename.textContent=f?f.name:"No file selected";
  btn.disabled=!f;
});

btn.addEventListener("click", async()=>{
  const f=input.files[0];
  if(!f)return;
  btn.disabled=true;
  document.getElementById("progress").classList.remove("hidden");
  let p=15;
  const timer=setInterval(()=>{p=Math.min(90,p+Math.random()*12);document.getElementById("bar").style.width=p+"%";},350);

  const fd=new FormData(); fd.append("apk",f);
  try{
    const r=await fetch("/analyze",{method:"POST",body:fd});
    const data=await r.json();
    if(!r.ok) throw new Error(data.error||"Analysis failed");
    clearInterval(timer);
    document.getElementById("bar").style.width="100%";
    render(data);
  }catch(e){
    clearInterval(timer);
    alert(e.message);
  }finally{
    btn.disabled=false;
  }
});

function render(d){
  document.getElementById("results").classList.remove("hidden");
  document.getElementById("score").textContent=d.risk_score;
  const c=document.getElementById("classification");
  c.textContent=d.classification.toUpperCase();
  c.className="classification "+d.classification.toLowerCase();
  document.getElementById("summary").textContent=d.summary;
  document.getElementById("file").textContent=d.file;
  document.getElementById("package").textContent=d.package;
  document.getElementById("size").textContent=d.size_mb+" MB";
  document.getElementById("sha").textContent=d.sha256;
  document.getElementById("parser").textContent=d.androguard?"Androguard":"ZIP fallback";

  ["activities","services","receivers","urls","ips"].forEach(k=>{
    document.getElementById(k).textContent=d[k]?.length??0;
  });

  const fac=document.getElementById("factors"); fac.innerHTML="";
  (d.risk_factors||[]).slice(0,12).forEach(x=>{
    fac.innerHTML+=`<div class="factor"><span class="dot ${x.severity}"></span><div><b>${escapeHtml(x.title)}</b><small>${escapeHtml(x.detail)} · +${x.points} points</small></div></div>`;
  });
  if(!fac.innerHTML) fac.innerHTML="<p class='muted'>No significant indicators detected.</p>";

  fillChips("permissions",d.permissions);
  fillChips("apis",d.suspicious_apis);

  if(chart) chart.destroy();
  chart=new Chart(document.getElementById("chart"),{
    type:"bar",
    data:{labels:Object.keys(d.scores),datasets:[{label:"Risk contribution",data:Object.values(d.scores)}]},
    options:{responsive:true,indexAxis:"y",plugins:{legend:{display:false}},scales:{x:{beginAtZero:true,max:25}}}
  });
  window.scrollTo({top:document.getElementById("results").offsetTop-20,behavior:"smooth"});
}
function fillChips(id,arr){
  const el=document.getElementById(id);el.innerHTML="";
  (arr||[]).slice(0,30).forEach(x=>el.innerHTML+=`<span class="chip">${escapeHtml(x)}</span>`);
  if(!el.innerHTML)el.innerHTML="<span class='muted'>None detected</span>";
}
function escapeHtml(s){
  return String(s).replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[m]));
}
