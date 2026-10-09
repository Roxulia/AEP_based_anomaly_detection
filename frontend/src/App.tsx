import { ReactNode, useEffect, useState } from 'react'

const API = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'
type Summary = { detector_description: string; model_available: boolean; datasets: Record<string, {path:string;available:boolean}>; watch_dir:string; watch_dir_available:boolean; model?:{entropy_rate?:number;aep_threshold?:number;density_threshold?:number}; activity?:{total_requests:number;top_routes:Array<{route:string;count:number}>;status_counts:Record<string,number>;score_timeline:Array<{window_id:number;start_time:string;information_score:number;entropy_rate:number;final_anomalous:boolean}>}|null; evaluation?:{comparisons?:Record<string,{anomalous_windows:number;scorable_windows:number;metrics:{available:boolean;f1?:number;precision?:number;recall?:number}}>}|null }
type Alert = {id:number;created_at:string;acknowledged:boolean;final_anomalous:boolean|null;scorable?:boolean;start_time?:string;end_time?:string;information_score?:number;entropy_rate?:number;aep_deviation?:number;density_score?:number;anomaly_reasons?:string[];unscorable_reason?:string}
type DetectorMode = 'aep'|'density'|'hybrid'
type ExperimentEvent = {timestamp?:string;method?:string;uri?:string;normalized_uri?:string;status?:string;status_category?:string;url_group?:string;route_name?:string}
type ExperimentWindow = {window_id:number;start_time?:string;end_time?:string;client_ip?:string;event_count?:number;scorable?:boolean;final_anomalous?:boolean|null;information_score?:number;entropy_rate?:number;aep_deviation?:number;aep_threshold?:number;density?:number;density_score?:number;density_threshold?:number;novelty_detected?:boolean;unknown_state_count?:number;unknown_state_events?:Array<{event_index:number;state_description?:Record<string,string>}>;anomaly_reasons?:string[];unscorable_reason?:string;events?:ExperimentEvent[];encoded_states?:string[];state_descriptions?:Array<Record<string,string>>;transition_probabilities?:number[];least_probable_transitions?:Array<{from_state:string;to_state:string;probability:number}>}
type ExperimentComparison = {windows:number;scorable_windows:number;unscorable_windows:number;anomalous_windows:number;metrics:{available:boolean;reason?:string;f1?:number;precision?:number;recall?:number}}
type ExperimentAnomaly = {window_id:number;start_time?:string;end_time?:string;client_ip?:string;event_count:number;information_score?:number;entropy_rate?:number;aep_deviation?:number;density_score?:number;anomaly_reasons:string[];activities:ExperimentEvent[]}
type Experiment = {filename:string;detector_mode:DetectorMode;parse:Record<string,{files:number;parsed_rows:number;malformed_rows:number}>;preprocessing:{input_rows:number;processed_rows:number;skipped_rows:number;skipped_by_reason:Record<string,number>;missing_ip_rows:number};window_count:number;comparisons:Record<DetectorMode,ExperimentComparison>;results_by_mode:Record<DetectorMode,ExperimentWindow[]>;anomalies_by_mode:Record<DetectorMode,ExperimentAnomaly[]>;windows:ExperimentWindow[]}

async function request<T>(path:string, init?:RequestInit):Promise<T>{
  const response=await fetch(`${API}${path}`,init)
  if(!response.ok){const body=await response.json().catch(()=>({detail:response.statusText}));throw new Error(body.detail??'Request failed')}
  return response.json()
}

export default function App(){
  const [page,setPage]=useState<'overview'|'experiment'>('overview')
  const [summary,setSummary]=useState<Summary|null>(null)
  const [alerts,setAlerts]=useState<Alert[]>([])
  const [experiment,setExperiment]=useState<Experiment|null>(null)
  const [experimentMode,setExperimentMode]=useState<DetectorMode>('hybrid')
  const [busy,setBusy]=useState(false)
  const [message,setMessage]=useState('')
  const [error,setError]=useState('')
  const [searchQuery,setSearchQuery]=useState('')

  const refresh=async()=>{
    try { const [s,a]=await Promise.all([request<Summary>('/api/summary'),request<Alert[]>('/api/alerts')]);setSummary(s);setAlerts(a);setError('') }
    catch(e){setError(e instanceof Error?e.message:'Could not connect to the analysis API')}
  }
  useEffect(()=>{void refresh();const timer=setInterval(()=>void refresh(),10000);return()=>clearInterval(timer)},[])
  const run=async(path:string)=>{setBusy(true);setMessage('');setError('');try{const result=await request<Record<string,unknown>>(path,{method:'POST'});setMessage(JSON.stringify(result,null,2));await refresh()}catch(e){setError(e instanceof Error?e.message:'Action failed')}finally{setBusy(false)}}
  const upload=async(file?:File)=>{if(!file)return;setBusy(true);setExperiment(null);setError('');try{const form=new FormData();form.append('file',file);const result=await request<Experiment>('/api/experiment',{method:'POST',body:form});setExperiment(result);setExperimentMode(result.detector_mode??'hybrid')}catch(e){setError(e instanceof Error?e.message:'Analysis failed')}finally{setBusy(false)}}
  const acknowledge=async(id:number)=>{await request(`/api/alerts/${id}/acknowledge`,{method:'POST'});await refresh()}
  const unacknowledged=alerts.filter(a=>!a.acknowledged).length
  const experimentWindows=experiment?.results_by_mode?.[experimentMode]??experiment?.windows??[]
  const experimentAnomalies=experiment?.anomalies_by_mode?.[experimentMode]??[]
  const query=searchQuery.trim().toLowerCase()
  const visibleExperimentWindows=query?experimentWindows.filter(window=>JSON.stringify(window).toLowerCase().includes(query)):experimentWindows
  const visibleExperimentAnomalies=query?experimentAnomalies.filter(item=>JSON.stringify(item).toLowerCase().includes(query)):experimentAnomalies
  const visibleAlerts=query?alerts.filter(alert=>JSON.stringify(alert).toLowerCase().includes(query)):alerts
  const visibleRoutes=(summary?.activity?.top_routes??[]).filter(item=>!query||item.route.toLowerCase().includes(query))
  const totalWindows=experiment?.window_count??experimentWindows.length
  const anomalous=experimentWindows.filter(w=>w.final_anomalous===true).length
  const parsedRequests=Object.values(experiment?.parse??{}).reduce((n,x)=>n+x.parsed_rows,0)
  const malformedLines=Object.values(experiment?.parse??{}).reduce((n,x)=>n+x.malformed_rows,0)

  return <div className="shell">
    <aside className="sidebar"><div className="brand"><span className="brand-mark">S</span><span>signal<span className="brand-dot">.</span></span></div><div className="workspace"><span className="workspace-icon">⌘</span><span><b>Workspace</b><small>Local analysis</small></span><span className="chevron">⌄</span></div>
      <div className="nav-label">ANALYSIS</div><button className={`nav-item ${page==='overview'?'active':''}`} onClick={()=>setPage('overview')}><span>◫</span> Overview</button><button className={`nav-item ${page==='experiment'?'active':''}`} onClick={()=>setPage('experiment')}><span>⌁</span> Experiments</button>
      <div className="nav-label spaced">MONITORING</div><button className="nav-item" onClick={()=>setPage('overview')}><span>◉</span> Alerts <span className="badge">{unacknowledged}</span></button>
      <div className="sidebar-bottom"><div className="status-led"/><span>Statistical detector</span><small>{summary?.model_available?'Ready':'Model pending'}</small></div>
    </aside>
    <main className="main"><header className="topbar"><div className="crumb">Signal <span>/</span> {page==='overview'?'Overview':'Experiments'}</div><label className="global-search"><span aria-hidden="true">⌕</span><input aria-label="Search routes, windows, and alerts" placeholder="Search routes, windows, alerts…" value={searchQuery} onChange={event=>setSearchQuery(event.target.value)}/></label><div className="top-actions"><span className="live-indicator"><i/> API {error?'offline':'connected'}</span><button className="notification-button" aria-label={`${unacknowledged} unreviewed alerts`} title="View alerts" onClick={()=>{setPage('overview');setTimeout(()=>document.getElementById('alerts-panel')?.scrollIntoView({behavior:'smooth'}),0)}}>♧{unacknowledged>0&&<i>{unacknowledged}</i>}</button><button className="avatar" title="Administrator">A</button></div></header>
      <div className="content">
        {error&&<div className="error-banner">{error}</div>}
        {page==='overview'?<>
          <section className="page-heading"><div><div className="eyebrow">SERVER ACTIVITY</div><h1>Overview</h1><p>Statistical analysis of request behavior across your log data.</p></div><div className="heading-actions"><button className="button secondary" disabled={busy} onClick={()=>void run('/api/build')}>Build detector</button><button className="button secondary" disabled={busy||!summary?.model_available} onClick={()=>void run('/api/evaluate')}>Evaluate Test</button><button className="button secondary" disabled={busy||!summary?.model_available} onClick={()=>void run('/api/monitor/scan')}>Scan now</button><button className="button secondary" onClick={()=>void refresh()}>↻ <span>Refresh</span></button></div></section>
          <section className="metric-grid"><Metric label="Open alerts" value={String(unacknowledged).padStart(2,'0')} detail="Require review" icon="!" tone="orange"/><Metric label="Model status" value={summary?.model_available?'Ready':'Pending'} detail={summary?.model_available?'Fitted detector available':'Build after datasets are added'} icon="◈" tone="green"/><Metric label="Data sources" value={`${Object.values(summary?.datasets??{}).filter(d=>d.available).length}/3`} detail="Train · Validate · Test" icon="▤" tone="blue"/><Metric label="Watch folder" value={summary?.watch_dir_available?'Available':'Waiting'} detail="Poller runs separately" icon="◉" tone="purple"/></section>
          <section className="split-grid"><div className="panel dataset-panel"><PanelTitle title="Dataset folders" subtitle="Configured input locations"/><div className="dataset-list">{Object.entries(summary?.datasets??{}).map(([name,data],i)=><div className="dataset-row" key={name}><span className={`dataset-icon d${i}`}>{i===0?'↥':i===1?'◇':'↧'}</span><span className="dataset-name"><b>{name[0].toUpperCase()+name.slice(1)}</b><small>{data.path}</small></span><span className={`state-pill ${data.available?'ready':''}`}><i/>{data.available?'Available':'Placeholder'}</span></div>)}</div><div className="panel-foot">Folders are used as provided. No automatic re-splitting.{summary?.model?.entropy_rate!==undefined&&<span> · Entropy rate {fmt(summary.model.entropy_rate)} bits/request</span>}</div></div>
            <div className="panel detector-panel"><PanelTitle title="Detector composition" subtitle="Interpretable statistical methods"/><div className="method"><div className="method-symbol blue">Z</div><div><b>Normalized self-information</b><small>Markov sequence likelihood per request</small></div><span className="method-tag">BASE</span></div><div className="method"><div className="method-symbol violet">Δ</div><div><b>AEP deviation</b><small>Distance from learned entropy rate</small></div><span className="method-tag">TYPICALITY</span></div><div className="method"><div className="method-symbol orange">⌁</div><div><b>Information-score density</b><small>KDE rarity under normal windows</small></div><span className="method-tag">KDE</span></div><div className="hybrid-note"><span>✳</span> Hybrid mode combines AEP and density decisions.</div></div></section>
          {summary?.activity&&<section className="panel activity-panel"><PanelTitle title="Test traffic profile" subtitle={`${summary.activity.total_requests.toLocaleString()} usable requests in the latest Test evaluation`}/><div className="activity-grid"><div><div className="mini-label">NORMALIZED ROUTES</div>{visibleRoutes.length?visibleRoutes.map(item=><div className="route-bar-row" key={item.route}><span title={item.route}>{item.route}</span><div><i style={{width:`${Math.max(3,item.count/Math.max(...summary.activity!.top_routes.map(x=>x.count))*100)}%`}}/></div><b>{item.count}</b></div>):<div className="muted-empty">{query?'No routes match your search.':'No usable request rows.'}</div>}<div className="status-row"><span>STATUS CLASSES</span>{Object.entries(summary.activity.status_counts).map(([status,count])=><i key={status}>{status} <b>{count}</b></i>)}</div></div><div><div className="mini-label">NORMALIZED SELF-INFORMATION BY WINDOW</div>{summary.activity.score_timeline.length?<div className="score-chart">{summary.activity.score_timeline.map((point,i)=>{const max=Math.max(...summary.activity!.score_timeline.map(x=>x.information_score),0.01);return <i key={`${point.window_id}-${i}`} title={`Window ${point.window_id}: ${fmt(point.information_score)} bits`} className={point.final_anomalous?'outlier':''} style={{height:`${Math.max(5,point.information_score/max*100)}%`}}/>})}</div>:<div className="muted-empty">No scorable windows in the latest evaluation.</div>}<div className="chart-legend"><i/> information score <span className="legend-outlier"/> statistical outlier</div></div></div></section>}
          {summary?.evaluation?.comparisons&&<section className="panel compare-panel"><PanelTitle title="Test-set detector comparison" subtitle="Evaluation uses the configured Test folder; labels are optional."/><div className="comparison-grid">{Object.entries(summary.evaluation.comparisons).map(([name,result])=><div className="comparison-card" key={name}><span>{name.toUpperCase()}</span><b>{result.anomalous_windows} <small>outliers</small></b><div>{result.scorable_windows} scorable windows</div><small>{result.metrics.available?`F1 ${fmt(result.metrics.f1)} · Precision ${fmt(result.metrics.precision)} · Recall ${fmt(result.metrics.recall)}`:'Ground-truth metrics unavailable'}</small></div>)}</div></section>}
          <section className="panel alerts-panel" id="alerts-panel"><PanelTitle title="Recent alerts" subtitle="Atypical or unscorable windows from the watched log folder" action={<button className="text-button" onClick={()=>void refresh()}>View latest ↗</button>}/>
            {!visibleAlerts.length?<div className="empty-state"><div className="empty-icon">✓</div><b>{query?'No matching alerts':'No alerts yet'}</b><span>{query?'Try another search.':'New findings from the watched folder will appear here.'}</span></div>:<div className="table-wrap"><table><thead><tr><th>WINDOW</th><th>FINDING</th><th>INFO SCORE</th><th>AEP DEVIATION</th><th>DENSITY SCORE</th><th></th></tr></thead><tbody>{visibleAlerts.slice(0,8).map(alert=><tr key={alert.id}><td><b>{alert.start_time??alert.created_at}</b><small>{alert.end_time??'Watched folder'}</small></td><td><span className={`finding ${alert.scorable===false?'unknown':''}`}><i/>{alert.scorable===false?'Unscorable':'Statistical outlier'}</span></td><td>{fmt(alert.information_score)}</td><td>{fmt(alert.aep_deviation)}</td><td>{fmt(alert.density_score)}</td><td>{alert.acknowledged?<span className="ack">Reviewed</span>:<button className="text-button" onClick={()=>void acknowledge(alert.id)}>Acknowledge</button>}</td></tr>)}</tbody></table></div>}
          </section>
          <div className="footnote">An outlier is statistically unusual under the fitted detector. It does not by itself indicate malicious activity.</div>
        </>:<>
          <section className="page-heading"><div><div className="eyebrow">OFFLINE ANALYSIS</div><h1>Experiments</h1><p>Upload a supported raw request log and analyze its windows with the saved detector.</p></div></section>
          {!summary?.model_available?<div className="panel setup-panel"><div className="empty-icon">◈</div><h2>Detector not built yet</h2><p>Add data to the configured Train and Validate folders, then run the build command from the project instructions.</p><code>python -m src.aep_anomaly build</code></div>:<div className="panel upload-panel"><div className="upload-icon">↥</div><h2>Analyze a log file</h2><p>Upload a raw log using the supported route-request format. The file is analyzed locally against the saved detector.</p><label className="button primary upload-button">Choose log file<input type="file" accept=".log,.txt" disabled={busy} onChange={e=>void upload(e.target.files?.[0])}/></label><small className="privacy-note">Raw logs are processed by the local analysis service.</small>{busy&&<div className="loading"><span/> Parsing and scoring windows…</div>}</div>}
          {error&&page==='experiment'&&<div className="error-banner">{error}</div>}
          {experiment&&<section className="panel experiment-results">
            <PanelTitle title={experiment.filename} subtitle={`${parsedRequests.toLocaleString()} parsed requests · ${experiment.preprocessing.processed_rows.toLocaleString()} processed · ${experiment.preprocessing.skipped_rows.toLocaleString()} skipped`}/>
            <div className="result-stats">
              <Metric label="Windows analyzed" value={String(totalWindows)} detail="Using saved detector" icon="▦" tone="blue"/>
              <Metric label="Statistical outliers" value={String(anomalous)} detail={`${experimentMode.toUpperCase()} decision`} icon="!" tone="orange"/>
              <Metric label="Malformed lines" value={String(malformedLines)} detail="Reported by parser" icon="≋" tone="purple"/>
              <Metric label="Missing IP" value={String(experiment.preprocessing.missing_ip_rows)} detail="Grouped as unknown IP" icon="◎" tone="green"/>
            </div>
            <div className="comparison-grid experiment-comparison">
              {(['aep','density','hybrid'] as DetectorMode[]).map(mode=>{const result=experiment.comparisons?.[mode];return result?<button type="button" className={`comparison-card mode-card ${experimentMode===mode?'selected':''}`} key={mode} onClick={()=>setExperimentMode(mode)}>
                <span>{mode.toUpperCase()}</span><b>{result.anomalous_windows} <small>outliers</small></b><div>{result.scorable_windows} scorable · {result.unscorable_windows} unscorable</div><small>{result.metrics.available?`F1 ${fmt(result.metrics.f1)} · Precision ${fmt(result.metrics.precision)} · Recall ${fmt(result.metrics.recall)}`:result.metrics.reason??'Ground-truth metrics unavailable'}</small>
              </button>:null})}
            </div>
            <div className="experiment-table-heading"><div><h3>{experimentMode.toUpperCase()} window results</h3><p>Thresholds and event details from each scored sequence.</p></div><span>{anomalous} of {totalWindows} flagged</span></div>
            <section className="anomaly-activity-section"><div className="anomaly-activity-heading"><div><h3>Flagged activity</h3><p>Requests are grouped under each anomalous window for review.</p></div><span>{experimentAnomalies.length} anomalous windows</span></div>
              {!visibleExperimentAnomalies.length?<div className="muted-empty">{query?'No flagged activity matches your search.':`No windows were flagged in ${experimentMode.toUpperCase()} mode.`}</div>:visibleExperimentAnomalies.map(anomaly=><article className="anomaly-activity-card" key={anomaly.window_id}>
                <header><div><b>Window #{anomaly.window_id+1}</b><small>{anomaly.start_time??'Unknown start'}{anomaly.end_time&&anomaly.end_time!==anomaly.start_time?` – ${anomaly.end_time}`:''}</small></div><span>{anomaly.client_ip??'Unknown IP'} · {anomaly.event_count} requests</span></header>
                <p className="activity-reasons">{anomaly.anomaly_reasons.join(' · ')||'Flagged by the selected detector mode.'}</p>
                <ol>{anomaly.activities.map((activity,j)=><li key={`${activity.timestamp}-${j}`}><time>{activity.timestamp??'Unknown time'}</time><b>{activity.method??'?'}</b><code>{activity.normalized_uri??activity.uri??'unknown route'}</code><span>{activity.status??'—'}{activity.status_category?` · ${activity.status_category}`:''}</span>{activity.route_name&&<small>{activity.route_name}</small>}</li>)}</ol>
              </article>)}
            </section>
            {!visibleExperimentWindows.length?<div className="muted-empty">{query?'No windows match your search.':'No windows were available to score from this file.'}</div>:<div className="table-wrap"><table className="experiment-table"><thead><tr><th>WINDOW / TIME</th><th>IP</th><th>EVENTS</th><th>DECISION</th><th>INFO SCORE</th><th>ENTROPY RATE</th><th>AEP DEVIATION / LIMIT</th><th>DENSITY / SCORE / LIMIT</th><th>DETAILS</th></tr></thead><tbody>{visibleExperimentWindows.map((w,i)=><tr key={`${w.window_id}-${i}`}>
              <td><b>#{w.window_id+1}</b><small>{w.start_time??'Unknown start'}{w.end_time&&w.end_time!==w.start_time?` – ${w.end_time}`:''}</small></td>
              <td>{w.client_ip??'—'}</td><td>{w.event_count??w.events?.length??'—'}</td>
              <td><span className={`finding ${w.scorable===false?'unknown':w.final_anomalous?'':'normal'}`}><i/>{w.scorable===false?'Unscorable':w.final_anomalous?'Anomalous':'Normal'}</span></td>
              <td>{fmt(w.information_score)}</td><td>{fmt(w.entropy_rate)}</td><td>{fmt(w.aep_deviation)} / {fmt(w.aep_threshold)}</td><td>{fmt(w.density)} / {fmt(w.density_score)} / {fmt(w.density_threshold)}</td>
              <td><details className="window-details"><summary>Inspect</summary><div className="window-inspection">
                {w.unscorable_reason&&<p className="unscorable-reason">{w.unscorable_reason}</p>}
                {w.anomaly_reasons?.length?<div><b>Why flagged</b><ul>{w.anomaly_reasons.map(reason=><li key={reason}>{reason}</li>)}</ul></div>:<p>{w.final_anomalous?'No detector reason was returned.':'No anomaly reason; scores are within the selected mode threshold.'}</p>}
                {w.novelty_detected&&<p>Novel states: {w.unknown_state_count??w.unknown_state_events?.length??0}. These states were mapped to the model’s reserved unknown state for scoring.</p>}
                {w.state_descriptions?.length?<div><b>Encoded state flow</b><ol>{w.state_descriptions.map((state,j)=><li key={`${w.encoded_states?.[j]??'state'}-${j}`}>{state.method??'unknown method'} · {state.url_group??'unknown route group'} · {state.status_category??'unknown status'}{w.encoded_states?.[j]?` · ${w.encoded_states[j].slice(-8)}`:''}</li>)}</ol></div>:null}
                {w.transition_probabilities?.length?<div><b>Transition probabilities</b><ul>{w.transition_probabilities.map((probability,j)=><li key={`transition-${j}`}>{w.encoded_states?.[j]?.slice(-8)??`state ${j+1}`} → {w.encoded_states?.[j+1]?.slice(-8)??`state ${j+2}`} · p={fmt(probability)}</li>)}</ul></div>:null}
                {w.least_probable_transitions?.length?<div><b>Least-probable transitions</b><ul>{w.least_probable_transitions.map((item,j)=><li key={`${item.from_state}-${item.to_state}-${j}`}>{item.from_state.slice(-8)} → {item.to_state.slice(-8)} · p={fmt(item.probability)}</li>)}</ul></div>:null}
                {w.events?.length?<div><b>Requests in window</b><ul>{w.events.map((event,j)=><li key={`${event.timestamp}-${j}`}><code>{event.timestamp??'time unknown'}</code> · {event.method??'?' } {event.normalized_uri??event.uri??'unknown route'} · {event.status??'status unknown'}{event.route_name?` · ${event.route_name}`:''}</li>)}</ul></div>:null}
              </div></details></td>
            </tr>)}</tbody></table></div>}
            <div className="parse-summary"><b>Parsing details</b>{Object.entries(experiment.parse).map(([kind,stats])=><span key={kind}>{kind}: {stats.files} file(s), {stats.parsed_rows} parsed, {stats.malformed_rows} malformed</span>)}{Object.entries(experiment.preprocessing.skipped_by_reason??{}).map(([reason,count])=><span key={reason}>Skipped {reason}: {count}</span>)}</div>
            <div className="footnote">An anomaly means the sequence is statistically unusual under the saved model; it does not establish malicious activity.</div>
          </section>}
        </>}
        {message&&<pre className="action-output">{message}</pre>}
      </div>
    </main>
  </div>
}

function Metric({label,value,detail,icon,tone}:{label:string;value:string;detail:string;icon:string;tone:string}){return <div className="metric-card"><div className="metric-top"><span>{label}</span><i className={`metric-icon ${tone}`}>{icon}</i></div><strong>{value}</strong><small>{detail}</small></div>}
function PanelTitle({title,subtitle,action}:{title:string;subtitle:string;action?:ReactNode}){return <div className="panel-title"><div><h2>{title}</h2><p>{subtitle}</p></div>{action}</div>}
function fmt(value:unknown){return typeof value==='number'&&Number.isFinite(value)?value.toFixed(3):'—'}
