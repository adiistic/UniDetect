import React from "react";
import type { ModelInfoResponse } from "../api/types";

interface ModelIntelligenceViewProps {
  modelInfo: ModelInfoResponse | null;
}

export const ModelIntelligenceView: React.FC<ModelIntelligenceViewProps> = ({ modelInfo }) => {
  const modalities = [
    {
      id: "BENIGN",
      label: "Benign Baseline",
      desc: "Normal university academic & administrative network traffic (HTTPS, DNS, SSH, NTP, Web).",
      icon: "check_circle",
      color: "text-emerald-400",
      bgColor: "bg-emerald-500/10",
      borderColor: "border-emerald-500/30",
    },
    {
      id: "DDOS",
      label: "DDoS Volumetric",
      desc: "High-frequency SYN/UDP flood saturation, packet rate anomalies, and half-open socket depletion.",
      icon: "crisis_alert",
      color: "text-red-400",
      bgColor: "bg-red-500/10",
      borderColor: "border-red-500/30",
    },
    {
      id: "RECON",
      label: "Recon & Port Scan",
      desc: "Horizontal IP sweeps, vertical port scanning, and automated service discovery with tuned sensitivity (θ = 0.35).",
      icon: "radar",
      color: "text-purple-400",
      bgColor: "bg-purple-500/10",
      borderColor: "border-purple-500/30",
    },
    {
      id: "DNS_TUNNEL",
      label: "DNS Exfiltration",
      desc: "High-entropy subdomain queries, oversized TXT lookups, base64 payload encoding, and bursty query patterns.",
      icon: "dns",
      color: "text-orange-400",
      bgColor: "bg-orange-500/10",
      borderColor: "border-orange-500/30",
    },
    {
      id: "C2_BEACON",
      label: "C2 Beaconing",
      desc: "Low-jitter periodic outbound heartbeat intervals to external IP infrastructure and abnormal sleep timings.",
      icon: "router",
      color: "text-cyan-400",
      bgColor: "bg-cyan-500/10",
      borderColor: "border-cyan-500/30",
    },
    {
      id: "SLOW_HTTP",
      label: "Slow HTTP DoS",
      desc: "Incomplete HTTP request header transmissions (Slowloris) and extended connection socket starvation.",
      icon: "hourglass_bottom",
      color: "text-amber-400",
      bgColor: "bg-amber-500/10",
      borderColor: "border-amber-500/30",
    },
  ];

  const featureTaxonomy = [
    {
      category: "Transport & Connection Dimensions (16)",
      items: [
        "orig_bytes", "resp_bytes", "duration", "orig_pkts", "resp_pkts",
        "missed_bytes", "history_char_entropy", "conn_state_SF", "conn_state_S0",
        "conn_state_REJ", "conn_state_RSTO", "proto_TCP", "proto_UDP", "proto_ICMP"
      ],
    },
    {
      category: "Causal Temporal Windows (36: 10s, 60s, 300s)",
      items: [
        "flows_count_10s/60s/300s", "bytes_orig_rate_10s/60s/300s", "bytes_resp_rate_10s/60s/300s",
        "syn_ratio_10s/60s/300s", "rej_ratio_10s/60s/300s", "unique_dest_ips_10s/60s/300s",
        "unique_dest_ports_10s/60s/300s", "mean_flow_duration_10s/60s/300s"
      ],
    },
    {
      category: "DNS Correlated Behavior (14)",
      items: [
        "dns_query_shannon_entropy", "dns_query_length_mean", "dns_query_length_max",
        "dns_qtype_TXT_ratio", "dns_qtype_A_ratio", "dns_nxdomain_rate", "dns_ttl_variance"
      ],
    },
    {
      category: "TLS & Protocol Metadata (12)",
      items: [
        "tls_sni_shannon_entropy", "tls_version_1_3", "tls_version_1_2",
        "weird_log_event_count", "weird_bad_SYN", "quic_packet_ratio"
      ],
    },
  ];

  return (
    <div className="flex-1 overflow-y-auto p-6 flex flex-col gap-6 select-none bg-[#0a0a0c]">
      {/* Top Banner */}
      <div className="bg-[#131316] border border-[#222226] rounded-2xl p-6 shadow-sm flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-2xl bg-white text-black flex items-center justify-center shadow-sm">
            <span className="material-symbols-outlined text-2xl" data-weight="fill">
              psychology
            </span>
          </div>
          <div>
            <h2 className="font-bold text-white text-lg font-mono">
              Model Intelligence & Machine Learning Architecture
            </h2>
            <p className="text-xs text-gray-400">
              Frozen calibrated estimator contract, 78-dimensional feature schema, and decision boundaries
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 bg-[#0e0e11] px-3.5 py-1.5 rounded-xl border border-[#222226]">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span className="font-mono text-xs font-bold text-white">
            {modelInfo?.model_version || "Phase 6E Calibrated Estimator"}
          </span>
        </div>
      </div>

      {/* Estimator Specifications Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#131316] border border-[#222226] rounded-2xl p-4">
          <span className="text-[11px] font-mono text-gray-400 uppercase tracking-wider">
            Primary Estimator
          </span>
          <div className="text-base font-bold text-white font-mono mt-1 truncate" title={modelInfo?.model_type}>
            HistGradientBoosting
          </div>
          <span className="text-xs text-gray-500 font-mono">Scikit-learn tree ensemble</span>
        </div>

        <div className="bg-[#131316] border border-[#222226] rounded-2xl p-4">
          <span className="text-[11px] font-mono text-gray-400 uppercase tracking-wider">
            Calibration Method
          </span>
          <div className="text-base font-bold text-emerald-400 font-mono mt-1">
            Sigmoid (Platt Scaling)
          </div>
          <span className="text-xs text-gray-500 font-mono">3-Fold Cross-Validation</span>
        </div>

        <div className="bg-[#131316] border border-[#222226] rounded-2xl p-4">
          <span className="text-[11px] font-mono text-gray-400 uppercase tracking-wider">
            Feature Contract
          </span>
          <div className="text-base font-bold text-cyan-400 font-mono mt-1">
            {modelInfo?.feature_count || 78} Dimensions
          </div>
          <span className="text-xs text-gray-500 font-mono">Schema v{modelInfo?.schema_version || "1.0.0"} (Frozen)</span>
        </div>

        <div className="bg-[#131316] border border-[#222226] rounded-2xl p-4">
          <span className="text-[11px] font-mono text-gray-400 uppercase tracking-wider">
            Temporal Lookback
          </span>
          <div className="text-base font-bold text-amber-400 font-mono mt-1">
            10s / 60s / 300s
          </div>
          <span className="text-xs text-gray-500 font-mono">Causal Backward Windows</span>
        </div>
      </div>

      {/* Decision Boundaries & Selective Abstention */}
      <div className="bg-[#131316] border border-[#222226] rounded-2xl p-6 shadow-sm flex flex-col gap-4">
        <div className="flex items-center justify-between pb-3 border-b border-[#222226]">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-gray-300">tune</span>
            <span className="font-bold text-white text-sm font-mono">Operational Decision Policy Thresholds</span>
          </div>
          <span className="text-xs font-mono text-gray-400">
            Automated vs Selective Abstention Policy
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-[#0e0e11] border border-[#222226] rounded-xl p-4 flex flex-col justify-between">
            <div>
              <div className="flex justify-between items-center mb-1">
                <span className="text-xs font-bold text-white font-mono">
                  Global Abstention Threshold (&theta;<sub>abstain</sub>)
                </span>
                <span className="font-mono text-sm font-bold text-purple-300 bg-purple-950/40 border border-purple-800/40 px-2 py-0.5 rounded">
                  {modelInfo?.thresholds?.abstain_confidence_threshold ?? 0.40}
                </span>
              </div>
              <p className="text-xs text-gray-400 leading-relaxed mt-2">
                Inferences with calibrated multi-class confidence below 40% are not executed automatically.
                They are safely flagged as <strong className="text-white">ANALYST_REVIEW</strong> for Tier-2 SOC validation,
                preventing false-positive disruptions on legitimate university research traffic.
              </p>
            </div>
          </div>

          <div className="bg-[#0e0e11] border border-[#222226] rounded-xl p-4 flex flex-col justify-between">
            <div>
              <div className="flex justify-between items-center mb-1">
                <span className="text-xs font-bold text-white font-mono">
                  Reconnaissance Sensitivity (&theta;<sub>recon</sub>)
                </span>
                <span className="font-mono text-sm font-bold text-amber-300 bg-amber-950/40 border border-amber-800/40 px-2 py-0.5 rounded">
                  {modelInfo?.thresholds?.recon_threshold ?? 0.35}
                </span>
              </div>
              <p className="text-xs text-gray-400 leading-relaxed mt-2">
                Stealthy horizontal scans and slow network reconnaissance sweeps exhibit low packet footprints.
                The calibrated policy applies an elevated sensitivity cutoff at 35% to catch early lateral movement attempts.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Multi-Class Threat Modalities */}
      <div className="bg-[#131316] border border-[#222226] rounded-2xl p-6 shadow-sm flex flex-col gap-4">
        <div className="flex items-center justify-between pb-3 border-b border-[#222226]">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-gray-300">hub</span>
            <span className="font-bold text-white text-sm font-mono">Supported Threat Vector Modalities</span>
          </div>
          <span className="text-xs font-mono text-gray-400">6 Multi-Class Target Categories</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {modalities.map((mod) => (
            <div
              key={mod.id}
              className={`bg-[#0e0e11] border ${mod.borderColor} rounded-xl p-4 flex flex-col gap-2`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className={`material-symbols-outlined text-lg ${mod.color}`}>{mod.icon}</span>
                  <span className="font-bold text-sm text-white font-mono">{mod.label}</span>
                </div>
                <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${mod.bgColor} ${mod.color}`}>
                  {mod.id}
                </span>
              </div>
              <p className="text-xs text-gray-400 leading-relaxed">{mod.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* 78-Dimensional Feature Vector Taxonomy */}
      <div className="bg-[#131316] border border-[#222226] rounded-2xl p-6 shadow-sm flex flex-col gap-4">
        <div className="flex items-center justify-between pb-3 border-b border-[#222226]">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-gray-300">account_tree</span>
            <span className="font-bold text-white text-sm font-mono">78-Dimensional Feature Vector Taxonomy</span>
          </div>
          <span className="text-xs font-mono text-gray-400">Continuous Numerical Representation</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {featureTaxonomy.map((sec, idx) => (
            <div key={idx} className="bg-[#0e0e11] border border-[#222226] rounded-xl p-4 flex flex-col gap-2">
              <span className="text-xs font-bold text-white font-mono flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                {sec.category}
              </span>
              <div className="flex flex-wrap gap-1.5 pt-1">
                {sec.items.map((item, i) => (
                  <span
                    key={i}
                    className="text-[10px] font-mono bg-[#16161c] text-gray-300 px-2 py-0.5 rounded border border-[#262632]"
                  >
                    {item}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Passive Security & Privacy Guarantee */}
      <div className="bg-[#101410] border border-emerald-500/30 rounded-2xl p-5 flex items-start gap-4">
        <div className="w-9 h-9 rounded-xl bg-emerald-500/20 text-emerald-400 flex items-center justify-center flex-shrink-0">
          <span className="material-symbols-outlined text-xl">verified_user</span>
        </div>
        <div className="flex flex-col gap-1">
          <div className="text-xs font-bold text-white font-mono uppercase tracking-wider">
            Zero-Payload Passive Inspection Guarantee
          </div>
          <p className="text-xs text-gray-300 leading-relaxed">
            UniDetect operates exclusively out-of-band via network TAP or mirror port Zeek log ingestion.
            Zero user packet contents, application payloads, or TLS communications are decrypted or inspected.
            All 78 feature inputs are strictly derived from statistical flow geometry and transport metadata.
          </p>
        </div>
      </div>
    </div>
  );
};
