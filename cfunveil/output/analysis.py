import hashlib
from typing import Dict, List, Any

def get_subnet_24(ip: str) -> str:
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return ip

def get_tier(confidence: float) -> str:
    if confidence >= 0.80:
        return "High"
    elif confidence >= 0.50:
        return "Medium"
    else:
        return "Low"

def generate_justification(ip_data: Dict[str, Any]) -> str:
    # E.g. "High confidence due to matching TLS certificate and identical HTTP response fingerprint."
    exp = ip_data.get("explanation", {})
    if not exp:
        return "Legacy scoring system applied."
        
    factors = exp.get("contributing_factors", [])
    tls = "TLS match" if any("TLS" in f or "tls" in f.lower() for f in factors if "(+signal)" in f or "Boost" in f) else ""
    network = "HTTP response match" if any("network" in f.lower() for f in factors if "(+signal)" in f) else ""
    dns = "Historical DNS" if any("dns" in f.lower() for f in factors if "(+signal)" in f) else ""
    
    positives = [x for x in [tls, network, dns] if x]
    
    if get_tier(ip_data.get("confidence", 0.0)) == "High":
        if len(positives) >= 2:
            return f"High confidence due to {positives[0]} and {positives[1]}."
        elif len(positives) == 1:
            return f"High confidence primarily driven by {positives[0]}."
        return "High confidence due to multiple correlating signals."
    elif get_tier(ip_data.get("confidence", 0.0)) == "Medium":
        if positives:
            return f"Medium confidence based on {positives[0]} with limited corroboration."
        return "Medium confidence due to partial indicator matches."
    return "Low confidence noise or unrelated infrastructure."

def cluster_and_rank_ips(validated_ips: Dict[str, Any]) -> Dict[str, Any]:
    # Ensure confidence is float and add tier/justification
    processed = []
    for ip, data in validated_ips.items():
        conf = data.get("confidence", 0)
        # Handle case where v1 was used (0-100) instead of v2 (0-1.0)
        if conf > 1.0:
            conf = conf / 100.0
            data["confidence"] = conf
            
        data["tier"] = get_tier(conf)
        data["justification"] = generate_justification(data)
        data["ip"] = ip
        processed.append(data)

    # Sort globally by confidence descending
    processed.sort(key=lambda x: x.get("confidence", 0), reverse=True)

    clusters = {}
    
    for item in processed:
        ip = item["ip"]
        subnet = get_subnet_24(ip)
        body_hash = item.get("body_hash", "")
        # tls footprint proxy: stringified cert_domains if any
        cert_info = str(item.get("cert_domains", {}))
        
        # Determine cluster ID (prefer body hash, then cert, then subnet)
        if body_hash:
            cluster_id = f"hash:{body_hash}"
            cluster_name = f"Same HTTP Response ({body_hash[:8]})"
        elif cert_info and cert_info != "{}":
            h = hashlib.md5(cert_info.encode()).hexdigest()[:8]
            cluster_id = f"tls:{h}"
            cluster_name = f"Same TLS Certificate ({h})"
        else:
            cluster_id = f"subnet:{subnet}"
            cluster_name = f"Subnet {subnet}"
            
        if cluster_id not in clusters:
            clusters[cluster_id] = {
                "id": cluster_id,
                "name": cluster_name,
                "members": [],
                "max_confidence": 0,
                "tier": "Low"
            }
            
        clusters[cluster_id]["members"].append(item)
        if item["confidence"] > clusters[cluster_id]["max_confidence"]:
            clusters[cluster_id]["max_confidence"] = item["confidence"]
            clusters[cluster_id]["tier"] = item["tier"]
            
    # Check for unreliable subnet clusters (shared hosting warning)
    for c_id, c_data in clusters.items():
        if c_id.startswith("subnet:"):
            orgs = set()
            for m in c_data["members"]:
                org = m.get("org", m.get("isp", "Unknown"))
                if org:
                    orgs.add(org)
            if len(orgs) > 1:
                c_data["warning"] = "Unreliable /24 cluster: Multiple organizations detected (shared hosting)."

    # Select Top Candidates (Diverse)
    # Pick the best member from the top clusters until we have up to 10
    sorted_clusters = sorted(clusters.values(), key=lambda c: c["max_confidence"], reverse=True)
    
    top_candidates = []
    for c in sorted_clusters:
        if c["tier"] in ["High", "Medium"]:
            best_member = c["members"][0] # already sorted by confidence
            top_candidates.append(best_member)
        if len(top_candidates) >= 10:
            break
            
    # If we don't have enough, we could add second-best members of high-confidence clusters
    if len(top_candidates) < 5:
        for c in sorted_clusters:
            if c["tier"] == "High":
                for member in c["members"][1:]:
                    if member not in top_candidates:
                        top_candidates.append(member)
                    if len(top_candidates) >= 5:
                        break
            if len(top_candidates) >= 5:
                break
                
    return {
        "all_ranked": processed,
        "clusters": sorted_clusters,
        "top_candidates": sorted(top_candidates, key=lambda x: x["confidence"], reverse=True)
    }

