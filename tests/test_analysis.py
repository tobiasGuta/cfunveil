import pytest
from output.analysis import cluster_and_rank_ips, generate_justification

def test_tiering_and_ranking():
    validated_ips = {
        "1.1.1.1": {"confidence": 0.85, "body_hash": "hash1"},
        "1.1.1.2": {"confidence": 0.82, "body_hash": "hash1"},
        "2.2.2.2": {"confidence": 0.60, "body_hash": "hash2"},
        "3.3.3.3": {"confidence": 0.20, "body_hash": "hash3"},
        "3.3.3.4": {"confidence": 0.22, "body_hash": "hash3"},
    }
    analysis = cluster_and_rank_ips(validated_ips)
    
    assert len(analysis["clusters"]) == 3
    
    # Check top candidate diversity
    top_candidates = analysis["top_candidates"]
    assert len(top_candidates) == 3 # 2 from High due to fallback, 1 from Medium. Low are excluded.
    
    # 1.1.1.1 top of cluster 1 is included
    assert any(c["ip"] == "1.1.1.1" for c in top_candidates)
    # 1.1.1.2 is included purely because top clusters are exhausted and we aim for 5 min length
    assert any(c["ip"] == "1.1.1.2" for c in top_candidates)
    # 2.2.2.2 top of cluster 2 included
    assert any(c["ip"] == "2.2.2.2" for c in top_candidates)
    
    # 3.3.3.3 should never be included (Low tier)
    assert not any(c["ip"] == "3.3.3.3" for c in top_candidates)

def test_explanation_generation():
    data_high = {
        "confidence": 0.85,
        "explanation": {
            "contributing_factors": [
                "[tls] (+signal) Wildcard SSL match",
                "[network] (+signal) Target domain found in response body",
                "[boost] Boost(+0.20): Strong correlation"
            ]
        }
    }
    justif = generate_justification(data_high)
    assert "High confidence due to TLS match and HTTP response match" in justif
