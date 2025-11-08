import streamlit as st
import requests
import pandas as pd
import time
from datetime import datetime

# Configuration
COLLECTOR_URL = "http://localhost:8080"

st.set_page_config(
    page_title="eBPF Micro-Segmentation",
    page_icon="🛡️",
    layout="wide"
)

# Title
st.title("🛡️ eBPF Network Micro-Segmentation Dashboard")

# Sidebar
with st.sidebar:
    st.header("⚙️ Controls")
    
    # Get current config
    try:
        resp = requests.get(f"{COLLECTOR_URL}/api/config", timeout=2)
        current_mode = resp.json().get("mode", "observe")
    except:
        current_mode = "observe"
    
    # Mode toggle
    mode = st.radio(
        "Operating Mode",
        ["observe", "enforce"],
        index=0 if current_mode == "observe" else 1
    )
    
    if st.button("Update Mode"):
        try:
            requests.post(
                f"{COLLECTOR_URL}/api/config",
                json={"mode": mode},
                timeout=2
            )
            st.success(f"✅ Mode set to: {mode}")
        except Exception as e:
            st.error(f"❌ Failed to update: {e}")
    
    st.divider()
    
    # Auto-refresh
    auto_refresh = st.checkbox("Auto-refresh (5s)", value=True)
    
    if st.button("🔄 Refresh Now"):
        st.rerun()

# Main content
col1, col2, col3, col4 = st.columns(4)

# Fetch stats
try:
    stats = requests.get(f"{COLLECTOR_URL}/api/stats", timeout=2).json()
    
    with col1:
        st.metric("Total Events", stats.get("total", 0))
    with col2:
        st.metric("Allowed", stats.get("allowed", 0), delta_color="normal")
    with col3:
        st.metric("Suspicious", stats.get("suspicious", 0), delta_color="inverse")
    with col4:
        st.metric("Blocked", stats.get("blocked", 0), delta_color="inverse")
except:
    st.error("⚠️ Cannot connect to collector")

st.divider()

# Tabs
tab1, tab2 = st.tabs(["📊 Network Events", "📋 Rules"])

with tab1:
    st.subheader("Recent Network Connections")
    
    try:
        events = requests.get(f"{COLLECTOR_URL}/api/events?limit=100", timeout=2).json()
        
        if events:
            df = pd.DataFrame(events)
            
            # Color code status
            def highlight_status(val):
                if val == "blocked":
                    return "background-color: #ffcccc"
                elif val == "suspicious":
                    return "background-color: #fff4cc"
                elif val == "allowed":
                    return "background-color: #ccffcc"
                return ""
            
            # Display dataframe with fixed methods
            st.dataframe(
                df.style.map(highlight_status, subset=["status"]),
                width="stretch",
                height=400
            )
            
            # Filters
            with st.expander("🔍 Filters"):
                col_a, col_b = st.columns(2)
                with col_a:
                    process_filter = st.multiselect(
                        "Process",
                        options=df["process"].unique()
                    )
                with col_b:
                    status_filter = st.multiselect(
                        "Status",
                        options=df["status"].unique()
                    )
                
                if process_filter or status_filter:
                    filtered = df
                    if process_filter:
                        filtered = filtered[filtered["process"].isin(process_filter)]
                    if status_filter:
                        filtered = filtered[filtered["status"].isin(status_filter)]
                    
                    st.dataframe(filtered, width="stretch")
        else:
            st.info("No events yet. Waiting for network activity...")
    except Exception as e:
        st.error(f"❌ Error fetching events: {e}")

with tab2:
    st.subheader("Access Control Rules")
    
    col_x, col_y = st.columns([3, 1])
    
    with col_x:
        try:
            rules = requests.get(f"{COLLECTOR_URL}/api/rules", timeout=2).json()
            
            if rules:
                rules_df = pd.DataFrame(rules)
                
                # Display rules with delete option
                for idx, rule in rules_df.iterrows():
                    col_r1, col_r2, col_r3, col_r4, col_r5 = st.columns([2, 2, 1, 1, 1])
                    
                    with col_r1:
                        st.text(f"Process: {rule['process']}")
                    with col_r2:
                        st.text(f"Dest: {rule['dst_ip']}:{rule['dst_port']}")
                    with col_r3:
                        if rule['action'] == 'allow':
                            st.success("✅ Allow")
                        else:
                            st.error("🚫 Deny")
                    with col_r4:
                        st.text(f"ID: {rule['id']}")
                    with col_r5:
                        if st.button(f"🗑️", key=f"del_{rule['id']}"):
                            try:
                                requests.delete(
                                    f"{COLLECTOR_URL}/api/rules/{rule['id']}",
                                    timeout=2
                                )
                                st.success("Deleted!")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Error: {e}")
            else:
                st.info("No rules defined yet")
        except Exception as e:
            st.error(f"❌ Error fetching rules: {e}")
    
    with col_y:
        st.subheader("➕ Add Rule")
        
        with st.form("add_rule_form"):
            new_process = st.text_input("Process", value="*", help="Use * for wildcard")
            new_dst_ip = st.text_input("Dest IP", value="*", help="Use * for any IP")
            new_dst_port = st.number_input("Dest Port", value=0, min_value=0, max_value=65535, help="Use 0 for any port")
            new_action = st.selectbox("Action", ["allow", "deny"])
            
            submitted = st.form_submit_button("Add Rule")
            
            if submitted:
                try:
                    resp = requests.post(
                        f"{COLLECTOR_URL}/api/rules",
                        json={
                            "process": new_process,
                            "dst_ip": new_dst_ip,
                            "dst_port": new_dst_port,
                            "action": new_action
                        },
                        timeout=2
                    )
                    st.success("✅ Rule added!")
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ Failed: {e}")

# Auto-refresh logic
if auto_refresh:
    time.sleep(5)
    st.rerun()

# Footer
st.divider()
st.caption(f"🕐 Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")