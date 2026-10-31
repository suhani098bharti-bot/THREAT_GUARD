"""Page 1: ThreatGuard Security Operations Center (SOC) Dashboard."""

import streamlit as st

from authentication.auth import enforce_authentication
from dashboard.overview import render_dashboard_view
from utils.helpers import render_sidebar_profile

# Ensure authenticated session
enforce_authentication()
render_sidebar_profile()

# Render complete SOC dashboard
render_dashboard_view()
