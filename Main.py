import streamlit as st
import pandas as pd
import numpy as np

st.set_page_config(page_title="Data Logger", page_icon="📊", layout="wide", initial_sidebar_state="expanded")




# Using "with" notation
with st.sidebar:
    st.title("Menu")
    st.file_uploader('Upload ideal File', type=None, accept_multiple_files=False, key=None, help=None, on_change=None, args=None, kwargs=None,  disabled=False, label_visibility="visible")
    
    title = st.text_input('Data Logger Directcory', 'c:')
    st.button("Plot Graph")

st.write('Scan files from ', title)






comp_Graphset1 , comp_Graphset2 = st.columns(2 , gap='large')

with comp_Graphset1:
   col1, col2 = st.columns(2)
   with col1:
    st.text("Ideal Graph")
    chart_data = pd.DataFrame(np.random.randn(20, 3), columns=["a", "b", "c"])
    st.line_chart(chart_data)

   with col2:
    st.text("Current Graph")
    chart_data = pd.DataFrame(np.random.randn(20, 3), columns=["a", "b", "c"])
    st.line_chart(chart_data)

with comp_Graphset2:
   col1, col2 = st.columns(2)
   with col1:
    st.text("Ideal Graph")
    chart_data = pd.DataFrame(np.random.randn(20, 3), columns=["a", "b", "c"])
    st.line_chart(chart_data)

   with col2:
    st.text("Current Graph")
    chart_data = pd.DataFrame(np.random.randn(20, 3), columns=["a", "b", "c"])
    st.line_chart(chart_data)