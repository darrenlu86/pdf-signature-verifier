import React from 'react'
import ReactDOM from 'react-dom/client'
import { PanelApp } from '@/popup/PanelApp'
import '@/assets/main.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <PanelApp />
  </React.StrictMode>
)
