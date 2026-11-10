import { createRoot } from 'react-dom/client'
import { App } from './App'
import { applyTextSize } from './lib/scale'
import { setting } from './lib/settings'
import './index.css'

applyTextSize(setting('textSize'))
createRoot(document.getElementById('root')!).render(<App />)
