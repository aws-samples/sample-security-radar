import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './styles/global.css';
import './styles/layout.css';
// R3.6: fonts are not render-blocking — their CSS (~250 @font-face rules) arrives after the app is on screen
void import('./styles/fonts.css');

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
