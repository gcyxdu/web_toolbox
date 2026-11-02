import React from 'react';
import ReactDOM from 'react-dom/client';
import { Theme } from '@radix-ui/themes';
import '@radix-ui/themes/styles.css';
import '@xyflow/react/dist/style.css';
import './styles.css';
import App from './App';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Theme appearance="light" accentColor="teal" grayColor="slate" radius="medium" scaling="100%">
      <App />
    </Theme>
  </React.StrictMode>,
);
